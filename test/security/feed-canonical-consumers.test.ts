// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Canonical feed matching outside the sync pipeline: the matcher's derived-hit
 * log line, the catch-all analyzer, outbound send-risk and deep-scan all give
 * the same feed result for a link and its canonical variants.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Email } from "postal-mime";

import { checkUrlAgainstFeeds, refreshAllFeeds } from "../../workers/intel/feeds";
import { analyzeCatchall } from "../../workers/security/catchall";
import { assessSendRisk } from "../../workers/lib/send-risk-assess";
import { runDeepScan } from "../../workers/intel/deep-scan";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import {
	createFakeFeedKv,
	createFakeMailboxStub,
	makeFakeEnv,
	type FakeFeedSeed,
	type FakeMailboxStub,
} from "./fakes";

const MAILBOX = "test@example.com";
const DOMAIN = "example.com";
const DOMAIN_FEED: FakeFeedSeed = { id: "probe-domain", kind: "domain", lines: ["evil.example"] };
const URL_FEED: FakeFeedSeed = { id: "probe-url", kind: "url", lines: ["https://phish.example/login"] };
const FEEDS = [DOMAIN_FEED, URL_FEED];
const INTEL = { feeds: FEEDS.map((f) => ({ id: f.id, kind: f.kind, url: "" })) };

function feedEnv(stub: FakeMailboxStub = createFakeMailboxStub().stub) {
	return makeFakeEnv({
		mailboxId: MAILBOX,
		stub,
		settings: { enabled: true, send_risk: { llm_enabled: false } } as never,
		intel: INTEL,
		objects: { [`domains/${DOMAIN}.json`]: { intel: INTEL } },
		bloomKv: createFakeFeedKv(FEEDS),
	});
}

beforeEach(() => {
	clearOrgSettingsCache();
	clearDomainSettingsCache();
});
afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

describe("checkUrlAgainstFeeds — derived hits are logged", () => {
	it.each([
		["https://phish.example/login?utm=1", "query-superset"],
		["https://phish.example/login#a", "fragment"],
	])("%s emits one info line naming feed, entry and derivation", async (link, derivation) => {
		const info = vi.spyOn(console, "info").mockImplementation(() => {});
		const hit = await checkUrlAgainstFeeds(feedEnv(), MAILBOX, link);
		expect(hit).toMatchObject({ feedId: "probe-url", value: "https://phish.example/login", confirmed: false, derived: true });
		expect(info).toHaveBeenCalledTimes(1);
		const line = info.mock.calls[0].map(String).join(" ");
		expect(line).toContain("probe-url");
		expect(line).toContain("https://phish.example/login");
		expect(line).toContain(derivation);
	});

	it("an exact hit logs nothing", async () => {
		const info = vi.spyOn(console, "info").mockImplementation(() => {});
		const hit = await checkUrlAgainstFeeds(feedEnv(), MAILBOX, "https://phish.example./login");
		expect(hit).toMatchObject({ confirmed: true });
		expect(info).not.toHaveBeenCalled();
	});
});

describe("refreshAllFeeds — url feeds store a path prefilter key", () => {
	it("a refreshed feed finds a multi-param entry from a reordered, padded link", async () => {
		// Filler entries give the refreshed bloom production sizing; a 1-entry
		// bloom answers most probes with a false positive.
		const filler = Array.from({ length: 3000 }, (_, i) => `https://filler.example/${i}`);
		const body = ["https://multi.example/p?a=1&b=2", ...filler].join("\n");
		vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
			const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
			if (new URL(url).hostname !== "feeds.example") throw new Error(`unexpected fetch: ${url}`);
			return new Response(body, { status: 200 });
		});
		const env = makeFakeEnv({
			mailboxId: MAILBOX,
			stub: createFakeMailboxStub().stub,
			intel: { feeds: [{ id: "probe-url", kind: "url", url: "https://feeds.example/list.txt" }] },
			bloomKv: createFakeFeedKv([]),
		});
		expect(await refreshAllFeeds(env)).toEqual({ feeds: 1, entries: 3001 });
		vi.spyOn(console, "info").mockImplementation(() => {});

		const hit = await checkUrlAgainstFeeds(env, MAILBOX, "https://multi.example/p?c=3&b=2&x=9&a=1");
		expect(hit).toMatchObject({
			feedId: "probe-url",
			value: "https://multi.example/p?a=1&b=2",
			derived: true,
			derivation: "query-superset",
		});
	});
});

function catchallEmail(link: string): Email {
	return {
		from: { address: "sender@other.example", name: "" },
		html: `<a href="${link}">open</a>`,
		text: null,
		headers: [],
		attachments: [],
	} as unknown as Email;
}

describe("analyzeCatchall — feed result is the same for canonical variants", () => {
	it.each([
		["https://evil.example/login", "evil.example in probe-domain"],
		["https://evil.example./login", "evil.example in probe-domain"],
		["https://phish.example:443/login", "https://phish.example/login in probe-url"],
		["https://PHISH.example./login", "https://phish.example/login in probe-url"],
	])("%s", async (link, signal) => {
		const v = await analyzeCatchall(feedEnv(), { parsedEmail: catchallEmail(link), domain: DOMAIN });
		expect(v.signals).toContain(`url-feed: ${signal}`);
		expect(v.score).toBe(30);
	});

	it("labels a derived hit as derived", async () => {
		const v = await analyzeCatchall(feedEnv(), {
			parsedEmail: catchallEmail("https://phish.example/login?utm=1"),
			domain: DOMAIN,
		});
		expect(v.signals).toContain("url-feed: https://phish.example/login in probe-url (derived)");
		expect(v.score).toBe(15);
	});
});

describe("assessSendRisk — feed and lookalike reasons are the same for canonical variants", () => {
	async function assess(body: string) {
		return assessSendRisk(feedEnv(), undefined, {
			mailboxId: MAILBOX,
			to: "partner@external.example",
			subject: "hello",
			body,
		});
	}

	it.each([
		["https://evil.example./login", "Link on threat-intel feed: evil.example (probe-domain)"],
		["https://phish.example./login", "Link on threat-intel feed: phish.example (probe-url)"],
		["https://phish.example/x/../login", "Link on threat-intel feed: phish.example (probe-url)"],
	])("%s", async (body, reason) => {
		const risk = await assess(body);
		expect(risk.tier).toBe(2);
		expect(risk.reasons).toContain(reason);
	});

	it("reports a derived hit at tier 1", async () => {
		const risk = await assess("https://phish.example/login?utm=1");
		expect(risk.tier).toBe(1);
		expect(risk.reasons).toContain("Link possibly on threat-intel feed: phish.example (probe-url, derived)");
	});

	it("names a lookalike host without its trailing dot", async () => {
		const risk = await assess("https://paypa1.co./login");
		expect(risk.reasons).toContain("Lookalike or internationalized link: paypa1.co");
	});
});

describe("runDeepScan — resolved URL gets the same feed and homograph result", () => {
	interface UrlRow {
		id: string;
		url: string;
	}

	function deepScanStub(url: string) {
		const urls = new Map<string, UrlRow & Record<string, unknown>>([["url-1", { id: "url-1", url }]]);
		const stub = {
			async getStoredVerdict() {
				return {
					verdict: JSON.stringify({
						action: "allow",
						score: 5,
						explanation: "first-time sender",
						auth: { spf: "none", dkim: "none", dmarc: "none" },
						classification: { label: "safe", confidence: 0.9, reasoning: "stub" },
						signals: ["first-time sender"],
					}),
					score: 5,
					explanation: "first-time sender",
					sender: "sender@other.example",
				};
			},
			async getUrlsForEmail() {
				return [...urls.values()];
			},
			async getAttachmentsForEmail() {
				return [];
			},
			async updateUrlScan(id: string, data: Record<string, unknown>) {
				urls.set(id, { ...urls.get(id)!, ...data });
			},
			async persistSecurityVerdict() {},
			async moveEmail() {},
			async updateDeepScanStatus() {},
		};
		return { stub: stub as unknown as FakeMailboxStub, urls };
	}

	/** Routes by parsed hostname; DoH fail-opens, unknown hosts (RDAP) throw. */
	function stubFetch(byHost: Record<string, () => Response>) {
		vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
			const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
			const host = new URL(url).hostname;
			if (host === "cloudflare-dns.com") {
				return new Response(JSON.stringify({ Answer: [] }), {
					status: 200,
					headers: { "content-type": "application/dns-json" },
				});
			}
			const respond = byHost[host];
			if (respond) return respond();
			throw new Error(`unexpected fetch: ${host}`);
		});
	}

	const ok = () => new Response("<title>page</title>", { status: 200 });
	const redirectTo = (location: string) => () => new Response("", { status: 302, headers: { location } });

	async function deepScan(link: string) {
		const { stub } = deepScanStub(link);
		return runDeepScan({ env: feedEnv(stub), mailboxId: MAILBOX, emailId: "email-1" });
	}

	it.each([
		["https://evil.example/login", "evil.example"],
		["https://evil.example./login", "evil.example."],
	])("direct link %s → intel_match", async (link, fetchedHost) => {
		stubFetch({ [fetchedHost]: ok });
		const result = await deepScan(link);
		expect(result.reasons).toContain("URL evil.example: intel_match:probe-domain");
		expect(result.added_score).toBe(20);
	});

	it.each([
		["https://evil.example/login", "evil.example"],
		["https://evil.example./login", "evil.example."],
	])("unlisted redirector → %s → intel_match", async (location, fetchedHost) => {
		stubFetch({ "redir.example": redirectTo(location), [fetchedHost]: ok });
		const result = await deepScan("https://redir.example/r");
		expect(result.reasons).toContain("URL evil.example: redirect_host_change,intel_match:probe-domain");
		expect(result.added_score).toBe(30);
	});

	it("unlisted redirector → derived variant → intel_match_derived", async () => {
		stubFetch({ "redir.example": redirectTo("https://phish.example/login?x=1"), "phish.example": ok });
		const result = await deepScan("https://redir.example/r");
		expect(result.reasons).toContain("URL phish.example: redirect_host_change,intel_match_derived:probe-url");
		expect(result.added_score).toBe(30);
	});

	it("a lookalike resolved host keeps resolved_homograph with a trailing dot", async () => {
		stubFetch({ "paypa1.co.": ok });
		const result = await deepScan("https://paypa1.co./login");
		expect(result.reasons).toContain("URL paypa1.co: resolved_homograph");
		expect(result.added_score).toBe(15);
	});
});
