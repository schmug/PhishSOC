// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Deep-scan coverage for the `redirect_host_change` sender-domain exemption
 * (issue #716). A 2026-09-26 classifier evaluation found 9 legitimate
 * emails (IETF mailing-list posts, YouTube/Google notifications, SaaS
 * onboarding mail) tagged solely because `runDeepScan` scored every
 * apex/www redirect hop and every ESP click-tracker bounce-back as
 * `redirect_host_change`. These tests pin: same-registrable-domain
 * redirects and redirects landing back on the authenticated (DMARC-pass)
 * sender's own domain add no score, while a redirect to a genuinely
 * unrelated registrable domain still scores +10 regardless of sender or
 * DMARC state.
 */

import { afterEach, describe, expect, it } from "vitest";

import { runDeepScan } from "../../workers/intel/deep-scan";
import type { Env } from "../../workers/types";

interface UrlRow {
	id: string;
	url: string;
	resolved_url: string | null;
	verdict: string | null;
	fetch_status: string | null;
	page_title: string | null;
}

interface StoredVerdictSeed {
	verdict_json: string;
	score: number;
	explanation: string;
	sender: string;
}

function seedVerdict(opts: {
	dmarc: "pass" | "fail" | "none";
	score?: number;
	sender: string;
}): StoredVerdictSeed {
	const score = opts.score ?? 5;
	return {
		verdict_json: JSON.stringify({
			action: "allow",
			score,
			explanation: "first-time sender",
			auth: { spf: "none", dkim: "none", dmarc: opts.dmarc },
			classification: { label: "safe", confidence: 0.9, reasoning: "stub" },
			signals: ["first_time_sender"],
		}),
		score,
		explanation: "first-time sender",
		sender: opts.sender,
	};
}

function makeStub(initialUrls: UrlRow[], seed: StoredVerdictSeed) {
	const urls = new Map(initialUrls.map((u) => [u.id, u]));
	const verdicts = new Map<string, StoredVerdictSeed>();
	const moves: Array<{ id: string; folderId: string }> = [];

	verdicts.set("email-1", seed);

	const stub = {
		async getStoredVerdict(emailId: string) {
			const row = verdicts.get(emailId);
			return row
				? { verdict: row.verdict_json, score: row.score, explanation: row.explanation, sender: row.sender }
				: null;
		},
		async getUrlsForEmail(_emailId: string) {
			return Array.from(urls.values());
		},
		async getAttachmentsForEmail(_emailId: string) {
			return [];
		},
		async updateUrlScan(urlId: string, data: Partial<UrlRow>) {
			const existing = urls.get(urlId);
			if (existing) urls.set(urlId, { ...existing, ...data });
		},
		async persistSecurityVerdict(
			emailId: string,
			data: { verdict_json: string; score: number; explanation: string },
		) {
			verdicts.set(emailId, { ...data, sender: verdicts.get(emailId)?.sender ?? "" });
		},
		async moveEmail(id: string, folderId: string) {
			moves.push({ id, folderId });
		},
		async updateDeepScanStatus(_emailId: string, _status: string) {},
	};

	return { stub, urls, verdicts, moves };
}

function makeFakeEnv(stub: unknown): Env {
	const ns = {
		idFromName: () => ({ toString: () => "email-1" } as unknown as DurableObjectId),
		get: () => stub as unknown as DurableObjectStub,
	} as unknown as DurableObjectNamespace;
	return { MAILBOX: ns } as unknown as Env;
}

/**
 * Fake fetch that fail-opens every DoH lookup (SSRF guard sees no private
 * IPs and allows the hop) and plays back a scripted redirect chain by exact
 * URL. Anything else throws — every deep-scan call site that isn't the
 * redirect chain itself wraps its fetch in `.catch(() => null)`, so an
 * unscripted URL just degrades that signal to "no data" rather than
 * failing the test.
 */
function buildRedirectFetch(chain: Record<string, Response>): typeof fetch {
	return (async (input: RequestInfo | URL) => {
		const url = typeof input === "string"
			? input
			: input instanceof URL
				? input.href
				: (input as Request).url;
		const parsed = new URL(url);
		if (parsed.hostname === "cloudflare-dns.com") {
			return new Response(JSON.stringify({ Answer: [] }), {
				status: 200,
				headers: { "content-type": "application/dns-json" },
			});
		}
		const res = chain[url];
		if (res) return res;
		throw new Error(`unexpected URL: ${url}`);
	}) as unknown as typeof fetch;
}

describe("runDeepScan — redirect_host_change sender-domain exemption (issue #716)", () => {
	const realFetch = globalThis.fetch;

	afterEach(() => {
		globalThis.fetch = realFetch;
	});

	it("scores 0 when a redirect lands on the sender's registrable domain and DMARC passed", async () => {
		globalThis.fetch = buildRedirectFetch({
			"https://track.esp-provider.example/click?id=1": new Response("", {
				status: 302,
				headers: { location: "https://vendor.example/onboarding" },
			}),
			"https://vendor.example/onboarding": new Response("ok", { status: 200 }),
		});

		const { stub, verdicts } = makeStub(
			[{
				id: "url-1",
				url: "https://track.esp-provider.example/click?id=1",
				resolved_url: null,
				verdict: null,
				fetch_status: null,
				page_title: null,
			}],
			seedVerdict({ dmarc: "pass", sender: "notify@vendor.example" }),
		);

		const result = await runDeepScan({
			env: makeFakeEnv(stub),
			mailboxId: "test@example.com",
			emailId: "email-1",
		});

		expect(result.added_score).toBe(0);
		expect(result.reasons.join(" ")).not.toMatch(/redirect_host_change/);
		expect(verdicts.get("email-1")!.score).toBe(5);
	});

	it("still scores +10 when the redirect lands on the sender's domain but DMARC did not pass", async () => {
		globalThis.fetch = buildRedirectFetch({
			"https://track.esp-provider.example/click?id=1": new Response("", {
				status: 302,
				headers: { location: "https://vendor.example/onboarding" },
			}),
			"https://vendor.example/onboarding": new Response("ok", { status: 200 }),
		});

		const { stub } = makeStub(
			[{
				id: "url-1",
				url: "https://track.esp-provider.example/click?id=1",
				resolved_url: null,
				verdict: null,
				fetch_status: null,
				page_title: null,
			}],
			seedVerdict({ dmarc: "fail", sender: "notify@vendor.example" }),
		);

		const result = await runDeepScan({
			env: makeFakeEnv(stub),
			mailboxId: "test@example.com",
			emailId: "email-1",
		});

		expect(result.added_score).toBe(10);
		expect(result.reasons.join(" ")).toMatch(/redirect_host_change/);
	});

	it("still scores +10 when the redirect lands on the sender's domain but DMARC is none", async () => {
		globalThis.fetch = buildRedirectFetch({
			"https://track.esp-provider.example/click?id=1": new Response("", {
				status: 302,
				headers: { location: "https://vendor.example/onboarding" },
			}),
			"https://vendor.example/onboarding": new Response("ok", { status: 200 }),
		});

		const { stub } = makeStub(
			[{
				id: "url-1",
				url: "https://track.esp-provider.example/click?id=1",
				resolved_url: null,
				verdict: null,
				fetch_status: null,
				page_title: null,
			}],
			seedVerdict({ dmarc: "none", sender: "notify@vendor.example" }),
		);

		const result = await runDeepScan({
			env: makeFakeEnv(stub),
			mailboxId: "test@example.com",
			emailId: "email-1",
		});

		expect(result.added_score).toBe(10);
		expect(result.reasons.join(" ")).toMatch(/redirect_host_change/);
	});

	it("still scores +10 for a redirect to a registrable domain unrelated to both the start host and the sender", async () => {
		globalThis.fetch = buildRedirectFetch({
			"https://track.esp-provider.example/click?id=1": new Response("", {
				status: 302,
				headers: { location: "https://evil-lookalike.example/login" },
			}),
			"https://evil-lookalike.example/login": new Response("ok", { status: 200 }),
		});

		const { stub } = makeStub(
			[{
				id: "url-1",
				url: "https://track.esp-provider.example/click?id=1",
				resolved_url: null,
				verdict: null,
				fetch_status: null,
				page_title: null,
			}],
			// DMARC passes, but the redirect target shares neither the start
			// host's nor the sender's registrable domain — must still score.
			seedVerdict({ dmarc: "pass", sender: "notify@vendor.example" }),
		);

		const result = await runDeepScan({
			env: makeFakeEnv(stub),
			mailboxId: "test@example.com",
			emailId: "email-1",
		});

		expect(result.added_score).toBe(10);
		expect(result.reasons.join(" ")).toMatch(/redirect_host_change/);
	});

	it("leaves an IETF-style mailing-list email at allow: same-site redirects on a first-time sender with DMARC pass add no score", async () => {
		globalThis.fetch = buildRedirectFetch({
			"https://ietf.org/a": new Response("", {
				status: 301,
				headers: { location: "https://www.ietf.org/a" },
			}),
			"https://www.ietf.org/a": new Response("ok", { status: 200 }),
			"https://ietf.org/b": new Response("", {
				status: 301,
				headers: { location: "https://www.ietf.org/b" },
			}),
			"https://www.ietf.org/b": new Response("ok", { status: 200 }),
			"https://datatracker.ietf.org/c": new Response("", {
				status: 302,
				headers: { location: "https://www.ietf.org/c" },
			}),
			"https://www.ietf.org/c": new Response("ok", { status: 200 }),
		});

		const { stub, verdicts, moves } = makeStub(
			[
				{
					id: "url-1",
					url: "https://ietf.org/a",
					resolved_url: null,
					verdict: null,
					fetch_status: null,
					page_title: null,
				},
				{
					id: "url-2",
					url: "https://ietf.org/b",
					resolved_url: null,
					verdict: null,
					fetch_status: null,
					page_title: null,
				},
				{
					id: "url-3",
					url: "https://datatracker.ietf.org/c",
					resolved_url: null,
					verdict: null,
					fetch_status: null,
					page_title: null,
				},
			],
			seedVerdict({ dmarc: "pass", score: 5, sender: "ietf-announce@ietf.org" }),
		);

		const result = await runDeepScan({
			env: makeFakeEnv(stub),
			mailboxId: "test@example.com",
			emailId: "email-1",
		});

		expect(result.added_score).toBe(0);
		expect(result.final_action).toBe("unchanged");
		expect(verdicts.get("email-1")!.score).toBe(5);
		expect(moves).toEqual([]);
	});
});
