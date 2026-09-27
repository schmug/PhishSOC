// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * `runSecurityPipeline` against seeded intel feeds: link URLs and feed
 * entries are compared in canonical form, in two tiers.
 *   - Exact: the link equals an entry after lossless canonicalization
 *     (host case, one trailing dot, default port, dot segments, empty `?`/`#`,
 *     percent-encoded unreserved path chars) → confirmed → `hard_block`.
 *   - Derived: the link equals an entry after removing its fragment, or the
 *     entry's query params are a sub-multiset of the link's → +20, classifier
 *     still runs; derived hits in 2+ distinct feeds floor at quarantine.
 *
 * Baselines with no intel hit (first-time sender only): LLM safe 0.9 → 5,
 * suspicious 0.7 → 31, phishing 0.6 → 45.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { runSecurityPipeline } from "../../workers/security/index";
import { __setClassifier, type ClassificationResult } from "../../workers/security/classification";
import type { MailboxSecuritySettings } from "../../workers/security/settings";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import { createFakeFeedKv, createFakeMailboxStub, makeFakeEnv, type FakeFeedSeed } from "./fakes";

const MAILBOX = "test@example.com";
const SAFE: ClassificationResult = { label: "safe", confidence: 0.9, reasoning: "stub" };
const SUSPICIOUS: ClassificationResult = { label: "suspicious", confidence: 0.7, reasoning: "stub" };
const PHISHING: ClassificationResult = { label: "phishing", confidence: 0.6, reasoning: "stub" };

const DOMAIN_FEED: FakeFeedSeed = { id: "probe-domain", kind: "domain", lines: ["evil.example"] };
const URL_FEED: FakeFeedSeed = {
	id: "probe-url",
	kind: "url",
	lines: ["https://phish.example/login", "https://drive.example/open?id=AAA", "https://app.example/#/t/evil"],
};

async function scan(
	link: string,
	feeds: FakeFeedSeed[],
	opts: { llm?: ClassificationResult; settings?: Partial<MailboxSecuritySettings> } = {},
) {
	__setClassifier(async () => opts.llm ?? SAFE);
	const { stub } = createFakeMailboxStub();
	const env = makeFakeEnv({
		mailboxId: MAILBOX,
		stub,
		settings: { enabled: true, ...opts.settings },
		intel: { feeds: feeds.map((f) => ({ id: f.id, kind: f.kind, url: "" })) },
		bloomKv: createFakeFeedKv(feeds),
	});
	const result = await runSecurityPipeline({
		env,
		mailboxId: MAILBOX,
		messageId: "m-1",
		targetFolder: "inbox",
		parsedEmail: {
			subject: "Account notice",
			from: { address: "sender@other.example", name: "" },
			html: `<p><a href="${link}">open</a></p>`,
			headers: [],
		},
	});
	return result.verdict!;
}

beforeEach(() => {
	clearOrgSettingsCache();
	clearDomainSettingsCache();
});
afterEach(() => {
	__setClassifier(null);
});

describe("exact tier → hard_block", () => {
	it.each([
		"https://evil.example/login",
		"https://evil.example./login",
		"http://evil.example./login",
		"https://EVIL.EXAMPLE./login",
	])("domain feed: %s", async (link) => {
		const v = await scan(link, [DOMAIN_FEED]);
		expect(v.triage).toBe("hard_block");
		expect(v.action).toBe("quarantine");
	});

	it.each([
		"https://phish.example/login",
		"https://phish.example./login",
		"https://PHISH.example/login",
		"https://phish.example:443/login",
		"https://phish.example/login?",
		"https://phish.example/login#",
		"https://phish.example/%6Cogin",
		"https://phish.example/x/../login",
	])("url feed: %s", async (link) => {
		const v = await scan(link, [URL_FEED]);
		expect(v.triage).toBe("hard_block");
		expect(v.signals).toContain("confirmed intel hit (probe-url: https://phish.example/login)");
	});

	it("a url-feed entry with a fragment matches the same fragment", async () => {
		const v = await scan("https://APP.example./#/t/evil", [URL_FEED]);
		expect(v.triage).toBe("hard_block");
	});

	it("a non-canonical feed line matches its canonical link after ingest", async () => {
		const feed: FakeFeedSeed = { id: "probe-url", kind: "url", lines: ["HTTP://Phish.Example.:80/login?#"] };
		const v = await scan("http://phish.example/login", [feed]);
		expect(v.triage).toBe("hard_block");
	});

	it("a blob written before canonical ingest still confirms its raw value", async () => {
		const feed: FakeFeedSeed = { id: "probe-url", kind: "url", rawValues: ["http://phish.example"] };
		const v = await scan("http://phish.example", [feed]);
		expect(v.triage).toBe("hard_block");
	});
});

describe("derived tier → +20, classifier still runs", () => {
	it.each([
		["https://phish.example/login?utm=1", "https://phish.example/login"],
		["https://phish.example/login#a", "https://phish.example/login"],
		["https://phish.example./login?utm=1#a", "https://phish.example/login"],
		["https://drive.example/open?id=AAA&x=1", "https://drive.example/open?id=AAA"],
		["https://drive.example/open?x=1&id=AAA", "https://drive.example/open?id=AAA"],
	])("%s", async (link, entry) => {
		const v = await scan(link, [URL_FEED]);
		expect(v.triage).toBeUndefined();
		expect(v.score).toBe(25);
		expect(v.action).toBe("allow");
		expect(v.signals).toContain(`threat-intel match (derived) (probe-url: ${entry})`);
	});

	it("reaches quarantine only when the classifier agrees", async () => {
		expect((await scan("https://phish.example/login?utm=1", [URL_FEED], { llm: SUSPICIOUS })).action).toBe("tag");
		const v = await scan("https://phish.example/login?utm=1", [URL_FEED], { llm: PHISHING });
		expect(v.score).toBe(65);
		expect(v.action).toBe("quarantine");
		expect(v.triage).toBeUndefined();
	});

	it("ignores a derived candidate that only the bloom holds", async () => {
		const feed: FakeFeedSeed = { id: "probe-url", kind: "url", bloomOnly: ["https://bloom.example/login"] };
		const v = await scan("https://bloom.example/login?utm=1", [feed]);
		expect(v.score).toBe(5);
		expect(v.signals.join(" ")).not.toMatch(/threat-intel/);
	});
});

describe("no match", () => {
	it.each([
		"https://drive.example/open?id=BBB",
		"https://drive.example/open",
		"https://phish.example/LOGIN",
		"https://phish.example/login/extra",
		"https://app.example/#/t/legit",
		"https://app.example/",
	])("url feed: %s", async (link) => {
		const v = await scan(link, [URL_FEED]);
		expect(v.score).toBe(5);
		expect(v.signals.join(" ")).not.toMatch(/threat-intel|intel hit/);
	});

	it("a domain feed matches the exact host only", async () => {
		const v = await scan("https://login.evil.example/", [DOMAIN_FEED]);
		expect(v.score).toBe(5);
		expect(v.signals.join(" ")).not.toMatch(/threat-intel|intel hit/);
	});
});

describe("tier priority across feeds", () => {
	const FEED_A: FakeFeedSeed = { id: "feed-a", kind: "url", lines: ["https://phish.example/login"] };
	const FEED_B: FakeFeedSeed = { id: "feed-b", kind: "url", lines: ["https://phish.example/login?x=1"] };

	it.each([
		["derived feed first", [FEED_A, FEED_B]],
		["exact feed first", [FEED_B, FEED_A]],
	])("an exact hit beats a derived hit (%s)", async (_label, feeds) => {
		const v = await scan("https://phish.example/login?x=1", feeds);
		expect(v.triage).toBe("hard_block");
		expect(v.signals).toContain("confirmed intel hit (feed-b: https://phish.example/login?x=1)");
	});
});

describe("derived corroboration", () => {
	const FEED_A: FakeFeedSeed = { id: "feed-a", kind: "url", lines: ["https://phish.example/login"] };
	const FEED_B: FakeFeedSeed = { id: "feed-b", kind: "url", lines: ["https://phish.example/login"] };

	it("derived hits in two distinct feeds floor the score at quarantine", async () => {
		const v = await scan("https://phish.example/login?x=1", [FEED_A, FEED_B]);
		expect(v.triage).toBeUndefined();
		expect(v.action).toBe("quarantine");
		expect(v.score).toBeGreaterThanOrEqual(60);
	});

	it("learning_mode still caps the corroborated verdict at tag", async () => {
		const v = await scan("https://phish.example/login?x=1", [FEED_A, FEED_B], {
			settings: { learning_mode: true },
		});
		expect(v.action).toBe("tag");
	});

	it("several derived entries in one feed count once", async () => {
		const feed: FakeFeedSeed = {
			id: "feed-a",
			kind: "url",
			lines: ["https://phish.example/login", "https://phish.example/login?x=1"],
		};
		const v = await scan("https://phish.example/login?x=1&y=2", [feed]);
		expect(v.score).toBe(25);
		expect(v.action).toBe("allow");
	});
});

describe("host canonicalization in URL heuristics", () => {
	it("a lookalike host keeps its homograph signal with a trailing dot", async () => {
		const v = await scan("https://paypa1.co./login", [], { llm: PHISHING });
		expect(v.signals).toContain("homograph URL (paypa1.co)");
		expect(v.action).toBe("quarantine");
	});
});
