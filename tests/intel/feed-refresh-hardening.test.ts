// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Hardening follow-ups to the #481/#482 KV write reduction.
 *
 * Core behavior (blob writes, refreshHours gate, membership-confirmed reads)
 * is pinned by tests/intel/feed-kv-writes.test.ts. This file pins the gaps
 * found in pre-merge review of the parallel implementation (PR #483):
 *
 *   1. A 304 must record a fresh `last_fetched_at`, otherwise 304-ing feeds
 *      are conditionally fetched every hour forever and never get the
 *      refreshHours skip.
 *   2. While a feed's exact blob is absent (the window between deploying
 *      the blob scheme and that feed's first new-style refresh), the read
 *      path must fall back to the legacy `intel:<feed>:exact:<value>` keys
 *      so detections don't transiently degrade to unconfirmed.
 *   3. The exact blob must be deduplicated before the cap — url-kind values
 *      repeat hostnames, which would waste roughly half the cap.
 *   4. An unparseable exact blob must degrade the hit to `confirmed: false`,
 *      not throw out of the whole lookup.
 *   5. The exact blob must be fetched lazily — only after a bloom hit — not
 *      eagerly for every feed on every lookup.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkUrlAgainstFeeds, refreshAllFeeds } from "../../workers/intel/feeds";
import { addToBloom, createBloom, serializeBloom } from "../../workers/intel/bloom";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import type { Env } from "../../workers/types";

const MAILBOX_ID = "user@example.com";
const FEED_URL = "https://feeds.test.example/list.txt";

// ── Fakes ─────────────────────────────────────────────────────────────

/** Mock KV that records get/put keys and supports `get(key, "arrayBuffer")`. */
function makeKv() {
	const store = new Map<string, string | Uint8Array>();
	const gets: string[] = [];
	return {
		store,
		gets,
		async get(key: string, type?: string) {
			gets.push(key);
			const v = store.get(key);
			if (v === undefined) return null;
			if (type === "arrayBuffer") {
				const bytes = typeof v === "string" ? new TextEncoder().encode(v) : v;
				return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
			}
			return typeof v === "string" ? v : new TextDecoder().decode(v);
		},
		async put(key: string, value: string | Uint8Array) {
			store.set(key, value);
		},
	};
}

function makeBucket(mailboxSettings: unknown) {
	return {
		async list(_opts: { prefix: string }) {
			return { objects: [{ key: `mailboxes/${MAILBOX_ID}.json` }] };
		},
		async get(key: string) {
			if (key !== `mailboxes/${MAILBOX_ID}.json`) return null;
			return {
				etag: "etag-1",
				async json() {
					return mailboxSettings;
				},
			};
		},
	};
}

interface FakeFeedState {
	last_fetched_at: string;
	etag: string | null;
	entry_count: number;
}

function makeMailboxStub(states: Record<string, FakeFeedState> = {}) {
	const upserts: Array<{ feedId: string; state: FakeFeedState }> = [];
	return {
		upserts,
		async getIntelFeedState(feedId: string) {
			return states[feedId] ?? null;
		},
		async upsertIntelFeedState(feedId: string, state: FakeFeedState) {
			upserts.push({ feedId, state });
		},
	};
}

function makeEnv(opts: {
	mailboxSettings: unknown;
	kv?: ReturnType<typeof makeKv>;
	stub?: ReturnType<typeof makeMailboxStub>;
}): Env {
	const stub = opts.stub ?? makeMailboxStub();
	const mailboxNs = {
		idFromName(name: string) {
			return { toString: () => name } as unknown as DurableObjectId;
		},
		get(_id: DurableObjectId) {
			return stub as unknown as DurableObjectStub;
		},
	} as unknown as DurableObjectNamespace;
	return {
		BLOOM_KV: (opts.kv ?? makeKv()) as unknown as KVNamespace,
		BUCKET: makeBucket(opts.mailboxSettings) as unknown as R2Bucket,
		MAILBOX: mailboxNs,
	} as unknown as Env;
}

function urlFeedSettings(refreshHours = 6) {
	return {
		intel: {
			feeds: [{ id: "testfeed", url: FEED_URL, kind: "url", refresh_hours: refreshHours }],
		},
	};
}

function mockFetch(body: string, status = 200) {
	globalThis.fetch = vi.fn(
		async () => new Response(status === 304 ? null : body, { status }),
	) as unknown as typeof fetch;
}

let originalFetch: typeof fetch;

beforeEach(() => {
	originalFetch = globalThis.fetch;
	clearOrgSettingsCache();
	clearDomainSettingsCache();
});

afterEach(() => {
	globalThis.fetch = originalFetch;
	vi.restoreAllMocks();
});

// ── 304 freshness ─────────────────────────────────────────────────────

describe("refreshFeed 304 handling", () => {
	it("records a fresh last_fetched_at on 304 so refreshHours skips apply to unchanged feeds", async () => {
		mockFetch("", 304);
		const stale = new Date(Date.now() - 7 * 3600 * 1000).toISOString();
		const stub = makeMailboxStub({
			testfeed: { last_fetched_at: stale, etag: '"abc"', entry_count: 42 },
		});
		const env = makeEnv({ mailboxSettings: urlFeedSettings(6), stub });

		const result = await refreshAllFeeds(env);

		expect(result.feeds).toBe(1);
		expect(result.entries).toBe(42);
		expect(stub.upserts).toHaveLength(1);
		const upserted = stub.upserts[0];
		expect(upserted.feedId).toBe("testfeed");
		expect(upserted.state.etag).toBe('"abc"');
		expect(upserted.state.entry_count).toBe(42);
		const ageMs = Date.now() - Date.parse(upserted.state.last_fetched_at);
		expect(ageMs).toBeGreaterThanOrEqual(0);
		expect(ageMs).toBeLessThan(60 * 1000);
	});
});

// ── Deploy-window legacy fallback ─────────────────────────────────────

describe("legacy per-entry exact-key fallback", () => {
	it("confirms via a legacy exact key while the exact blob is absent", async () => {
		const member = "https://evil.example/login";
		const bloom = createBloom(10);
		for (const v of [member, "evil.example"]) addToBloom(bloom, v);
		const kv = makeKv();
		kv.store.set("intel:testfeed:bloom", serializeBloom(bloom));
		kv.store.set(`intel:testfeed:exact:${member}`, "1");
		const env = makeEnv({ mailboxSettings: urlFeedSettings(), kv });

		const match = await checkUrlAgainstFeeds(env, MAILBOX_ID, member);

		expect(match).not.toBeNull();
		expect(match!.confirmed).toBe(true);
	});

	it("degrades to unconfirmed when neither blob nor legacy key exists", async () => {
		const member = "https://evil.example/login";
		const bloom = createBloom(10);
		for (const v of [member, "evil.example"]) addToBloom(bloom, v);
		const kv = makeKv();
		kv.store.set("intel:testfeed:bloom", serializeBloom(bloom));
		const env = makeEnv({ mailboxSettings: urlFeedSettings(), kv });

		const match = await checkUrlAgainstFeeds(env, MAILBOX_ID, member);

		expect(match).not.toBeNull();
		expect(match!.confirmed).toBe(false);
	});
});

// ── Robust + lazy exact-blob reads ────────────────────────────────────

describe("exact-blob read robustness", () => {
	it("degrades to unconfirmed when the exact blob is unparseable", async () => {
		const member = "https://evil.example/login";
		const bloom = createBloom(10);
		for (const v of [member, "evil.example"]) addToBloom(bloom, v);
		const kv = makeKv();
		kv.store.set("intel:testfeed:bloom", serializeBloom(bloom));
		kv.store.set("intel:testfeed:exact-blob", "not json {{{");
		const env = makeEnv({ mailboxSettings: urlFeedSettings(), kv });

		const match = await checkUrlAgainstFeeds(env, MAILBOX_ID, member);

		expect(match).not.toBeNull();
		expect(match!.confirmed).toBe(false);
	});

	it("does not fetch the exact blob when nothing hits the bloom", async () => {
		const bloom = createBloom(10);
		addToBloom(bloom, "https://unrelated.example/x");
		addToBloom(bloom, "unrelated.example");
		const kv = makeKv();
		kv.store.set("intel:testfeed:bloom", serializeBloom(bloom));
		kv.store.set("intel:testfeed:exact-blob", JSON.stringify(["https://unrelated.example/x"]));
		const env = makeEnv({ mailboxSettings: urlFeedSettings(), kv });

		const match = await checkUrlAgainstFeeds(env, MAILBOX_ID, "https://benign.example/ok");

		expect(match).toBeNull();
		// The ~200 KB blob must only be read after a bloom hit — this is the
		// per-URL hot path of the security pipeline.
		expect(kv.gets.filter((k) => k === "intel:testfeed:exact-blob")).toEqual([]);
	});
});

// ── Exact-blob dedupe ─────────────────────────────────────────────────

describe("exact-blob dedupe", () => {
	it("deduplicates values so the cap covers more unique entries", async () => {
		// Two URLs on the same host parse to [urlA, host, urlB, host] — the
		// blob should store each value once so the 2000-entry cap isn't
		// wasted on repeated hostnames.
		mockFetch("https://x.example/a\nhttps://x.example/b\n");
		const kv = makeKv();
		const env = makeEnv({ mailboxSettings: urlFeedSettings(), kv });

		await refreshAllFeeds(env);

		const blob = await kv.get("intel:testfeed:exact-blob");
		const parsed = JSON.parse(blob as string) as string[];
		expect(parsed.sort()).toEqual(
			["https://x.example/a", "https://x.example/b", "x.example"].sort(),
		);
	});
});
