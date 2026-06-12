// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * BLOOM_KV write-reduction: exact-blob storage + refreshHours staleness gate.
 *
 * Validates that:
 *   1. A url-kind feed refresh writes exactly 2 KV keys (bloom blob + exact blob)
 *      regardless of entry count — not one key per entry.
 *   2. refreshAllFeeds skips a feed whose last_fetched_at is within refreshHours.
 *   3. The exact-match read path still confirms values that appear in the blob
 *      and reports bloom-only hits as unconfirmed.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkUrlAgainstFeeds, refreshAllFeeds } from "../../workers/intel/feeds";
import { addToBloom, createBloom, serializeBloom } from "../../workers/intel/bloom";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import type { Env } from "../../workers/types";

const MAILBOX_ID = "user@example.com";

// ── KV mock with put-call tracking ────────────────────────────────────────────

function makeCountingKv() {
	const store = new Map<string, string | Uint8Array>();
	const putKeys: string[] = [];
	return {
		store,
		putKeys,
		async get(key: string, type?: "text" | "arrayBuffer") {
			const val = store.get(key);
			if (val === undefined) return null;
			if (type === "arrayBuffer") {
				return val instanceof Uint8Array ? val.buffer : null;
			}
			if (type === "text") {
				return typeof val === "string" ? val : null;
			}
			return val;
		},
		async put(key: string, value: string | Uint8Array, _opts?: unknown) {
			putKeys.push(key);
			store.set(key, value);
		},
	};
}

// ── Feed-state factory ────────────────────────────────────────────────────────

type FeedStateRow = {
	feed_id: string;
	url: string;
	last_fetched_at: string | null;
	etag: string | null;
	entry_count: number | null;
	bloom_kv_key: string | null;
};

function makeFeedState(overrides: Partial<FeedStateRow> = {}): FeedStateRow {
	return {
		feed_id: "test-feed",
		url: "https://test.example/feed.txt",
		last_fetched_at: null,
		etag: null,
		entry_count: null,
		bloom_kv_key: null,
		...overrides,
	};
}

// ── Env factory ───────────────────────────────────────────────────────────────

function makeEnv(opts: {
	mailboxSettings: unknown;
	kv?: ReturnType<typeof makeCountingKv>;
	feedState?: FeedStateRow | null;
}): { env: Env; kv: ReturnType<typeof makeCountingKv> } {
	const kv = opts.kv ?? makeCountingKv();
	const state = opts.feedState !== undefined ? opts.feedState : null;

	const stub = {
		async getIntelFeedState(_feedId: string) {
			return state;
		},
		async upsertIntelFeedState(_feedId: string, _data: unknown) {},
	};

	const mailboxNs = {
		idFromName(_name: string) {
			return { toString: () => _name } as unknown as DurableObjectId;
		},
		get(_id: DurableObjectId) {
			return stub as unknown as DurableObjectStub;
		},
	} as unknown as DurableObjectNamespace;

	const bucket = {
		async list(_opts: { prefix: string }) {
			return { objects: [{ key: `mailboxes/${MAILBOX_ID}.json` }] };
		},
		async get(key: string) {
			if (key !== `mailboxes/${MAILBOX_ID}.json`) return null;
			return {
				etag: "etag-1",
				async json() {
					return opts.mailboxSettings;
				},
			};
		},
	};

	const env = {
		BLOOM_KV: kv as unknown as KVNamespace,
		BUCKET: bucket as unknown as R2Bucket,
		MAILBOX: mailboxNs,
	} as unknown as Env;

	return { env, kv };
}

function feedBody(n: number): string {
	return Array.from({ length: n }, (_, i) => `https://evil-${i}.example/phish`).join("\n");
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

let savedFetch: typeof fetch;
beforeEach(() => {
	savedFetch = globalThis.fetch;
	clearOrgSettingsCache();
	clearDomainSettingsCache();
});
afterEach(() => {
	globalThis.fetch = savedFetch;
	vi.restoreAllMocks();
});

// ── Tests: write count ────────────────────────────────────────────────────────

describe("BLOOM_KV write count — url-kind feed", () => {
	it("performs exactly 2 BLOOM_KV.put calls per refresh (bloom blob + exact blob)", async () => {
		vi.stubGlobal("fetch", async () => new Response(feedBody(2500), { status: 200 }));

		const { env, kv } = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [{ id: "test-feed", url: "https://test.example/feed.txt", kind: "url" }],
				},
			},
		});

		await refreshAllFeeds(env);

		expect(kv.putKeys).toHaveLength(2);
		expect(kv.putKeys.some((k) => k === "intel:test-feed:bloom")).toBe(true);
		expect(kv.putKeys.some((k) => k === "intel:test-feed:exact-blob")).toBe(true);
	});

	it("exact blob is a JSON array capped at EXACT_KEY_CAP entries", async () => {
		vi.stubGlobal("fetch", async () => new Response(feedBody(2500), { status: 200 }));

		const { env, kv } = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [{ id: "test-feed", url: "https://test.example/feed.txt", kind: "url" }],
				},
			},
		});

		await refreshAllFeeds(env);

		const raw = kv.store.get("intel:test-feed:exact-blob");
		expect(typeof raw).toBe("string");
		const parsed = JSON.parse(raw as string) as unknown[];
		expect(Array.isArray(parsed)).toBe(true);
		expect(parsed.length).toBeLessThanOrEqual(2000);
	});

	it("small feed (fewer entries than cap) still uses exact-blob, not per-entry keys", async () => {
		vi.stubGlobal("fetch", async () => new Response(feedBody(5), { status: 200 }));

		const { env, kv } = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [{ id: "small-feed", url: "https://test.example/small.txt", kind: "url" }],
				},
			},
		});

		await refreshAllFeeds(env);

		// Still exactly 2 — no per-entry keys
		expect(kv.putKeys).toHaveLength(2);
		const perEntryKeys = kv.putKeys.filter((k) => k.startsWith("intel:small-feed:exact:"));
		expect(perEntryKeys).toHaveLength(0);
	});
});

// ── Tests: refreshHours staleness gate ───────────────────────────────────────

describe("refreshHours staleness gate", () => {
	it("skips a feed whose last_fetched_at is within refreshHours", async () => {
		const fetchUrls: string[] = [];
		vi.stubGlobal(
			"fetch",
			async (input: string | URL | Request) => {
				fetchUrls.push(typeof input === "string" ? input : input.toString());
				return new Response(feedBody(5), { status: 200 });
			},
		);

		// refreshHours = 6; last fetched 2 h ago → still fresh
		const { env } = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [
						{
							id: "test-feed",
							url: "https://test.example/feed.txt",
							kind: "url",
							refresh_hours: 6,
						},
					],
				},
			},
			feedState: makeFeedState({
				last_fetched_at: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
				entry_count: 10,
			}),
		});

		const result = await refreshAllFeeds(env);

		expect(fetchUrls).toHaveLength(0);
		expect(result.feeds).toBe(0);
	});

	it("fetches a feed whose last_fetched_at is beyond refreshHours", async () => {
		const fetchUrls: string[] = [];
		vi.stubGlobal(
			"fetch",
			async (input: string | URL | Request) => {
				fetchUrls.push(typeof input === "string" ? input : input.toString());
				return new Response(feedBody(5), { status: 200 });
			},
		);

		// refreshHours = 6; last fetched 8 h ago → stale
		const { env } = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [
						{
							id: "test-feed",
							url: "https://test.example/feed.txt",
							kind: "url",
							refresh_hours: 6,
						},
					],
				},
			},
			feedState: makeFeedState({
				last_fetched_at: new Date(Date.now() - 8 * 3600 * 1000).toISOString(),
			}),
		});

		await refreshAllFeeds(env);

		expect(fetchUrls).toHaveLength(1);
	});

	it("fetches a feed with no prior state (first run)", async () => {
		const fetchUrls: string[] = [];
		vi.stubGlobal(
			"fetch",
			async (input: string | URL | Request) => {
				fetchUrls.push(typeof input === "string" ? input : input.toString());
				return new Response(feedBody(5), { status: 200 });
			},
		);

		const { env } = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [{ id: "test-feed", url: "https://test.example/feed.txt", kind: "url" }],
				},
			},
			feedState: null,
		});

		await refreshAllFeeds(env);

		expect(fetchUrls).toHaveLength(1);
	});

	it("feeds with no last_fetched_at (state row exists but field is null) are treated as first run", async () => {
		const fetchUrls: string[] = [];
		vi.stubGlobal(
			"fetch",
			async (input: string | URL | Request) => {
				fetchUrls.push(typeof input === "string" ? input : input.toString());
				return new Response(feedBody(5), { status: 200 });
			},
		);

		const { env } = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [{ id: "test-feed", url: "https://test.example/feed.txt", kind: "url" }],
				},
			},
			feedState: makeFeedState({ last_fetched_at: null }),
		});

		await refreshAllFeeds(env);

		expect(fetchUrls).toHaveLength(1);
	});
});

// ── Tests: exact-match read path ──────────────────────────────────────────────

describe("exact-match read path (exact blob)", () => {
	it("value present in exact blob → confirmed: true", async () => {
		const { env, kv } = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [{ id: "test-feed", url: "https://test.example/feed.txt", kind: "url" }],
				},
			},
		});

		const testUrl = "https://evil.example/phish";
		const host = new URL(testUrl).hostname;

		const bloom = createBloom(10);
		addToBloom(bloom, testUrl);
		addToBloom(bloom, host);
		kv.store.set("intel:test-feed:bloom", serializeBloom(bloom));
		kv.store.set("intel:test-feed:exact-blob", JSON.stringify([testUrl, host]));

		const result = await checkUrlAgainstFeeds(env, MAILBOX_ID, testUrl);

		expect(result).not.toBeNull();
		expect(result?.confirmed).toBe(true);
		expect(result?.value).toBe(testUrl);
	});

	it("bloom hit but value absent from exact blob → confirmed: false", async () => {
		const { env, kv } = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [{ id: "test-feed", url: "https://test.example/feed.txt", kind: "url" }],
				},
			},
		});

		const testUrl = "https://evil.example/phish";

		const bloom = createBloom(10);
		addToBloom(bloom, testUrl);
		kv.store.set("intel:test-feed:bloom", serializeBloom(bloom));
		// exact blob is empty — simulates a bloom false positive or a value above the cap
		kv.store.set("intel:test-feed:exact-blob", JSON.stringify([]));

		const result = await checkUrlAgainstFeeds(env, MAILBOX_ID, testUrl);

		expect(result).not.toBeNull();
		expect(result?.confirmed).toBe(false);
	});

	it("URL not in bloom → null", async () => {
		const { env, kv } = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [{ id: "test-feed", url: "https://test.example/feed.txt", kind: "url" }],
				},
			},
		});

		const bloom = createBloom(10);
		kv.store.set("intel:test-feed:bloom", serializeBloom(bloom));
		kv.store.set("intel:test-feed:exact-blob", JSON.stringify([]));

		const result = await checkUrlAgainstFeeds(env, MAILBOX_ID, "https://safe.example/ok");

		expect(result).toBeNull();
	});

	it("no exact blob in KV → bloom hit falls back to confirmed: false gracefully", async () => {
		const { env, kv } = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [{ id: "test-feed", url: "https://test.example/feed.txt", kind: "url" }],
				},
			},
		});

		const testUrl = "https://evil.example/phish";

		const bloom = createBloom(10);
		addToBloom(bloom, testUrl);
		kv.store.set("intel:test-feed:bloom", serializeBloom(bloom));
		// no exact-blob key at all

		const result = await checkUrlAgainstFeeds(env, MAILBOX_ID, testUrl);

		expect(result).not.toBeNull();
		expect(result?.confirmed).toBe(false);
	});
});
