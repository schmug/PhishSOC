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
 *   4. A 304 renews the required blobs' TTLs (re-put same value) instead of
 *      letting them expire under sustained 304s, and a missing blob forces an
 *      unconditional refetch (#484).
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
	const putCalls: Array<{ key: string; opts?: { expirationTtl?: number } }> = [];
	return {
		store,
		putKeys,
		putCalls,
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
		async put(
			key: string,
			value: string | Uint8Array | ArrayBuffer,
			opts?: { expirationTtl?: number },
		) {
			putKeys.push(key);
			putCalls.push({ key, opts });
			store.set(key, value instanceof ArrayBuffer ? new Uint8Array(value) : value);
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
}): {
	env: Env;
	kv: ReturnType<typeof makeCountingKv>;
	upserts: Array<{ feedId: string; data: Record<string, unknown> }>;
} {
	const kv = opts.kv ?? makeCountingKv();
	const state = opts.feedState !== undefined ? opts.feedState : null;
	const upserts: Array<{ feedId: string; data: Record<string, unknown> }> = [];

	const stub = {
		async getIntelFeedState(_feedId: string) {
			return state;
		},
		async upsertIntelFeedState(feedId: string, data: unknown) {
			upserts.push({ feedId, data: data as Record<string, unknown> });
		},
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

	return { env, kv, upserts };
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

// ── Tests: blob TTL renewal under sustained 304s (#484) ──────────────────────

describe("blob TTL renewal on 304 (#484)", () => {
	function staleFetchedAt(hoursAgo: number): string {
		return new Date(Date.now() - hoursAgo * 3600 * 1000).toISOString();
	}

	function urlFeedSettings() {
		return {
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
		};
	}

	/** Seed both required blobs for a url-kind feed, returning the seeded values. */
	function seedUrlBlobs(kv: ReturnType<typeof makeCountingKv>) {
		const bloom = createBloom(10);
		addToBloom(bloom, "https://evil.example/phish");
		const bloomBytes = serializeBloom(bloom);
		const exactJson = JSON.stringify(["https://evil.example/phish"]);
		kv.store.set("intel:test-feed:bloom", bloomBytes);
		kv.store.set("intel:test-feed:exact-blob", exactJson);
		return { bloomBytes, exactJson };
	}

	it("304 with blobs present re-puts bloom + exact blobs with a fresh TTL (≤ required-blob writes)", async () => {
		vi.stubGlobal("fetch", async () => new Response(null, { status: 304 }));
		const kv = makeCountingKv();
		const { bloomBytes, exactJson } = seedUrlBlobs(kv);
		const { env } = makeEnv({
			mailboxSettings: urlFeedSettings(),
			kv,
			feedState: makeFeedState({
				etag: '"abc"',
				last_fetched_at: staleFetchedAt(8),
				entry_count: 1,
			}),
		});

		await refreshAllFeeds(env);

		// exactly the two required blobs — no extra writes
		expect([...kv.putKeys].sort()).toEqual([
			"intel:test-feed:bloom",
			"intel:test-feed:exact-blob",
		]);
		// every renewal put carries a fresh TTL: max(6h * 4, 86400) = 86400
		for (const call of kv.putCalls) {
			expect(call.opts?.expirationTtl).toBe(86400);
		}
		// rewrite-same-value renewal: blob contents unchanged
		expect(kv.store.get("intel:test-feed:bloom")).toEqual(bloomBytes);
		expect(kv.store.get("intel:test-feed:exact-blob")).toBe(exactJson);
	});

	it("304 on an ip-cidr feed re-puts the cidrs blob (write count = 1)", async () => {
		vi.stubGlobal("fetch", async () => new Response(null, { status: 304 }));
		const kv = makeCountingKv();
		const cidrJson = JSON.stringify([{ n: 16909056, m: 4294901760, p: 16 }]);
		kv.store.set("intel:spamhaus-drop:cidrs", cidrJson);
		const { env } = makeEnv({
			mailboxSettings: {
				intel: {
					// base DEFAULT_FEEDS entry supplies kind: "ip-cidr"
					feeds: [
						{ id: "spamhaus-drop", url: "https://test.example/drop.txt", refresh_hours: 12 },
					],
				},
			},
			kv,
			feedState: makeFeedState({
				feed_id: "spamhaus-drop",
				etag: '"abc"',
				last_fetched_at: staleFetchedAt(13),
				entry_count: 1,
			}),
		});

		await refreshAllFeeds(env);

		expect(kv.putKeys).toEqual(["intel:spamhaus-drop:cidrs"]);
		expect(kv.putCalls[0]?.opts?.expirationTtl).toBe(12 * 4 * 3600);
		expect(kv.store.get("intel:spamhaus-drop:cidrs")).toBe(cidrJson);
	});

	it("304 upserts a fresh last_fetched_at preserving etag and entry_count (keeps the refreshHours gate)", async () => {
		vi.stubGlobal("fetch", async () => new Response(null, { status: 304 }));
		const kv = makeCountingKv();
		seedUrlBlobs(kv);
		const before = Date.now();
		const { env, upserts } = makeEnv({
			mailboxSettings: urlFeedSettings(),
			kv,
			feedState: makeFeedState({
				etag: '"abc"',
				last_fetched_at: staleFetchedAt(8),
				entry_count: 7,
			}),
		});

		await refreshAllFeeds(env);

		expect(upserts).toHaveLength(1);
		const data = upserts[0].data as {
			last_fetched_at: string;
			etag: string | null;
			entry_count: number;
		};
		expect(new Date(data.last_fetched_at).getTime()).toBeGreaterThanOrEqual(before);
		expect(data.etag).toBe('"abc"');
		expect(data.entry_count).toBe(7);
	});

	it("missing required blob → fetch omits If-None-Match and a 200 rebuilds all blobs", async () => {
		const captured: Array<Record<string, string>> = [];
		vi.stubGlobal("fetch", async (_input: string | URL | Request, init?: RequestInit) => {
			captured.push({ ...((init?.headers as Record<string, string>) ?? {}) });
			return new Response(feedBody(5), { status: 200 });
		});
		const kv = makeCountingKv();
		// bloom survives but the exact blob has TTL-expired
		kv.store.set("intel:test-feed:bloom", serializeBloom(createBloom(10)));
		const { env } = makeEnv({
			mailboxSettings: urlFeedSettings(),
			kv,
			feedState: makeFeedState({
				etag: '"abc"',
				last_fetched_at: staleFetchedAt(8),
				entry_count: 5,
			}),
		});

		await refreshAllFeeds(env);

		expect(captured).toHaveLength(1);
		expect(captured[0]).not.toHaveProperty("If-None-Match");
		expect([...kv.putKeys].sort()).toEqual([
			"intel:test-feed:bloom",
			"intel:test-feed:exact-blob",
		]);
	});

	it("blobs present + stored etag → If-None-Match still sent (normal conditional flow)", async () => {
		const captured: Array<Record<string, string>> = [];
		vi.stubGlobal("fetch", async (_input: string | URL | Request, init?: RequestInit) => {
			captured.push({ ...((init?.headers as Record<string, string>) ?? {}) });
			return new Response(feedBody(5), { status: 200 });
		});
		const kv = makeCountingKv();
		seedUrlBlobs(kv);
		const { env } = makeEnv({
			mailboxSettings: urlFeedSettings(),
			kv,
			feedState: makeFeedState({
				etag: '"abc"',
				last_fetched_at: staleFetchedAt(8),
				entry_count: 1,
			}),
		});

		await refreshAllFeeds(env);

		expect(captured).toHaveLength(1);
		expect(captured[0]["If-None-Match"]).toBe('"abc"');
		// content changed → full rebuild of both blobs
		expect([...kv.putKeys].sort()).toEqual([
			"intel:test-feed:bloom",
			"intel:test-feed:exact-blob",
		]);
	});

	it("304 to an unconditional request (blobs missing) fails the refresh without marking it fresh", async () => {
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		vi.stubGlobal("fetch", async () => new Response(null, { status: 304 }));
		const kv = makeCountingKv(); // no blobs seeded
		const { env, upserts } = makeEnv({
			mailboxSettings: urlFeedSettings(),
			kv,
			feedState: makeFeedState({
				etag: '"abc"',
				last_fetched_at: staleFetchedAt(8),
				entry_count: 5,
			}),
		});

		const result = await refreshAllFeeds(env);

		// counted as failed, not refreshed; last_fetched_at stays stale → retried next run
		expect(result.feeds).toBe(0);
		expect(upserts).toHaveLength(0);
		expect(kv.putKeys).toHaveLength(0);
		expect(errorSpy).toHaveBeenCalled();
	});
});
