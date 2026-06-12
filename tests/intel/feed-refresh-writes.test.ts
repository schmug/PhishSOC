// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * KV write-volume regression tests for #481.
 *
 * The hourly cron was rewriting one KV key PER feed entry (capped at 2,000)
 * on every run — ~49k writes/day — which crossed the Workers Paid included
 * 1M KV writes and started overage billing. Two invariants pinned here:
 *
 *   1. A `url`-kind feed refresh costs at most 2 `BLOOM_KV.put` calls:
 *      the bloom blob plus ONE serialized exact-match set blob (the same
 *      single-blob pattern the `ip-cidr` path already uses).
 *   2. `refreshAllFeeds` honors `refreshHours`: a feed fetched more
 *      recently than its interval is skipped entirely (no fetch); a feed
 *      with no recorded state (first run) or stale state still fetches.
 *
 * The read path must be behaviorally identical: a bloom hit is only
 * `confirmed` when the value is a member of the exact set — a bloom-only
 * collision must not confirm.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkUrlAgainstFeeds, refreshAllFeeds } from "../../workers/intel/feeds";
import { addToBloom, createBloom, serializeBloom } from "../../workers/intel/bloom";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import type { Env } from "../../workers/types";

const MAILBOX_ID = "user@example.com";
const FEED_HOST = "feeds.test.example";
const FEED_URL = `https://${FEED_HOST}/list.txt`;

// ── Fakes ─────────────────────────────────────────────────────────────

/** Mock KV that counts `put` calls and supports `get(key, "arrayBuffer")`. */
function makeKv() {
	const store = new Map<string, string | Uint8Array>();
	const state = { puts: 0 };
	return {
		store,
		state,
		async get(key: string, type?: string) {
			const v = store.get(key);
			if (v === undefined) return null;
			if (type === "arrayBuffer") {
				const bytes = typeof v === "string" ? new TextEncoder().encode(v) : v;
				return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
			}
			return typeof v === "string" ? v : new TextDecoder().decode(v);
		},
		async put(key: string, value: string | Uint8Array) {
			state.puts++;
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
	return {
		async getIntelFeedState(feedId: string) {
			return states[feedId] ?? null;
		},
		async upsertIntelFeedState(_feedId: string, _state: unknown) {},
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

/** Serve `body` for every fetch; record calls. */
function mockFetch(body: string) {
	const calls: string[] = [];
	const fn = vi.fn(async (input: string | URL | Request) => {
		calls.push(typeof input === "string" ? input : input.toString());
		return new Response(body, { status: 200 });
	});
	globalThis.fetch = fn as unknown as typeof fetch;
	return calls;
}

function feedBody(count: number): string {
	return Array.from({ length: count }, (_, i) => `https://bad${i}.example/p${i}`).join("\n");
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

// ── Write volume (#481 invariant 1) ───────────────────────────────────

describe("feed refresh KV write volume (#481)", () => {
	it("a url-kind feed refresh performs at most 2 BLOOM_KV.put calls", async () => {
		mockFetch(feedBody(50));
		const kv = makeKv();
		const env = makeEnv({ mailboxSettings: urlFeedSettings(), kv });

		const result = await refreshAllFeeds(env);

		expect(result.feeds).toBe(1);
		// Bloom blob + ONE exact-set blob. Anything proportional to entry
		// count reintroduces the 49k-writes/day KV overage.
		expect(kv.state.puts).toBeLessThanOrEqual(2);
	});

	it("writes no per-entry exact keys, only blob keys", async () => {
		mockFetch(feedBody(50));
		const kv = makeKv();
		const env = makeEnv({ mailboxSettings: urlFeedSettings(), kv });

		await refreshAllFeeds(env);

		const keys = [...kv.store.keys()];
		expect(keys.filter((k) => k.startsWith("intel:testfeed:exact:"))).toEqual([]);
		expect(keys).toContain("intel:testfeed:bloom");
	});

	it("caps the exact-set blob at 2000 entries", async () => {
		// 1100 URL lines parse to 2200 values (each URL also contributes its
		// hostname) — the blob must stay capped so it sits far below KV's
		// 25 MB value limit.
		mockFetch(feedBody(1100));
		const kv = makeKv();
		const env = makeEnv({ mailboxSettings: urlFeedSettings(), kv });

		await refreshAllFeeds(env);

		const blobKey = [...kv.store.keys()].find(
			(k) => k.startsWith("intel:testfeed:") && k !== "intel:testfeed:bloom",
		);
		expect(blobKey).toBeDefined();
		const blob = await kv.get(blobKey!);
		const parsed = JSON.parse(blob as string) as string[];
		expect(Array.isArray(parsed)).toBe(true);
		expect(parsed.length).toBeLessThanOrEqual(2000);
	});
});

// ── refreshHours staleness skip (#481 invariant 2) ────────────────────

describe("refreshAllFeeds honors refreshHours (#481)", () => {
	it("skips a feed fetched more recently than its refreshHours", async () => {
		const calls = mockFetch(feedBody(5));
		const stub = makeMailboxStub({
			testfeed: {
				last_fetched_at: new Date(Date.now() - 30 * 60 * 1000).toISOString(), // 30 min ago
				etag: null,
				entry_count: 5,
			},
		});
		const env = makeEnv({ mailboxSettings: urlFeedSettings(6), stub });

		const result = await refreshAllFeeds(env);

		expect(calls).toEqual([]);
		expect(result.feeds).toBe(0);
	});

	it("still fetches a feed whose state is older than refreshHours", async () => {
		const calls = mockFetch(feedBody(5));
		const stub = makeMailboxStub({
			testfeed: {
				last_fetched_at: new Date(Date.now() - 7 * 3600 * 1000).toISOString(), // 7h ago
				etag: null,
				entry_count: 5,
			},
		});
		const env = makeEnv({ mailboxSettings: urlFeedSettings(6), stub });

		const result = await refreshAllFeeds(env);

		expect(calls).toEqual([FEED_URL]);
		expect(result.feeds).toBe(1);
	});

	it("still fetches on first run (no recorded feed state)", async () => {
		const calls = mockFetch(feedBody(5));
		const env = makeEnv({ mailboxSettings: urlFeedSettings(6) });

		const result = await refreshAllFeeds(env);

		expect(calls).toEqual([FEED_URL]);
		expect(result.feeds).toBe(1);
	});
});

// ── Read path equivalence (#481 invariant 3) ──────────────────────────

describe("exact-match confirmation via blob membership (#481)", () => {
	it("confirms a URL that the feed actually contains, end to end", async () => {
		mockFetch("https://evil.example/login\nhttps://other.example/x\n");
		const kv = makeKv();
		const env = makeEnv({ mailboxSettings: urlFeedSettings(), kv });
		await refreshAllFeeds(env);

		const match = await checkUrlAgainstFeeds(env, MAILBOX_ID, "https://evil.example/login");

		expect(match).not.toBeNull();
		expect(match!.feedId).toBe("testfeed");
		expect(match!.confirmed).toBe(true);
	});

	it("does not confirm a bloom-only collision absent from the exact set", async () => {
		// Hand-craft KV state: the bloom contains BOTH values, but the exact
		// set contains only one. The member must confirm; the other (a
		// simulated bloom false-positive) must surface as confirmed: false.
		const member = "https://evil.example/login";
		const collision = "https://collide.example/x";
		const bloom = createBloom(10);
		for (const v of [member, collision, "evil.example", "collide.example"]) {
			addToBloom(bloom, v);
		}
		const kv = makeKv();
		kv.store.set("intel:testfeed:bloom", serializeBloom(bloom));
		kv.store.set("intel:testfeed:exactset", JSON.stringify([member, "evil.example"]));
		const env = makeEnv({ mailboxSettings: urlFeedSettings(), kv });

		const confirmed = await checkUrlAgainstFeeds(env, MAILBOX_ID, member);
		expect(confirmed).not.toBeNull();
		expect(confirmed!.confirmed).toBe(true);

		const collided = await checkUrlAgainstFeeds(env, MAILBOX_ID, collision);
		expect(collided).not.toBeNull();
		expect(collided!.confirmed).toBe(false);
	});
});
