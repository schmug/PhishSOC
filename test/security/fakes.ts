// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * In-memory fakes for the Cloudflare bindings that `runSecurityPipeline`
 * touches. Kept deliberately minimal — each fake implements only the methods
 * the pipeline actually calls. The types here use `any` ONLY for the Env
 * shape (Cloudflare's generated `Env` is huge and we don't need most of it);
 * individual fake surfaces are strictly typed.
 *
 * The `BLOOM_KV` binding is omitted by default so that `checkUrlAgainstFeeds`
 * returns `null` naturally — most suites run without any intel-feed state.
 * Suites that exercise feed matching pass `bloomKv: createFakeFeedKv(...)`.
 */

import type { Env } from "../../workers/types";
import { feedBloomKeys, parseFeedBody } from "../../workers/intel/feeds";
import { addToBloom, createBloom, serializeBloom } from "../../workers/intel/bloom";
import type { SenderReputation } from "../../workers/security/reputation";
import type { MailboxSecuritySettings } from "../../workers/security/settings";

export interface FakeVerdictRow {
	verdict_json: string;
	score: number;
	explanation: string;
}

export interface FakeUrlRow {
	url: string;
	display_text: string | null;
	is_homograph: number;
	is_shortener: number;
	hostname?: string | null;
}

export interface IntelFeedStateRow {
	feed_id: string;
	url: string;
	last_fetched_at: string;
	etag: string | null;
	entry_count: number;
	bloom_kv_key: string;
}

export interface FakeSenderGraphRecord {
	sender_address: string;
	message_count: number;
}

/**
 * Minimal subset of `MailboxDO` methods the security pipeline calls. Widened
 * to include the feed-state methods so the pipeline's intel lookup doesn't
 * throw if a feed is registered (we don't register any in tests, but the
 * surface is here for future coverage).
 */
export interface FakeMailboxStub {
	getSenderReputation(sender: string): Promise<SenderReputation | null>;
	upsertSenderReputation(sender: string, newScore: number): Promise<void>;
	flagSender(sender: string, flagged: boolean): Promise<void>;
	persistSecurityVerdict(emailId: string, data: FakeVerdictRow): Promise<void>;
	insertUrls(emailId: string, urls: FakeUrlRow[]): Promise<void>;
	moveEmail(id: string, folderId: string): Promise<void>;
	getIntelFeedState(feedId: string): Promise<IntelFeedStateRow | null>;
	upsertIntelFeedState(
		feedId: string,
		data: Omit<IntelFeedStateRow, "feed_id">,
	): Promise<void>;
	getSenderGraphByName(senderName: string): Promise<FakeSenderGraphRecord[]>;
	upsertSenderGraph(senderName: string, senderAddress: string): Promise<void>;
}

export function createFakeMailboxStub(): {
	stub: FakeMailboxStub;
	reputation: Map<string, SenderReputation>;
	verdicts: Map<string, FakeVerdictRow>;
	urls: Map<string, FakeUrlRow[]>;
	moves: Array<{ id: string; folderId: string }>;
	feedState: Map<string, IntelFeedStateRow>;
	senderGraph: Map<string, FakeSenderGraphRecord[]>;
} {
	const reputation = new Map<string, SenderReputation>();
	const verdicts = new Map<string, FakeVerdictRow>();
	const urls = new Map<string, FakeUrlRow[]>();
	const moves: Array<{ id: string; folderId: string }> = [];
	const feedState = new Map<string, IntelFeedStateRow>();
	const senderGraph = new Map<string, FakeSenderGraphRecord[]>();

	const stub: FakeMailboxStub = {
		async getSenderReputation(sender) {
			return reputation.get(sender) ?? null;
		},
		async upsertSenderReputation(sender, newScore) {
			const now = new Date().toISOString();
			const existing = reputation.get(sender);
			if (!existing) {
				reputation.set(sender, {
					sender,
					first_seen: now,
					last_seen: now,
					message_count: 1,
					avg_score: newScore,
					flagged: false,
				});
				return;
			}
			const cappedCount = Math.min(existing.message_count, 1000);
			const newAvg = (existing.avg_score * cappedCount + newScore) / (cappedCount + 1);
			reputation.set(sender, {
				...existing,
				last_seen: now,
				message_count: cappedCount + 1,
				avg_score: newAvg,
			});
		},
		async flagSender(sender, flagged) {
			const existing = reputation.get(sender);
			if (!existing) return;
			reputation.set(sender, { ...existing, flagged });
		},
		async persistSecurityVerdict(emailId, data) {
			verdicts.set(emailId, data);
		},
		async insertUrls(emailId, rows) {
			urls.set(emailId, rows);
		},
		async moveEmail(id, folderId) {
			moves.push({ id, folderId });
		},
		async getIntelFeedState(feedId) {
			return feedState.get(feedId) ?? null;
		},
		async upsertIntelFeedState(feedId, data) {
			feedState.set(feedId, { feed_id: feedId, ...data });
		},
		async getSenderGraphByName(name) {
			return senderGraph.get(name) ?? [];
		},
		async upsertSenderGraph(name, address) {
			const existing = senderGraph.get(name) ?? [];
			const idx = existing.findIndex((r) => r.sender_address === address);
			if (idx === -1) {
				senderGraph.set(name, [...existing, { sender_address: address, message_count: 1 }]);
			} else {
				const updated = [...existing];
				updated[idx] = { ...updated[idx], message_count: updated[idx].message_count + 1 };
				senderGraph.set(name, updated);
			}
		},
	};

	return { stub, reputation, verdicts, urls, moves, feedState, senderGraph };
}

export interface FakeEnvParts {
	settings?: Partial<MailboxSecuritySettings>;
	mailboxId: string;
	stub: FakeMailboxStub;
	/** Mailbox-tier `intel` block, e.g. `{ feeds: [{ id, kind, url: "" }] }`. */
	intel?: unknown;
	/** Extra R2 objects by key (e.g. `domains/<domain>.json` for the catch-all path). */
	objects?: Record<string, unknown>;
	/** Intel-feed KV; see `createFakeFeedKv`. */
	bloomKv?: KVNamespace;
}

/**
 * Build a fake R2 bucket that serves the mailbox settings JSON plus any extra
 * objects. `.list()` returns the mailbox key only (for `refreshAllFeeds`);
 * `.put()` is not implemented — the security pipeline doesn't call it.
 */
function createFakeBucket(
	mailboxId: string,
	settings: Partial<MailboxSecuritySettings>,
	intel?: unknown,
	objects: Record<string, unknown> = {},
): R2Bucket {
	const payloads = new Map<string, string>();
	payloads.set(
		`mailboxes/${mailboxId}.json`,
		JSON.stringify(intel === undefined ? { security: settings } : { security: settings, intel }),
	);
	for (const [key, value] of Object.entries(objects)) payloads.set(key, JSON.stringify(value));
	return {
		async list() {
			return { objects: [{ key: `mailboxes/${mailboxId}.json` }] };
		},
		async get(requested: string) {
			const payload = payloads.get(requested);
			if (payload === undefined) return null;
			return {
				async json() {
					return JSON.parse(payload);
				},
				async text() {
					return payload;
				},
			};
		},
	} as unknown as R2Bucket;
}

export interface FakeFeedSeed {
	id: string;
	kind: "domain" | "url";
	/** Feed body lines, stored through the real `parseFeedBody` + `feedBloomKeys` ingest path. */
	lines?: string[];
	/**
	 * Values stored verbatim in the bloom and exact blob, skipping ingest and
	 * the path prefilter keys (blobs written by an older build).
	 */
	rawValues?: string[];
	/** Values added to the bloom but not the exact blob (bloom-only hits). */
	bloomOnly?: string[];
}

/**
 * In-memory `BLOOM_KV` holding `intel:<id>:bloom` (serialized bloom) and
 * `intel:<id>:exact-blob` (JSON array) per feed, built the same way
 * `refreshFeed` builds them. Blooms are sized for 5000 entries: a bloom sized
 * for 2 entries gives false positives on unrelated probe strings. `put` is
 * implemented so `refreshAllFeeds` can write into it.
 */
export function createFakeFeedKv(feeds: FakeFeedSeed[]): KVNamespace {
	const store = new Map<string, ArrayBuffer | string>();
	for (const feed of feeds) {
		const ingested = parseFeedBody((feed.lines ?? []).join("\n"), feed.kind);
		const values = [...ingested, ...(feed.rawValues ?? [])];
		const bloom = createBloom(5000);
		const bloomKeys = [
			...feedBloomKeys(ingested, feed.kind),
			...(feed.rawValues ?? []),
			...(feed.bloomOnly ?? []),
		];
		for (const v of bloomKeys) addToBloom(bloom, v);
		const bytes = serializeBloom(bloom);
		store.set(
			`intel:${feed.id}:bloom`,
			bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
		);
		store.set(`intel:${feed.id}:exact-blob`, JSON.stringify([...new Set(values)]));
	}
	const meta = new Map<string, unknown>();
	async function get(key: string, type?: "text" | "arrayBuffer") {
		const value = store.get(key);
		if (value === undefined) return null;
		if (type === "arrayBuffer") return value instanceof ArrayBuffer ? value : null;
		return typeof value === "string" ? value : null;
	}
	return {
		get,
		async getWithMetadata(key: string, type?: "text" | "arrayBuffer") {
			return { value: await get(key, type), metadata: meta.get(key) ?? null };
		},
		async put(key: string, value: ArrayBuffer | Uint8Array | string, opts?: { metadata?: unknown }) {
			meta.set(key, opts?.metadata ?? null);
			store.set(
				key,
				value instanceof Uint8Array
					? (value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer)
					: value,
			);
		},
	} as unknown as KVNamespace;
}

/**
 * Build a minimal fake `Env` for the pipeline. The `AI` binding is only used
 * by the (overridden) classifier; we stamp in a stub that throws if called so
 * that tests which forget to inject the classifier fail loudly rather than
 * silently trying to hit Workers AI.
 */
export function makeFakeEnv(parts: FakeEnvParts): Env {
	const mailboxNs = {
		idFromName(_name: string) {
			return { toString: () => _name } as unknown as DurableObjectId;
		},
		get(_id: DurableObjectId) {
			return parts.stub as unknown as DurableObjectStub;
		},
	} as unknown as DurableObjectNamespace;

	const ai = {
		run() {
			throw new Error(
				"AI.run called in tests — inject a classifier via __setClassifier first",
			);
		},
	} as unknown as Ai;

	return {
		AI: ai,
		BUCKET: createFakeBucket(
			parts.mailboxId,
			parts.settings ?? { enabled: true },
			parts.intel,
			parts.objects,
		),
		MAILBOX: mailboxNs,
		// BLOOM_KV undefined unless a suite seeds feeds — pipeline skips feed checks.
		...(parts.bloomKv ? { BLOOM_KV: parts.bloomKv } : {}),
		POLICY_AUD: "",
		TEAM_DOMAIN: "",
	} as unknown as Env;
}
