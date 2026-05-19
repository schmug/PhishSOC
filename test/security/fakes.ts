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
 * The `BLOOM_KV` binding is intentionally omitted so that
 * `checkUrlAgainstFeeds` returns `null` naturally — the test suite runs
 * without any intel-feed state.
 */

import type { Env } from "../../workers/types";
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
}

/**
 * Build a fake R2 bucket that serves the mailbox settings JSON. Only `.get()`
 * is implemented — the security pipeline doesn't call `.put()` or `.list()`.
 */
function createFakeBucket(
	mailboxId: string,
	settings: Partial<MailboxSecuritySettings>,
): R2Bucket {
	const key = `mailboxes/${mailboxId}.json`;
	const payload = JSON.stringify({ security: settings });
	return {
		async get(requested: string) {
			if (requested !== key) return null;
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
		BUCKET: createFakeBucket(parts.mailboxId, parts.settings ?? { enabled: true }),
		MAILBOX: mailboxNs,
		// BLOOM_KV intentionally undefined — pipeline skips feed checks.
		POLICY_AUD: "",
		TEAM_DOMAIN: "",
	} as unknown as Env;
}
