// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * CatchallIntelDO — per-domain catch-all probe store (issue #425).
 *
 * Keyed by `idFromName(domain)`. Records probe activity as rollups plus a
 * capped ring of recent samples. Stores derived stats only — never the full
 * message body, never attachments.
 *
 * Three tables (see `catchallIntelMigrations`):
 *   - `probe_rollup`     — upsert-incremented (source_ip, sender_domain) stats
 *   - `probe_localparts` — per-(ip, domain, localpart) seen-set for distinct count
 *   - `probe_recent`     — ring buffer capped at `sampleLimit`, oldest evicted
 *
 * Lazy GC runs on every write: rows older than `retentionDays` are deleted.
 *
 * Business logic is in the exported `_recordProbeImpl` / `_getSummaryImpl`
 * helpers so unit tests can drive them via a Node `node:sqlite` adapter
 * without a Workers runtime.
 */

import { DurableObject } from "cloudflare:workers";
import type { Env } from "../types";
import { applyMigrations, catchallIntelMigrations } from "./migrations";

export interface CatchallProbeEvent {
	/** ISO-8601 timestamp of the probe (injected by caller so tests can freeze time). */
	ts: string;
	sourceIp: string;
	senderDomain: string;
	sender: string;
	/** Local-part of the catch-all recipient address. */
	localpart: string;
	/** First 200 chars of the subject. */
	subjectSnippet: string;
	score: number;
	band: "low" | "medium" | "high";
	signals: string[];
	/** From domain settings; controls GC window. */
	retentionDays: number;
	/** From domain settings; controls ring-buffer cap. */
	sampleLimit: number;
}

export interface CatchallSummary {
	totals: { count: number; distinctSources: number };
	topSources: Array<{
		sourceIp: string;
		senderDomain: string;
		count: number;
		distinctLocalparts: number;
		maxScore: number;
		firstSeen: string;
		lastSeen: string;
	}>;
	recent: Array<{
		id: string;
		ts: string;
		sourceIp: string;
		senderDomain: string;
		sender: string;
		localpart: string;
		subjectSnippet: string;
		score: number;
		band: string;
		signals: string[];
	}>;
}

/** Minimal sql interface — matches the subset of DO `SqlStorage` we use. */
export interface SqlLike {
	exec<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Iterable<T>;
}

export function _recordProbeImpl(sql: SqlLike, event: CatchallProbeEvent): void {
	const {
		ts, sourceIp, senderDomain, sender, localpart,
		subjectSnippet, score, band, signals, retentionDays, sampleLimit,
	} = event;

	const cutoff = new Date(new Date(ts).getTime() - retentionDays * 86_400_000).toISOString();

	// Lazy GC
	sql.exec(`DELETE FROM probe_rollup WHERE last_seen < ?`, cutoff);
	sql.exec(`DELETE FROM probe_localparts WHERE last_seen < ?`, cutoff);
	sql.exec(`DELETE FROM probe_recent WHERE ts < ?`, cutoff);

	// Upsert rollup — distinct_localparts starts at 0 so the isNewLocalpart
	// branch below is the single source of truth for incrementing it.
	sql.exec(
		`INSERT INTO probe_rollup (source_ip, sender_domain, count, distinct_localparts, max_score, first_seen, last_seen)
         VALUES (?, ?, 1, 0, ?, ?, ?)
         ON CONFLICT(source_ip, sender_domain) DO UPDATE SET
           count = count + 1,
           max_score = MAX(max_score, excluded.max_score),
           last_seen = excluded.last_seen`,
		sourceIp, senderDomain, score, ts, ts,
	);

	// Upsert localpart; update distinct_localparts on new entry
	const lpRows = [...sql.exec<{ cnt: number }>(
		`SELECT COUNT(*) as cnt FROM probe_localparts WHERE source_ip=? AND sender_domain=? AND localpart=?`,
		sourceIp, senderDomain, localpart,
	)];
	const isNewLocalpart = (lpRows[0]?.cnt ?? 0) === 0;

	sql.exec(
		`INSERT INTO probe_localparts (source_ip, sender_domain, localpart, last_seen)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(source_ip, sender_domain, localpart) DO UPDATE SET last_seen=excluded.last_seen`,
		sourceIp, senderDomain, localpart, ts,
	);

	if (isNewLocalpart) {
		sql.exec(
			`UPDATE probe_rollup SET distinct_localparts = distinct_localparts + 1
             WHERE source_ip=? AND sender_domain=?`,
			sourceIp, senderDomain,
		);
	}

	// Insert recent sample
	const id = crypto.randomUUID();
	sql.exec(
		`INSERT INTO probe_recent (id, ts, source_ip, sender_domain, sender, localpart, subject_snippet, score, band, signals_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, ts, sourceIp, senderDomain, sender, localpart,
		subjectSnippet.slice(0, 200), score, band, JSON.stringify(signals),
	);

	// Evict oldest rows that exceed sampleLimit
	const countRows = [...sql.exec<{ cnt: number }>(`SELECT COUNT(*) as cnt FROM probe_recent`)];
	const total = countRows[0]?.cnt ?? 0;
	if (total > sampleLimit) {
		sql.exec(
			`DELETE FROM probe_recent WHERE id IN (
                SELECT id FROM probe_recent ORDER BY ts ASC LIMIT ?
             )`,
			total - sampleLimit,
		);
	}
}

export function _getSummaryImpl(sql: SqlLike, opts: { limit: number }): CatchallSummary {
	const limit = Math.max(1, Math.min(opts.limit, 100));

	const totalRows = [
		...sql.exec<{ count: number | null; distinctSources: number }>(
			`SELECT SUM(count) as count, COUNT(*) as distinctSources FROM probe_rollup`,
		),
	];
	const totals = {
		count: totalRows[0]?.count ?? 0,
		distinctSources: totalRows[0]?.distinctSources ?? 0,
	};

	const topSources = [
		...sql.exec<{
			source_ip: string; sender_domain: string; count: number;
			distinct_localparts: number; max_score: number; first_seen: string; last_seen: string;
		}>(
			`SELECT source_ip, sender_domain, count, distinct_localparts, max_score, first_seen, last_seen
             FROM probe_rollup ORDER BY count DESC LIMIT ?`,
			limit,
		),
	].map((r) => ({
		sourceIp: r.source_ip,
		senderDomain: r.sender_domain,
		count: r.count,
		distinctLocalparts: r.distinct_localparts,
		maxScore: r.max_score,
		firstSeen: r.first_seen,
		lastSeen: r.last_seen,
	}));

	const recentRows = [
		...sql.exec<{
			id: string; ts: string; source_ip: string; sender_domain: string;
			sender: string; localpart: string; subject_snippet: string;
			score: number; band: string; signals_json: string;
		}>(
			`SELECT id, ts, source_ip, sender_domain, sender, localpart, subject_snippet, score, band, signals_json
             FROM probe_recent ORDER BY ts DESC LIMIT ?`,
			limit,
		),
	].map((r) => ({
		id: r.id,
		ts: r.ts,
		sourceIp: r.source_ip,
		senderDomain: r.sender_domain,
		sender: r.sender,
		localpart: r.localpart,
		subjectSnippet: r.subject_snippet,
		score: r.score,
		band: r.band,
		signals: (() => {
			try { return JSON.parse(r.signals_json) as string[]; } catch { return []; }
		})(),
	}));

	return { totals, topSources, recent: recentRows };
}

export class CatchallIntelDO extends DurableObject<Env> {
	constructor(state: DurableObjectState, env: Env) {
		super(state, env);
		applyMigrations(this.ctx.storage.sql, catchallIntelMigrations, this.ctx.storage);
	}

	async recordCatchallProbe(event: CatchallProbeEvent): Promise<void> {
		_recordProbeImpl(this.ctx.storage.sql as SqlLike, event);
	}

	async getCatchallSummary(opts: { limit: number }): Promise<CatchallSummary> {
		return _getSummaryImpl(this.ctx.storage.sql as SqlLike, opts);
	}
}
