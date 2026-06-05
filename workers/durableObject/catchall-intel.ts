// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { DurableObject } from "cloudflare:workers";
import type { Env } from "../types";
import { applyMigrations, catchallIntelMigrations } from "./migrations";

export interface CatchallProbeEvent {
	source_ip: string;
	sender_domain: string;
	localpart: string;
	sender: string;
	subject_snippet: string;
	score: number;
	band: string;
	signals_json: string;
}

export interface CatchallSummary {
	totals: {
		total_probes: number;
		source_count: number;
		distinct_localparts: number;
	};
	topSources: Array<{
		source_ip: string;
		sender_domain: string;
		count: number;
		distinct_localparts: number;
		max_score: number;
		last_seen: string;
	}>;
	recent: Array<{
		id: string;
		ts: string;
		source_ip: string;
		sender_domain: string;
		sender: string;
		localpart: string;
		subject_snippet: string;
		score: number;
		band: string;
		signals_json: string;
	}>;
}

export class CatchallIntelDO extends DurableObject<Env> {
	declare __DURABLE_OBJECT_BRAND: never;

	constructor(state: DurableObjectState, env: Env) {
		super(state, env);
		applyMigrations(
			this.ctx.storage.sql,
			catchallIntelMigrations,
			this.ctx.storage,
		);
	}

	/**
	 * Record a single catch-all probe observation.
	 *
	 * Upserts probe_rollup and probe_localparts, caps both rings to
	 * `sample_limit`, then lazily GCs rows older than `retention_days`.
	 * A write failure rejects the returned Promise — callers may swallow.
	 */
	async recordCatchallProbe(
		event: CatchallProbeEvent,
		opts: { retention_days: number; sample_limit: number; now?: string },
	): Promise<void> {
		const nowTs = opts.now ?? new Date().toISOString();
		const cutoffTs = new Date(
			new Date(nowTs).getTime() -
				opts.retention_days * 24 * 60 * 60 * 1000,
		).toISOString();
		const sql = this.ctx.storage.sql;

		// Upsert rollup — count, max_score, last_seen; distinct_localparts updated below
		sql.exec(
			`INSERT INTO probe_rollup
			   (source_ip, sender_domain, count, distinct_localparts, max_score, first_seen, last_seen)
			 VALUES (?1, ?2, 1, 0, ?3, ?4, ?4)
			 ON CONFLICT(source_ip, sender_domain) DO UPDATE SET
			   count       = count + 1,
			   max_score   = MAX(max_score, excluded.max_score),
			   last_seen   = excluded.last_seen`,
			event.source_ip,
			event.sender_domain,
			event.score,
			nowTs,
		);

		// Upsert localpart record
		sql.exec(
			`INSERT INTO probe_localparts (source_ip, sender_domain, localpart, last_seen)
			 VALUES (?1, ?2, ?3, ?4)
			 ON CONFLICT(source_ip, sender_domain, localpart) DO UPDATE SET
			   last_seen = excluded.last_seen`,
			event.source_ip,
			event.sender_domain,
			event.localpart,
			nowTs,
		);

		// Cap localparts ring: evict oldest beyond sample_limit
		const lpCountRows = [
			...sql.exec(
				`SELECT COUNT(*) AS c FROM probe_localparts
				 WHERE source_ip = ?1 AND sender_domain = ?2`,
				event.source_ip,
				event.sender_domain,
			),
		] as Array<{ c: number }>;
		const lpCount = Number(lpCountRows[0]?.c ?? 0);
		if (lpCount > opts.sample_limit) {
			sql.exec(
				`DELETE FROM probe_localparts
				 WHERE source_ip = ?1 AND sender_domain = ?2
				   AND localpart NOT IN (
				     SELECT localpart FROM probe_localparts
				     WHERE source_ip = ?1 AND sender_domain = ?2
				     ORDER BY last_seen DESC LIMIT ?3
				   )`,
				event.source_ip,
				event.sender_domain,
				opts.sample_limit,
			);
		}

		// Sync distinct_localparts from actual tracked count
		sql.exec(
			`UPDATE probe_rollup
			 SET distinct_localparts = (
			   SELECT COUNT(*) FROM probe_localparts
			   WHERE source_ip = ?1 AND sender_domain = ?2
			 )
			 WHERE source_ip = ?1 AND sender_domain = ?2`,
			event.source_ip,
			event.sender_domain,
		);

		// Insert recent sample
		sql.exec(
			`INSERT INTO probe_recent
			   (id, ts, source_ip, sender_domain, sender, localpart, subject_snippet, score, band, signals_json)
			 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
			crypto.randomUUID(),
			nowTs,
			event.source_ip,
			event.sender_domain,
			event.sender,
			event.localpart,
			event.subject_snippet,
			event.score,
			event.band,
			event.signals_json,
		);

		// Cap recent ring: evict oldest beyond sample_limit
		const recentCountRows = [
			...sql.exec(`SELECT COUNT(*) AS c FROM probe_recent`),
		] as Array<{ c: number }>;
		const recentCount = Number(recentCountRows[0]?.c ?? 0);
		if (recentCount > opts.sample_limit) {
			sql.exec(
				`DELETE FROM probe_recent WHERE id IN (
				   SELECT id FROM probe_recent ORDER BY ts ASC LIMIT ?1
				 )`,
				recentCount - opts.sample_limit,
			);
		}

		// Lazy GC: evict rows past retention window
		sql.exec(`DELETE FROM probe_rollup WHERE last_seen < ?1`, cutoffTs);
		sql.exec(`DELETE FROM probe_recent WHERE ts < ?1`, cutoffTs);
		sql.exec(
			`DELETE FROM probe_localparts WHERE last_seen < ?1`,
			cutoffTs,
		);
	}

	/**
	 * Return aggregated catch-all stats for this domain.
	 *
	 * `limit` caps both topSources and recent lists; callers should pass a
	 * reasonable page size (e.g. 50) rather than unbounded.
	 */
	async getCatchallSummary(opts: { limit: number }): Promise<CatchallSummary> {
		const sql = this.ctx.storage.sql;

		const totalsRows = [
			...sql.exec(`
				SELECT
				  COALESCE(SUM(count), 0)              AS total_probes,
				  COUNT(*)                             AS source_count,
				  COALESCE(SUM(distinct_localparts), 0) AS distinct_localparts
				FROM probe_rollup
			`),
		] as Array<{
			total_probes: number;
			source_count: number;
			distinct_localparts: number;
		}>;
		const totals = totalsRows[0] ?? {
			total_probes: 0,
			source_count: 0,
			distinct_localparts: 0,
		};

		const topSources = [
			...sql.exec(
				`SELECT source_ip, sender_domain, count, distinct_localparts, max_score, last_seen
				 FROM probe_rollup
				 ORDER BY count DESC
				 LIMIT ?1`,
				opts.limit,
			),
		] as CatchallSummary["topSources"];

		const recent = [
			...sql.exec(
				`SELECT id, ts, source_ip, sender_domain, sender, localpart,
				        subject_snippet, score, band, signals_json
				 FROM probe_recent
				 ORDER BY ts DESC
				 LIMIT ?1`,
				opts.limit,
			),
		] as CatchallSummary["recent"];

		return {
			totals: {
				total_probes: Number(totals.total_probes),
				source_count: Number(totals.source_count),
				distinct_localparts: Number(totals.distinct_localparts),
			},
			topSources,
			recent,
		};
	}
}
