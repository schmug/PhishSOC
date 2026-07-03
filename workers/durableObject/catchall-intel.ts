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
import {
	computeHarvestAlerts,
	DEFAULT_HARVEST_ALERT_CONFIG,
	type AlertDebounceStore,
	type HarvestAlert,
	type HarvestAlertConfig,
	type ProbeRollupEntry,
} from "../intel/catchall-alert";

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
	/**
	 * Harvest-alert config from domain settings (#436), resolved by the caller.
	 * Absent ⇒ `DEFAULT_HARVEST_ALERT_CONFIG`. The crossing metric is
	 * `distinct_localparts` (not raw probe count); `harvestAlertWindowMinutes`
	 * is the debounce window (24h default).
	 */
	harvestAlertThreshold?: number;
	harvestAlertWindowMinutes?: number;
}

/** Public API shape for `GET /api/v1/domains/:domain/catchall-intel` (#427). */
export interface CatchallSummary {
	totals: {
		probe_count: number;
		distinct_sources: number;
		distinct_localparts: number;
	};
	topSources: Array<{
		source_ip: string;
		sender_domain: string;
		count: number;
		distinct_localparts: number;
		max_score: number;
		first_seen: string;
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

/** Minimal sql interface — matches the subset of DO `SqlStorage` we use. */
export interface SqlLike {
	exec<T = Record<string, unknown>>(
		sql: string,
		...params: unknown[]
	): Iterable<T>;
}

/** Deep-scan results written back to a probe sample (#438). RDAP + redirect
 *  only — never any IP-reputation signal, never a MailboxDO verdict. */
export interface CatchallDeepScanResult {
	resolved_url: string | null;
	domain_age_days: number | null;
	redirect_chain_length: number | null;
}

export function _recordProbeImpl(
	sql: SqlLike,
	event: CatchallProbeEvent,
): string {
	const {
		ts,
		sourceIp,
		senderDomain,
		sender,
		localpart,
		subjectSnippet,
		score,
		band,
		signals,
		retentionDays,
		sampleLimit,
	} = event;

	const cutoff = new Date(
		Date.parse(ts) - retentionDays * 86_400_000,
	).toISOString();

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
		sourceIp,
		senderDomain,
		score,
		ts,
		ts,
	);

	// Upsert localpart; update distinct_localparts on new entry
	const lpRows = [
		...sql.exec<{ cnt: number }>(
			`SELECT COUNT(*) as cnt FROM probe_localparts WHERE source_ip=? AND sender_domain=? AND localpart=?`,
			sourceIp,
			senderDomain,
			localpart,
		),
	];
	const isNewLocalpart = (lpRows[0]?.cnt ?? 0) === 0;

	sql.exec(
		`INSERT INTO probe_localparts (source_ip, sender_domain, localpart, last_seen)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(source_ip, sender_domain, localpart) DO UPDATE SET last_seen=excluded.last_seen`,
		sourceIp,
		senderDomain,
		localpart,
		ts,
	);

	if (isNewLocalpart) {
		sql.exec(
			`UPDATE probe_rollup SET distinct_localparts = distinct_localparts + 1
             WHERE source_ip=? AND sender_domain=?`,
			sourceIp,
			senderDomain,
		);
	}

	// Insert recent sample
	const id = crypto.randomUUID();
	sql.exec(
		`INSERT INTO probe_recent (id, ts, source_ip, sender_domain, sender, localpart, subject_snippet, score, band, signals_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id,
		ts,
		sourceIp,
		senderDomain,
		sender,
		localpart,
		subjectSnippet.slice(0, 200),
		score,
		band,
		JSON.stringify(signals),
	);

	// Evict oldest rows that exceed sampleLimit
	const countRows = [
		...sql.exec<{ cnt: number }>(`SELECT COUNT(*) as cnt FROM probe_recent`),
	];
	const total = countRows[0]?.cnt ?? 0;
	if (total > sampleLimit) {
		sql.exec(
			`DELETE FROM probe_recent WHERE id IN (
                SELECT id FROM probe_recent ORDER BY ts ASC LIMIT ?
             )`,
			total - sampleLimit,
		);
	}

	// The newly inserted sample's id lets the caller (#438) dispatch an async
	// deep-scan and write results back to this exact row via updateProbeDeepScan.
	return id;
}

/**
 * Write async deep-scan results (#438) back to a probe sample. No-op when the
 * sample id is unknown (e.g. it was evicted from the ring buffer before the
 * deep-scan completed). RDAP + redirect only — never touches any other table.
 */
export function _updateProbeDeepScanImpl(
	sql: SqlLike,
	sampleId: string,
	result: CatchallDeepScanResult,
): void {
	sql.exec(
		`UPDATE probe_recent
         SET resolved_url = ?, domain_age_days = ?, redirect_chain_length = ?
         WHERE id = ?`,
		result.resolved_url,
		result.domain_age_days,
		result.redirect_chain_length,
		sampleId,
	);
}

/**
 * `AlertDebounceStore` backed by the `harvest_alert_log` table (#436). `now` is
 * injected so the window cutoff is deterministic in tests without patching the
 * global clock.
 */
export function _harvestAlertStore(
	sql: SqlLike,
	now: Date,
): AlertDebounceStore {
	return {
		async getLastAlertTime(sourceIp, senderDomain, windowMinutes) {
			const cutoff = new Date(
				now.getTime() - windowMinutes * 60_000,
			).toISOString();
			const rows = [
				...sql.exec<{ alerted_at: string }>(
					`SELECT alerted_at FROM harvest_alert_log
				 WHERE source_ip = ? AND sender_domain = ? AND alerted_at > ?
				 ORDER BY alerted_at DESC LIMIT 1`,
					sourceIp,
					senderDomain,
					cutoff,
				),
			];
			return rows[0]?.alerted_at ?? null;
		},
		async recordAlertTime(sourceIp, senderDomain, alertedAt, distinctCount) {
			sql.exec(
				`INSERT INTO harvest_alert_log (source_ip, sender_domain, alerted_at, distinct_count)
				 VALUES (?, ?, ?, ?)`,
				sourceIp,
				senderDomain,
				alertedAt,
				distinctCount,
			);
		},
	};
}

/** Resolve the harvest-alert config carried on the probe event (#436), filling
 *  in `DEFAULT_HARVEST_ALERT_CONFIG` for any field the caller omitted. */
export function alertConfigFromEvent(
	event: CatchallProbeEvent,
): HarvestAlertConfig {
	return {
		threshold:
			event.harvestAlertThreshold ?? DEFAULT_HARVEST_ALERT_CONFIG.threshold,
		window_minutes:
			event.harvestAlertWindowMinutes ??
			DEFAULT_HARVEST_ALERT_CONFIG.window_minutes,
	};
}

/**
 * Run the directory-harvest alert check for the just-recorded probe (#436).
 * Inspects the rollup row for (event.sourceIp, event.senderDomain) — the pair
 * that may have crossed the distinct-localpart threshold — and returns the
 * alerts to emit, recording each in `harvest_alert_log` so it is debounced for
 * the window. Pass `now` to control time in tests.
 */
export async function _checkHarvestAlertImpl(
	sql: SqlLike,
	event: CatchallProbeEvent,
	config: HarvestAlertConfig,
	now: Date = new Date(),
): Promise<HarvestAlert[]> {
	const rollups = [
		...sql.exec<ProbeRollupEntry>(
			`SELECT source_ip, sender_domain, count, distinct_localparts, max_score, first_seen, last_seen
		 FROM probe_rollup WHERE source_ip = ? AND sender_domain = ?`,
			event.sourceIp,
			event.senderDomain,
		),
	];
	return computeHarvestAlerts(
		rollups,
		config,
		_harvestAlertStore(sql, now),
		now,
	);
}

/**
 * Emit a directory-harvest alert (#436). `console.warn` for now; this is the
 * single extension point for a richer channel (e.g. an EMAIL-binding operator
 * notification) so the emission mechanism can evolve without touching the
 * detection logic above.
 */
export function emitHarvestAlert(alert: HarvestAlert): void {
	console.warn(
		`[harvest-alert] directory-harvest pattern: ${alert.distinct_localpart_count} distinct local-parts ` +
			`from ${alert.source_ip} via ${alert.sender_domain} (at ${alert.triggered_at})`,
	);
}

export function _getSummaryImpl(
	sql: SqlLike,
	opts: { limit: number },
): CatchallSummary {
	const limit = Math.max(1, Math.min(opts.limit, 100));

	const totalRows = [
		...sql.exec<{ probe_count: number | null; distinct_sources: number }>(
			`SELECT SUM(count) as probe_count, COUNT(*) as distinct_sources FROM probe_rollup`,
		),
	];
	const localpartRows = [
		...sql.exec<{ distinct_localparts: number }>(
			`SELECT COUNT(DISTINCT localpart) as distinct_localparts FROM probe_localparts`,
		),
	];
	const totals = {
		probe_count: Number(totalRows[0]?.probe_count ?? 0) || 0,
		distinct_sources: totalRows[0]?.distinct_sources ?? 0,
		distinct_localparts: localpartRows[0]?.distinct_localparts ?? 0,
	};

	const topSources = [
		...sql.exec<{
			source_ip: string;
			sender_domain: string;
			count: number;
			distinct_localparts: number;
			max_score: number;
			first_seen: string;
			last_seen: string;
		}>(
			`SELECT source_ip, sender_domain, count, distinct_localparts, max_score, first_seen, last_seen
             FROM probe_rollup ORDER BY count DESC LIMIT ?`,
			limit,
		),
	].map((r) => ({
		source_ip: r.source_ip,
		sender_domain: r.sender_domain,
		count: r.count,
		distinct_localparts: r.distinct_localparts,
		max_score: r.max_score,
		first_seen: r.first_seen,
		last_seen: r.last_seen,
	}));

	const recent = [
		...sql.exec<{
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
		}>(
			`SELECT id, ts, source_ip, sender_domain, sender, localpart, subject_snippet, score, band, signals_json
             FROM probe_recent ORDER BY ts DESC LIMIT ?`,
			limit,
		),
	].map((r) => ({
		id: r.id,
		ts: r.ts,
		source_ip: r.source_ip,
		sender_domain: r.sender_domain,
		sender: r.sender,
		localpart: r.localpart,
		subject_snippet: r.subject_snippet,
		score: r.score,
		band: r.band,
		signals_json: r.signals_json,
	}));

	return { totals, topSources, recent };
}

export class CatchallIntelDO extends DurableObject<Env> {
	constructor(state: DurableObjectState, env: Env) {
		super(state, env);
		applyMigrations(
			this.ctx.storage.sql,
			catchallIntelMigrations,
			this.ctx.storage,
		);
	}

	async recordCatchallProbe(event: CatchallProbeEvent): Promise<string> {
		const sql = this.ctx.storage.sql as SqlLike;
		const id = _recordProbeImpl(sql, event);
		// Directory-harvest alert check (#436) runs AFTER the lazy GC + rollup
		// update inside _recordProbeImpl. Best-effort: an alert failure must not
		// fail probe recording.
		try {
			const alerts = await _checkHarvestAlertImpl(
				sql,
				event,
				alertConfigFromEvent(event),
			);
			for (const alert of alerts) emitHarvestAlert(alert);
		} catch (e) {
			console.error(
				"catchall harvest-alert check failed:",
				(e as Error).message,
			);
		}
		return id;
	}

	/** Write async deep-scan results (#438) back to the probe sample row. */
	async updateProbeDeepScan(
		sampleId: string,
		result: CatchallDeepScanResult,
	): Promise<void> {
		_updateProbeDeepScanImpl(this.ctx.storage.sql as SqlLike, sampleId, result);
	}

	async getCatchallSummary(opts: { limit: number }): Promise<CatchallSummary> {
		return _getSummaryImpl(this.ctx.storage.sql as SqlLike, opts);
	}
}
