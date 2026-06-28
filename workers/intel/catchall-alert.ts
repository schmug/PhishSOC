// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Directory-harvest alerting driven by catch-all probe rollups (#429).
 *
 * Stateless logic layer: `computeHarvestAlerts` inspects a rollup snapshot,
 * applies the threshold check, consults a `AlertDebounceStore` for prior
 * alerts within the window, and returns the alerts that should be raised.
 * Callers (the `receiveCatchall` wiring in #426) act on the returned list —
 * this module never creates cases or sends notifications directly.
 *
 * The `AlertDebounceStore` interface will be implemented by `CatchallIntelDO`
 * in #425 using a `harvest_alert_log` SQLite table.
 */

import type { CatchallIntelSettings } from "../../shared/domain-settings";

// ── Types ────────────────────────────────────────────────────────────────────

/** Matches the `probe_rollup` row shape from `CatchallIntelDO` (#425). */
export interface ProbeRollupEntry {
	source_ip: string;
	sender_domain: string;
	count: number;
	distinct_localparts: number;
	max_score: number;
	first_seen: string;
	last_seen: string;
}

/** An alert to raise — returned by `computeHarvestAlerts` for each new
 *  (source_ip, sender_domain) pair that crossed the threshold this window. */
export interface HarvestAlert {
	source_ip: string;
	sender_domain: string;
	distinct_localpart_count: number;
	triggered_at: string;
}

/** Resolved alert config after applying defaults. */
export interface HarvestAlertConfig {
	threshold: number;
	window_minutes: number;
}

/**
 * Default alert config used when `catchall_intel` doesn't specify values.
 *
 * `threshold` is the number of distinct local-parts a single (source_ip,
 * sender_domain) pair must hit to look like a directory harvest. `window_minutes`
 * is the debounce window — at most one alert per pair per window. The window
 * defaults to 24h (1440 min) so a sustained harvest doesn't re-alert hourly
 * (#436; the crossing metric stays `distinct_localparts`, not raw probe count).
 */
export const DEFAULT_HARVEST_ALERT_CONFIG: HarvestAlertConfig = {
	threshold: 50,
	window_minutes: 1440,
};

/**
 * Persistent debounce state for harvest alerts.
 *
 * The implementation lives in `CatchallIntelDO` (#425). A test double can be
 * created with a plain in-memory map — see `tests/intel/catchall-alert.test.ts`.
 */
export interface AlertDebounceStore {
	/**
	 * Returns the ISO-8601 timestamp of the most recent alert recorded for
	 * `(sourceIp, senderDomain)` within the last `windowMinutes` minutes, or
	 * `null` when no in-window alert exists (meaning a new alert SHOULD fire).
	 */
	getLastAlertTime(
		sourceIp: string,
		senderDomain: string,
		windowMinutes: number,
	): Promise<string | null>;

	/**
	 * Persists a new alert event so subsequent calls to `getLastAlertTime`
	 * within the window return it and suppress duplicate alerts.
	 */
	recordAlertTime(
		sourceIp: string,
		senderDomain: string,
		alertedAt: string,
		distinctCount: number,
	): Promise<void>;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Resolve `catchall_intel` settings (possibly absent) into a fully-populated
 * `HarvestAlertConfig`, filling in defaults for missing fields.
 */
export function resolveAlertConfig(
	settings: CatchallIntelSettings | undefined,
): HarvestAlertConfig {
	return {
		threshold:
			settings?.harvest_alert_threshold ??
			DEFAULT_HARVEST_ALERT_CONFIG.threshold,
		window_minutes:
			settings?.harvest_alert_window_minutes ??
			DEFAULT_HARVEST_ALERT_CONFIG.window_minutes,
	};
}

// ── Core function ─────────────────────────────────────────────────────────────

/**
 * Given a rollup snapshot from `CatchallIntelDO.getCatchallSummary`,
 * determine which (source_ip, sender_domain) pairs should trigger a new
 * harvest alert.
 *
 * For each rollup whose `distinct_localparts` meets or exceeds
 * `config.threshold`, the function queries `store.getLastAlertTime` to check
 * whether an alert was already raised within the current window. If not, it
 * calls `store.recordAlertTime` and adds the entry to the returned list.
 *
 * Pass an explicit `now` in tests to control time without patching globals.
 */
export async function computeHarvestAlerts(
	rollups: ProbeRollupEntry[],
	config: HarvestAlertConfig,
	store: AlertDebounceStore,
	now: Date = new Date(),
): Promise<HarvestAlert[]> {
	const alerts: HarvestAlert[] = [];
	const triggeredAt = now.toISOString();

	for (const row of rollups) {
		if (row.distinct_localparts < config.threshold) continue;

		const lastAlert = await store.getLastAlertTime(
			row.source_ip,
			row.sender_domain,
			config.window_minutes,
		);
		if (lastAlert !== null) continue; // debounced

		await store.recordAlertTime(
			row.source_ip,
			row.sender_domain,
			triggeredAt,
			row.distinct_localparts,
		);

		alerts.push({
			source_ip: row.source_ip,
			sender_domain: row.sender_domain,
			distinct_localpart_count: row.distinct_localparts,
			triggered_at: triggeredAt,
		});
	}

	return alerts;
}
