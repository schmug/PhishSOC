// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sidecar-config resolution (issue #31). Validates the raw `sidecar` block
 * off a mailbox-settings blob and fills defaults, mirroring
 * `validateHubConfig` in `workers/lib/hub-config.ts`: invalid or absent
 * config resolves to null (feature off) rather than throwing, so a
 * malformed blob can never crash the cron loop or the receive path.
 */

import { SidecarSettings } from "../../shared/mailbox-settings";

export interface SidecarConfig {
	provider: "workspace";
	credentials_secret_name: string;
	mode: "observe" | "active";
	quarantine_behavior: "label-only" | "label-and-archive";
	/** Days to keep message bodies before the reap job strips them. 0 = keep forever. */
	retention_days: number;
}

export const SIDECAR_DEFAULT_RETENTION_DAYS = 7;

/**
 * Resolve the sidecar config from a raw mailbox-settings object (the
 * unresolved per-mailbox tier — `resolveMailboxSettings(...).raw` or a
 * freshly parsed blob). Returns null when absent or invalid.
 */
export function sidecarConfigOf(raw: unknown): SidecarConfig | null {
	if (!raw || typeof raw !== "object") return null;
	const block = (raw as { sidecar?: unknown }).sidecar;
	if (!block) return null;
	const parsed = SidecarSettings.safeParse(block);
	if (!parsed.success) return null;
	return {
		provider: parsed.data.provider,
		credentials_secret_name: parsed.data.credentials_secret_name,
		mode: parsed.data.mode ?? "observe",
		quarantine_behavior: parsed.data.quarantine_behavior ?? "label-only",
		retention_days: parsed.data.retention_days ?? SIDECAR_DEFAULT_RETENTION_DAYS,
	};
}

/** Poll-health fields the DO's `getSidecarState()` RPC returns — only the
 * subset `sidecarHealthOf` needs. `label_error` (#590) is optional so
 * callers holding a pre-migration-31 row shape still typecheck; absent
 * reads as null (no persisted label failure). */
export interface SidecarHealthState {
	consecutive_failures: number;
	last_poll_at: number | null;
	last_error: string | null;
	label_error?: string | null;
}

/** The durable history-gap surface (#594): when the Gmail history cursor
 * expired and where it re-anchored, bounding the window of unscored mail.
 * Sourced from the DO's append-only `sidecar_events` log, so it survives
 * the clean polls that reset `last_error` to null. */
export interface SidecarGapEvent {
	ts: string;
	old_cursor: string | null;
	new_cursor: string | null;
}

export interface SidecarHealth {
	healthy: boolean;
	last_poll_at: number | null;
	last_error: string | null;
	/** Durable label-failure signal (#590): the most recent label-write error,
	 * persisted in `sidecar_state.label_error`. Unlike `last_error` it survives
	 * label-clean polls and clears only when a label write succeeds. */
	label_error: string | null;
	last_gap: SidecarGapEvent | null;
}

/** Staleness threshold: a poll cursor older than this counts as unhealthy
 * even with zero consecutive failures (stuck cron, revoked grant, etc). */
export const SIDECAR_HEALTH_STALE_MS = 15 * 60 * 1000;

/**
 * Compute the poll-health surfaced to operators (mailbox list badge + the
 * single-mailbox GET). `healthy` = fewer than 3 consecutive failures AND
 * either never polled yet, or the last poll is within the staleness
 * window. `state` is null when the DO has no sidecar_state row yet (before
 * the first poll) — that still resolves to healthy (never-polled counts
 * as healthy, not stale).
 *
 * `lastGap` (#594) is the most recent durable history-gap event, or null.
 * It is surfaced verbatim but deliberately does NOT flip `healthy`: a gap
 * is not a failure (the poller recovered by re-anchoring, and there is no
 * acknowledge flow that could ever clear an unhealthy-forever flag). The
 * field itself is the persistent operator notice.
 *
 * `label_error` (#590) DOES flip `healthy` — the asymmetry with `last_gap`
 * is deliberate: a persisted label failure is a LIVE misconfiguration (e.g.
 * a gmail.readonly DWD grant in active mode) an operator must fix, and it
 * self-clears the moment a label write succeeds, so it can never become an
 * unclearable unhealthy-forever flag. It is decoupled from the transient
 * `consecutive_failures` counter precisely so a label-clean poll cannot
 * flap health back to green while labels keep failing.
 */
export function sidecarHealthOf(
	state: SidecarHealthState | null,
	lastGap: SidecarGapEvent | null = null,
): SidecarHealth {
	const stale = state?.last_poll_at != null && Date.now() - state.last_poll_at > SIDECAR_HEALTH_STALE_MS;
	const labelError = state?.label_error ?? null;
	return {
		healthy: (state?.consecutive_failures ?? 0) < 3 && !stale && labelError === null,
		last_poll_at: state?.last_poll_at ?? null,
		last_error: state?.last_error ?? null,
		label_error: labelError,
		// Re-pick the fields so extra DO-row columns (kind, detail) never leak
		// into the API payload shape.
		last_gap: lastGap
			? { ts: lastGap.ts, old_cursor: lastGap.old_cursor, new_cursor: lastGap.new_cursor }
			: null,
	};
}
