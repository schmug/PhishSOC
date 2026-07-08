// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sidecar poll-state, audit, events, dedupe, and retention-reap logic
 * (issue #31). Pure `_xImpl(sql, ...)` functions so the business logic is
 * testable against node:sqlite without a Workers runtime — same pattern as
 * `catchall-intel.ts`. `MailboxDO` exposes thin async delegates.
 *
 * `sidecar_events` (issue #594) is a dedicated append-only log for
 * operational events — today only `kind: "history-gap"` (the Gmail history
 * cursor aged out and the poller re-anchored, so a window of mail was never
 * scored). It is deliberately NOT folded into `sidecar_audit`: that table's
 * contract is one row per verdict decision (gmail_message_id/action/mode
 * are NOT NULL and meaningful), and a gap row with a blank message id would
 * silently corrupt the verdict-mix counts that justify observe→active
 * promotion. Events carry the cursor jump (`old_cursor` → `new_cursor`) so
 * an operator can bound the unscored window.
 */

import type { SqlLike } from "./catchall-intel";

export interface SidecarStateRow {
	history_cursor: string | null;
	access_token: string | null;
	token_expires_at: number | null;
	label_ids: string | null;
	last_poll_at: number | null;
	last_error: string | null;
	consecutive_failures: number;
}

const STATE_COLUMNS = [
	"history_cursor", "access_token", "token_expires_at",
	"label_ids", "last_poll_at", "last_error", "consecutive_failures",
] as const;

export function _getSidecarStateImpl(sql: SqlLike): SidecarStateRow | null {
	const rows = [...sql.exec(`SELECT ${STATE_COLUMNS.join(", ")} FROM sidecar_state WHERE id = 1`)];
	if (rows.length === 0) return null;
	return rows[0] as unknown as SidecarStateRow;
}

/** Upsert the singleton row, patching only the provided keys. */
export function _putSidecarStateImpl(sql: SqlLike, patch: Partial<SidecarStateRow>): void {
	const keys = STATE_COLUMNS.filter((k) => k in patch);
	if (keys.length === 0) return;
	sql.exec(`INSERT OR IGNORE INTO sidecar_state (id) VALUES (1)`);
	const sets = keys.map((k) => `${k} = ?`).join(", ");
	const values = keys.map((k) => patch[k] as unknown);
	sql.exec(`UPDATE sidecar_state SET ${sets} WHERE id = 1`, ...values);
}

export function _appendSidecarAuditImpl(
	sql: SqlLike,
	row: { ts: string; gmail_message_id: string; email_id: string; action: string; score: number | null; labels_applied: string; mode: string },
): void {
	sql.exec(
		`INSERT INTO sidecar_audit (ts, gmail_message_id, email_id, action, score, labels_applied, mode)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
		row.ts, row.gmail_message_id, row.email_id, row.action, row.score, row.labels_applied, row.mode,
	);
}

export interface SidecarEventRow {
	ts: string;
	kind: string;
	old_cursor: string | null;
	new_cursor: string | null;
	detail: string | null;
}

const EVENT_COLUMNS = "ts, kind, old_cursor, new_cursor, detail";

/** Append one durable operational event (#594). Append-only: no update or
 * delete path exists, so a recorded gap can never be erased by later polls. */
export function _appendSidecarEventImpl(sql: SqlLike, row: SidecarEventRow): void {
	sql.exec(
		`INSERT INTO sidecar_events (${EVENT_COLUMNS}) VALUES (?, ?, ?, ?, ?)`,
		row.ts, row.kind, row.old_cursor, row.new_cursor, row.detail,
	);
}

/** List events newest-first (per-mailbox by DO scope), capped for the API. */
export function _listSidecarEventsImpl(sql: SqlLike, limit = 50): SidecarEventRow[] {
	return [...sql.exec(
		`SELECT ${EVENT_COLUMNS} FROM sidecar_events ORDER BY id DESC LIMIT ?`,
		limit,
	)] as unknown as SidecarEventRow[];
}

/** Most recent history-gap event, or null — drives `sidecar_health.last_gap`. */
export function _latestSidecarGapImpl(sql: SqlLike): SidecarEventRow | null {
	const rows = [...sql.exec(
		`SELECT ${EVENT_COLUMNS} FROM sidecar_events WHERE kind = 'history-gap' ORDER BY id DESC LIMIT 1`,
	)];
	return rows.length > 0 ? (rows[0] as unknown as SidecarEventRow) : null;
}

export function _findEmailIdByMessageIdImpl(sql: SqlLike, messageId: string): string | null {
	const rows = [...sql.exec(`SELECT id FROM emails WHERE message_id = ? LIMIT 1`, messageId)];
	return rows.length > 0 ? (rows[0] as { id: string }).id : null;
}

export function _listReapableEmailsImpl(
	sql: SqlLike,
	cutoffIso: string,
): Array<{ id: string; attachments: Array<{ id: string; filename: string }> }> {
	const emails = [...sql.exec(
		`SELECT id FROM emails WHERE body_reaped_at IS NULL AND date < ? LIMIT 200`,
		cutoffIso,
	)] as Array<{ id: string }>;
	return emails.map((e) => ({
		id: e.id,
		attachments: [...sql.exec(
			`SELECT id, filename FROM attachments WHERE email_id = ?`, e.id,
		)] as Array<{ id: string; filename: string }>,
	}));
}

export function _markBodiesReapedImpl(sql: SqlLike, ids: string[], reapedAtIso: string): number {
	if (ids.length === 0) return 0;
	let n = 0;
	for (const id of ids) {
		sql.exec(`UPDATE emails SET body = '', body_reaped_at = ? WHERE id = ? AND body_reaped_at IS NULL`, reapedAtIso, id);
		sql.exec(`DELETE FROM attachments WHERE email_id = ?`, id);
		n += 1;
	}
	return n;
}
