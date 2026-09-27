// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sender-blocklist audit log + bulk sender move. Pure `_xImpl(sql, ...)`
 * functions, testable on node:sqlite (same pattern as sidecar-state.ts).
 */

import type { SqlLike } from "./catchall-intel";
import { normalizeSenderAddress, ruleMatches } from "../security/blocklist";

export const BLOCKED_LOG_MAX_ROWS = 500;
export const BLOCKED_LOG_MAX_AGE_MS = 30 * 86_400_000;

export interface BlockedLogInput {
	ts: string;
	rule_id: string;
	tier: string;
	action: "drop" | "reject";
	sender: string;
	subject: string;
	message_id: string | null;
}

export function _appendBlockedLogImpl(sql: SqlLike, row: BlockedLogInput, nowMs = Date.now()): void {
	sql.exec(
		`INSERT OR IGNORE INTO blocked_log (ts, rule_id, tier, action, sender, subject, message_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
		row.ts, row.rule_id, row.tier, row.action, row.sender, row.subject.slice(0, 120), row.message_id,
	);
	sql.exec(`DELETE FROM blocked_log WHERE ts < ?`, new Date(nowMs - BLOCKED_LOG_MAX_AGE_MS).toISOString());
	sql.exec(
		`DELETE FROM blocked_log WHERE id NOT IN (SELECT id FROM blocked_log ORDER BY ts DESC, id DESC LIMIT ?)`,
		BLOCKED_LOG_MAX_ROWS,
	);
}

export function _listBlockedLogImpl(sql: SqlLike, limit = 50): Array<BlockedLogInput & { id: number }> {
	const n = Math.min(Math.max(Math.trunc(limit) || 50, 1), BLOCKED_LOG_MAX_ROWS);
	return [
		...sql.exec<BlockedLogInput & { id: number }>(
			`SELECT id, ts, rule_id, tier, action, sender, subject, message_id
             FROM blocked_log ORDER BY ts DESC, id DESC LIMIT ?`,
			n,
		),
	];
}

export function _moveEmailsFromSenderImpl(
	sql: SqlLike,
	match: string,
	fromFolders: readonly string[],
	toFolder: string,
): number {
	if (fromFolders.length === 0) return 0;
	const placeholders = fromFolders.map(() => "?").join(", ");
	const rows = [
		...sql.exec<{ id: string; sender: string | null }>(
			`SELECT id, sender FROM emails WHERE folder_id IN (${placeholders})`,
			...fromFolders,
		),
	];
	let moved = 0;
	for (const r of rows) {
		const sender = normalizeSenderAddress(r.sender);
		if (!sender || !ruleMatches(match, sender)) continue;
		sql.exec(`UPDATE emails SET folder_id = ? WHERE id = ?`, toFolder, r.id);
		moved++;
	}
	return moved;
}
