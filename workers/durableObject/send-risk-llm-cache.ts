// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Outbound LLM send-risk verdict cache (slice 3, migration 33). Pure
 * `_xImpl(sql, ...)` functions, testable against node:sqlite — same pattern
 * as `recipient-graph.ts`. `MailboxDO` exposes thin delegates.
 *
 * Only real classifier answers are stored (see `classifyOutbound`); timeouts,
 * errors and unparseable output are never cached, so a transient failure is
 * retried on the next preflight or send.
 */

import type { SqlLike } from "./catchall-intel";
import { OUTBOUND_LLM_LABELS, type OutboundLlmLabel } from "../security/send-risk";

export interface CachedOutboundVerdict {
	label: OutboundLlmLabel;
	confidence: number;
}

/** A verdict is reused for this long after it was computed. */
export const SEND_RISK_LLM_CACHE_TTL_MS = 15 * 60 * 1000;

const LABELS = new Set<string>(OUTBOUND_LLM_LABELS);

export function _getSendRiskLlmCacheImpl(
	sql: SqlLike,
	key: string,
	nowMs: number,
	ttlMs = SEND_RISK_LLM_CACHE_TTL_MS,
): CachedOutboundVerdict | null {
	const row = [
		...sql.exec<{ label: string; confidence: number }>(
			`SELECT label, confidence FROM send_risk_llm_cache WHERE key = ?1 AND created_at > ?2 LIMIT 1`,
			key,
			nowMs - ttlMs,
		),
	][0];
	if (!row || !LABELS.has(row.label)) return null;
	return { label: row.label as OutboundLlmLabel, confidence: Number(row.confidence) };
}

/** Store a verdict and prune expired rows, so the table holds at most one TTL window of sends. */
export function _putSendRiskLlmCacheImpl(
	sql: SqlLike,
	key: string,
	verdict: CachedOutboundVerdict,
	nowMs: number,
	ttlMs = SEND_RISK_LLM_CACHE_TTL_MS,
): void {
	if (!LABELS.has(verdict.label)) return;
	sql.exec(`DELETE FROM send_risk_llm_cache WHERE created_at <= ?1`, nowMs - ttlMs);
	sql.exec(
		`INSERT INTO send_risk_llm_cache (key, label, confidence, created_at) VALUES (?1, ?2, ?3, ?4)
		 ON CONFLICT(key) DO UPDATE SET label = excluded.label, confidence = excluded.confidence, created_at = excluded.created_at`,
		key,
		verdict.label,
		verdict.confidence,
		nowMs,
	);
}
