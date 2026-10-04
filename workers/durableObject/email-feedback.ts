// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Per-email user feedback labels (issue #751). Pure `_xImpl(sql, ...)`
 * functions, testable on node:sqlite (same pattern as blocked-log.ts).
 *
 * The label is a user claim that is stored and exported. Nothing here
 * touches the verdict, score, sender reputation or any blocklist.
 */

import type { SqlLike } from "./catchall-intel";

export interface EmailFeedback {
	email_id: string;
	label: "not_phish";
	created_at: string;
	verdict_action: string | null;
	verdict_score: number | null;
}

export function _getEmailFeedbackImpl(sql: SqlLike, emailId: string): EmailFeedback | null {
	return (
		[
			...sql.exec<EmailFeedback>(
				`SELECT email_id, label, created_at, verdict_action, verdict_score
                 FROM email_feedback WHERE email_id = ?`,
				emailId,
			),
		][0] ?? null
	);
}

/**
 * Record a `not_phish` label. Returns null when the email does not exist.
 * Idempotent: a repeat call keeps the first label (and its timestamp and
 * verdict snapshot) and returns it unchanged.
 */
export function _markNotPhishImpl(sql: SqlLike, emailId: string, nowIso: string): EmailFeedback | null {
	const email = [
		...sql.exec<{ security_verdict: string | null; security_score: number | null }>(
			`SELECT security_verdict, security_score FROM emails WHERE id = ?`,
			emailId,
		),
	][0];
	if (!email) return null;

	let action: string | null = null;
	if (typeof email.security_verdict === "string") {
		try {
			const parsed = JSON.parse(email.security_verdict) as { action?: unknown };
			if (typeof parsed?.action === "string") action = parsed.action;
		} catch {
			// malformed verdict JSON — action stays null
		}
	}
	const score = typeof email.security_score === "number" ? email.security_score : null;

	sql.exec(
		`INSERT OR IGNORE INTO email_feedback (email_id, label, created_at, verdict_action, verdict_score)
         VALUES (?, 'not_phish', ?, ?, ?)`,
		emailId, nowIso, action, score,
	);
	return _getEmailFeedbackImpl(sql, emailId);
}
