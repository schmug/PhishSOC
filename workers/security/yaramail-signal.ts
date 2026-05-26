// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Async yaramail sidecar enrichment signal (issue #256).
 *
 * The sidecar is an operator-supplied Python container that receives
 * attachment references from PhishSOC, runs yaramail-powered scanning
 * (PDF extraction, password-protected ZIPs, nested archives, .eml recursion),
 * and POSTs YARA match results back to a callback route.
 *
 * This module handles the outbound side only:
 *   - `computeYaraScoreDelta` normalises raw YARA match lists to a bounded
 *     score contribution (capped at YARA_SCORE_CAP = 30).
 *   - `fireYaraScan` fires the fire-and-forget enrichment request via
 *     ctx.waitUntil when the mailbox has the scanner enabled.
 *
 * All three wiring points are in place: `fireYaraScan` is called from
 * `receiveEmail` at `workers/index.ts:1464`; the callback route is mounted at
 * `workers/index.ts:140` and handled by `workers/routes/yaramail-callback.ts`;
 * the DO methods `MailboxDO.insertYaraScanResult` (line 1928) and
 * `MailboxDO.applyYaraSignal` (line 1955) live in
 * `workers/durableObject/index.ts`.
 */

import { resolveMailboxSettings } from "../lib/mailbox-settings";

/** Maximum score contribution from YARA signals — mirrors the deep-scan cap. */
export const YARA_SCORE_CAP = 30;

/**
 * Default YARA rule name → score contribution table. Unknown rule names fall
 * back to +5 so a new rule in the operator's YARA ruleset contributes a small
 * signal rather than nothing. Operators can extend this via the mapping table
 * documented in docs/yaramail-sidecar.md (follow-up).
 */
export const DEFAULT_YARA_RULE_SCORES: Record<string, number> = {
	pdf_phishing: 20,
	macro_dropper: 25,
	encrypted_zip: 15,
	nested_archive: 10,
	eml_attachment: 5,
};

/** A single YARA rule match as returned by the sidecar. */
export interface YaraMatchResult {
	/** YARA rule name, e.g. "pdf_phishing". */
	rule_name: string;
	/** Optional signal category for display purposes. */
	category?: string;
	/** Explicit score override — takes precedence over DEFAULT_YARA_RULE_SCORES. */
	score?: number;
}

/** Payload sent to the sidecar endpoint. */
export interface YaraScanPayload {
	emailId: string;
	/** R2 object key for the attachment to scan. */
	r2Key: string;
	mailboxId: string;
	/**
	 * Presigned download URL for the attachment.
	 * Requires R2 S3-compatible API presigned URL support; see
	 * docs/yaramail-sidecar.md for deployment guidance. Empty string when
	 * not yet configured — the sidecar MUST treat an empty presignedUrl as a
	 * signal to call back to PhishSOC's attachment download endpoint instead.
	 */
	presignedUrl: string;
}

/**
 * Map a list of YARA match results to a single bounded score delta.
 *
 * Each match contributes `match.score` (explicit) or the value from
 * DEFAULT_YARA_RULE_SCORES keyed on `rule_name`, or 5 for unknown rules.
 * The total is capped at YARA_SCORE_CAP so no combination of YARA matches
 * can dominate the verdict on its own.
 */
export function computeYaraScoreDelta(matches: YaraMatchResult[]): number {
	let total = 0;
	for (const m of matches) {
		total += m.score ?? DEFAULT_YARA_RULE_SCORES[m.rule_name] ?? 5;
	}
	return Math.min(YARA_SCORE_CAP, total);
}

type R2BucketEnv = { BUCKET: R2Bucket };
type CtxLike = { waitUntil: (p: Promise<unknown>) => void };

/**
 * Fire a fire-and-forget enrichment request to the configured yaramail
 * sidecar endpoint.
 *
 * Returns immediately after scheduling the request via ctx.waitUntil.
 * If the sidecar is disabled for this mailbox (or has no endpoint_url
 * configured), this is a no-op. Network failures and timeouts are caught
 * and logged so they never propagate to the email-receive path.
 *
 * @param env        Worker environment (needs BUCKET for settings resolution).
 * @param ctx        ExecutionContext — waitUntil keeps the request alive after
 *                   the outer handler returns.
 * @param mailboxId  Per-mailbox identifier (also the R2 settings key suffix).
 * @param emailId    Message ID of the email being scanned.
 * @param r2Key      R2 object key for the attachment to scan.
 * @param presignedUrl  Pre-generated download URL for the attachment (may be
 *                      empty — see YaraScanPayload.presignedUrl).
 */
export async function fireYaraScan(
	env: R2BucketEnv,
	ctx: CtxLike,
	mailboxId: string,
	emailId: string,
	r2Key: string,
	presignedUrl = "",
): Promise<void> {
	const resolved = await resolveMailboxSettings(env, mailboxId);
	const scanner = resolved.raw.yaramail_scanner;
	if (!scanner?.enabled || !scanner.endpoint_url) return;

	const endpointUrl = scanner.endpoint_url;
	const payload: YaraScanPayload = { emailId, r2Key, mailboxId, presignedUrl };

	ctx.waitUntil(
		fetch(endpointUrl, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(payload),
			signal: AbortSignal.timeout(30_000),
		}).catch((err: unknown) => {
			console.error("yaramail sidecar request failed:", (err as Error).message);
		}),
	);
}
