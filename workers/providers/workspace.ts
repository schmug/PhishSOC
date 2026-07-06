// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Google Workspace API-sidecar provider (issue #31).
 *
 * Inbound is pull-based: `pollSidecarMailboxes` (minutely cron) walks every
 * sidecar-enabled mailbox, fetches new messages via the Gmail history API,
 * and hands them to the shared pipeline (`receiveEmail`). The POLLER — not
 * the pipeline — applies verdict labels (active mode only), writes audit
 * rows, and auto-creates Cases for flagged mail. See the design spec:
 * docs/superpowers/specs/2026-07-06-sidecar-workspace-design.md.
 *
 * Per #30's contract this file plus gmail-client.ts is the whole provider:
 * no edits to workers/security/, workers/intel/, or workers/agent/.
 */

import PostalMime from "postal-mime";
import type { Env } from "../types";
import type { MailProvider, MailboxInbound, NormalizedOutbound } from "./types";
import {
	ensureLabels,
	getProfile,
	getRawMessage,
	listNewMessageIds,
	modifyMessage,
	mintAccessToken,
	parseServiceAccountJson,
} from "./gmail-client";
import { sidecarConfigOf, type SidecarConfig } from "../lib/sidecar-config";
import { getMailboxSettings } from "../lib/mailbox-settings";
import { receiveEmail } from "../index";

export const SIDECAR_LABEL_NAMES = [
	"PhishPilot/Quarantine",
	"PhishPilot/Suspicious",
	"PhishPilot/Allow",
] as const;

/**
 * Verdict action → Gmail label. Unknown actions map to Allow: labeling is a
 * UX affordance, and a future action value must degrade to "visible but not
 * quarantined" rather than throw inside the poll loop.
 */
export function verdictLabelName(action: string): string {
	if (action === "block" || action === "quarantine") return "PhishPilot/Quarantine";
	if (action === "tag") return "PhishPilot/Suspicious";
	return "PhishPilot/Allow";
}

/**
 * Write the verdict label to the source message. Quarantine-class verdicts
 * optionally archive (remove INBOX) per the mailbox's quarantine_behavior.
 * Returns the label names applied, for the audit row.
 */
export async function applyVerdictLabels(
	token: string,
	gmailMessageId: string,
	action: string,
	quarantineBehavior: "label-only" | "label-and-archive",
	labelIds: Record<string, string>,
): Promise<string[]> {
	const name = verdictLabelName(action);
	const isQuarantine = name === "PhishPilot/Quarantine";
	const removeLabelIds = isQuarantine && quarantineBehavior === "label-and-archive" ? ["INBOX"] : [];
	await modifyMessage(token, gmailMessageId, [labelIds[name]], removeLabelIds);
	return [name];
}

export class WorkspaceProvider implements MailProvider {
	readonly id = "workspace-api";

	async send(_env: Env, _msg: NormalizedOutbound): Promise<{ messageId: string }> {
		throw new Error("workspace-api provider is read-only sidecar; outbound send is unsupported (see issue #32)");
	}

	/**
	 * MailProvider.applyVerdict for callers that hold a MailboxInbound with
	 * providerMessageId. The poll loop calls applyVerdictLabels directly with
	 * its cached token/label ids; this interface method exists so future
	 * pipeline hooks can stay provider-agnostic.
	 */
	async applyVerdict(env: Env, msg: MailboxInbound, verdict: unknown): Promise<void> {
		if (!msg.providerMessageId) return;
		const v = verdict as { action?: string } | null;
		if (!v?.action) return;
		const creds = await sidecarCredentials(env, msg.mailboxId);
		if (!creds) return;
		const labelIds = await ensureLabels(creds.token, [...SIDECAR_LABEL_NAMES], creds.cachedLabelIds);
		await applyVerdictLabels(creds.token, msg.providerMessageId, v.action, creds.cfg.quarantine_behavior, labelIds);
	}
}

/**
 * Resolve config + a live access token for a sidecar mailbox, or null when
 * the mailbox isn't sidecar-configured / the secret is unset or malformed.
 */
export async function sidecarCredentials(
	env: Env,
	mailboxId: string,
): Promise<{ cfg: SidecarConfig; token: string; expiresAt: number; cachedLabelIds: Record<string, string> | null } | null> {
	const raw = await getMailboxSettings(env, mailboxId);
	const cfg = sidecarConfigOf(raw);
	if (!cfg) return null;
	const secret = (env as unknown as Record<string, unknown>)[cfg.credentials_secret_name];
	const sa = parseServiceAccountJson(secret);
	if (!sa) return null;
	const { token, expiresAt } = await mintAccessToken(sa, mailboxId);
	return { cfg, token, expiresAt, cachedLabelIds: null };
}

// -- Per-mailbox poll step (Task 7, issue #31) --------------------------

export const SIDECAR_BACKOFF_THRESHOLD = 5;
export const SIDECAR_BACKOFF_INTERVAL_MS = 15 * 60 * 1000;
export const MAX_MESSAGES_PER_POLL = 25;
const TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000;

export interface PollResult { processed: number; deduped: number; error: string | null }

interface SidecarStub {
	getSidecarState(): Promise<{
		history_cursor: string | null; access_token: string | null; token_expires_at: number | null;
		label_ids: string | null; last_poll_at: number | null; last_error: string | null; consecutive_failures: number;
	} | null>;
	putSidecarState(patch: Record<string, unknown>): Promise<void>;
	appendSidecarAudit(row: Record<string, unknown>): Promise<void>;
	findEmailIdByMessageId(messageId: string): Promise<string | null>;
	createCase(input: Record<string, unknown>): Promise<{ id: string }>;
}

/** RFC Message-ID: strip angle brackets, matching receiveEmail's own extraction. */
const extractMsgId = (s: string) => { const m = s.match(/<([^>]+)>/); return m ? m[1] : s.trim().split(/\s+/)[0]; };

/**
 * Poll one sidecar-enabled mailbox for new Gmail messages and feed them
 * through the shared receive pipeline. See the 10-rule algorithm in
 * docs/superpowers/sdd/task-7-brief.md: backoff gate, token reuse/mint,
 * first-run cursor anchor (no backfill), history-gap re-anchor, batch cap
 * (no cursor advance when capped), per-message dedupe on RFC Message-ID,
 * active-mode labeling, and both-mode audit/case writes.
 *
 * Never throws: all failures are caught, recorded in `sidecar_state`
 * (cursor frozen, consecutive_failures incremented), and returned as
 * `{ error }` so the cron loop can continue to the next mailbox.
 */
export async function pollWorkspaceMailbox(
	env: Env,
	ctx: ExecutionContext,
	mailboxId: string,
	cfg: SidecarConfig,
): Promise<PollResult> {
	const stub = env.MAILBOX.get(env.MAILBOX.idFromName(mailboxId)) as unknown as SidecarStub;
	const state = (await stub.getSidecarState()) ?? {
		history_cursor: null, access_token: null, token_expires_at: null,
		label_ids: null, last_poll_at: null, last_error: null, consecutive_failures: 0,
	};

	// Backoff gate (rule 2).
	if (
		state.consecutive_failures >= SIDECAR_BACKOFF_THRESHOLD &&
		state.last_poll_at !== null &&
		Date.now() - state.last_poll_at < SIDECAR_BACKOFF_INTERVAL_MS
	) {
		return { processed: 0, deduped: 0, error: null };
	}

	let processed = 0;
	let deduped = 0;
	try {
		// Token (rule 3).
		let token = state.access_token;
		let tokenExpiresAt = state.token_expires_at;
		if (!token || !tokenExpiresAt || tokenExpiresAt - Date.now() < TOKEN_REFRESH_MARGIN_MS) {
			const secret = (env as unknown as Record<string, unknown>)[cfg.credentials_secret_name];
			const sa = parseServiceAccountJson(secret);
			if (!sa) throw new Error(`secret ${cfg.credentials_secret_name} is unset or not service-account JSON (auth)`);
			const minted = await mintAccessToken(sa, mailboxId);
			token = minted.token;
			tokenExpiresAt = minted.expiresAt;
		}

		let labelIds: Record<string, string> | null = state.label_ids
			? (JSON.parse(state.label_ids) as Record<string, string>)
			: null;

		const patch: Record<string, unknown> = {
			access_token: token, token_expires_at: tokenExpiresAt,
			last_poll_at: Date.now(), last_error: null, consecutive_failures: 0,
		};

		if (!state.history_cursor) {
			// First run (rule 4): anchor the cursor to "now"; no backfill.
			const profile = await getProfile(token);
			patch.history_cursor = profile.historyId;
			await stub.putSidecarState(patch);
			return { processed: 0, deduped: 0, error: null };
		}

		const history = await listNewMessageIds(token, state.history_cursor);
		if (!history.ok) {
			// Rule 5: cursor older than Gmail's history retention. Re-anchor and
			// record the gap — informational, NOT a failure (failures gate backoff).
			const profile = await getProfile(token);
			patch.history_cursor = profile.historyId;
			patch.last_error = "history gap: cursor expired; monitoring reinitialized from current historyId";
			await stub.putSidecarState(patch);
			return { processed: 0, deduped: 0, error: null };
		}

		const capped = history.messageIds.length > MAX_MESSAGES_PER_POLL;
		const messageIds = history.messageIds;

		for (const gmailId of messageIds.slice(0, MAX_MESSAGES_PER_POLL)) {
			const bytes = await getRawMessage(token, gmailId);
			const parsed = await new PostalMime().parse(bytes);
			const rfcId = parsed.messageId ? extractMsgId(parsed.messageId) : null;
			if (rfcId && (await stub.findEmailIdByMessageId(rfcId))) { deduped += 1; continue; }
			const normalized: MailboxInbound = {
				kind: "mailbox",
				rawEmail: bytes.buffer as ArrayBuffer,
				parsedEmail: parsed,
				mailboxId,
				providerMessageId: gmailId,
			};
			const result = await receiveEmail(normalized, env, ctx);
			processed += 1;
			if (!result?.verdict) continue;
			const verdict = result.verdict;
			let applied: string[] = [];
			if (cfg.mode === "active") {
				labelIds = await ensureLabels(token, [...SIDECAR_LABEL_NAMES], labelIds);
				applied = await applyVerdictLabels(token, gmailId, verdict.action, cfg.quarantine_behavior, labelIds);
			}
			await stub.appendSidecarAudit({
				ts: new Date().toISOString(), gmail_message_id: gmailId, email_id: result.messageId,
				action: verdict.action, score: verdict.score ?? null,
				labels_applied: JSON.stringify(applied), mode: cfg.mode,
			});
			if (verdict.action === "quarantine" || verdict.action === "block") {
				await stub.createCase({
					title: `Sidecar flagged: ${parsed.subject || "(no subject)"}`,
					notes: `Auto-created by the Workspace sidecar poller. Gmail message ${gmailId}.`,
					emailId: result.messageId,
					score: verdict.score ?? null,
					confidence: (verdict as { confidence?: number | null }).confidence ?? null,
				});
			}
		}

		// Rule 6: advance the cursor only when the batch was complete.
		if (!capped) patch.history_cursor = history.historyId;
		if (labelIds) patch.label_ids = JSON.stringify(labelIds);
		await stub.putSidecarState(patch);
		return { processed, deduped, error: null };
	} catch (e) {
		const message = String((e as Error).message).slice(0, 500);
		await stub.putSidecarState({
			last_poll_at: Date.now(), last_error: message,
			consecutive_failures: state.consecutive_failures + 1,
		}).catch((pe) => console.error("sidecar state write failed:", (pe as Error).message));
		return { processed, deduped, error: message };
	}
}
