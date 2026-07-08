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
 *
 * Replay dedupe (issue #593): the poll loop is at-least-once (a mid-batch
 * failure freezes the cursor, so the next poll re-lists already-ingested
 * ids), and idempotency comes from a per-message dedupe probe. The primary
 * key is the RFC `Message-ID` header; for messages WITHOUT one — which
 * adversarial mail omits deliberately — the probe falls back to the
 * provider-native Gmail message id, persisted on the email row at ingest
 * (`emails.provider_message_id`, migration 29). That is mechanism (b) from
 * the issue: a column on the email row, NOT (a) an audit row per ingested
 * message, because `sidecar_audit`'s contract is one row per verdict
 * decision — a null-verdict message writes no audit row, so an audit-trail
 * lookup would still re-ingest unscored mail on every replay. Either way
 * the dedupe stays one DO call per message.
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
import { listMailboxes } from "../lib/email-helpers";
import { attachmentObjectKey } from "../lib/attachments";
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
		// Resolve config FIRST and bail before any credential/token/network work
		// unless the mailbox is in active mode. Only active mode writes labels
		// (spec invariant); observe mode must never touch the tenant's Gmail.
		const raw = await getMailboxSettings(env, msg.mailboxId);
		const cfg = sidecarConfigOf(raw);
		if (!cfg || cfg.mode !== "active") return;
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
/**
 * Poll lease TTL (#591): must comfortably exceed a worst-case tick (a full
 * batch is ~26 sequential Gmail round-trips) and expire on its own so a
 * crashed poller never wedges the mailbox.
 */
export const POLL_LEASE_TTL_MS = 5 * 60 * 1000;

export interface PollResult { processed: number; deduped: number; error: string | null }

interface SidecarStub {
	getSidecarState(): Promise<{
		history_cursor: string | null; access_token: string | null; token_expires_at: number | null;
		label_ids: string | null; last_poll_at: number | null; last_error: string | null; consecutive_failures: number;
		poll_lease_until: number | null; label_error: string | null; label_failure_count: number;
	} | null>;
	acquirePollLease(nowMs: number, ttlMs: number): Promise<boolean>;
	putSidecarState(patch: Record<string, unknown>): Promise<void>;
	appendSidecarAudit(row: Record<string, unknown>): Promise<void>;
	findSidecarAuditPendingLabels(gmailMessageId: string): Promise<{ id: number; action: string } | null>;
	updateSidecarAuditLabels(id: number, labelsApplied: string): Promise<void>;
	appendSidecarEvent(row: Record<string, unknown>): Promise<void>;
	findEmailIdByMessageId(messageId: string): Promise<string | null>;
	findEmailIdByProviderMessageId(providerMessageId: string): Promise<string | null>;
	createCase(input: Record<string, unknown>): Promise<{ id: string }>;
}

/** RFC Message-ID: strip angle brackets, matching receiveEmail's own extraction. */
const extractMsgId = (s: string) => { const m = s.match(/<([^>]+)>/); return m ? m[1] : s.trim().split(/\s+/)[0]; };

/**
 * Poll one sidecar-enabled mailbox for new Gmail messages and feed them
 * through the shared receive pipeline. Guarded by a per-mailbox poll lease
 * (#591) so overlapping cron ticks cannot double-process. See the 10-rule
 * algorithm in docs/superpowers/sdd/task-7-brief.md: backoff gate, token reuse/mint,
 * first-run cursor anchor (no backfill), history-gap re-anchor, batch cap
 * (no cursor advance when capped), per-message dedupe on RFC Message-ID
 * (falling back to the stored provider id when the header is absent, #593),
 * active-mode labeling, and both-mode audit/case writes. Label failures are
 * contained per message and recorded durably (#590: `label_error` /
 * `label_failure_count`, cleared only by a successful write); dedupe hits in
 * active mode retry a label the audit row shows never landed.
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
		poll_lease_until: null, label_error: null, label_failure_count: 0,
	};

	// Backoff gate (rule 2). Sits BEFORE the lease so a backed-off mailbox
	// costs a read, not a lease write, per minute.
	if (
		state.consecutive_failures >= SIDECAR_BACKOFF_THRESHOLD &&
		state.last_poll_at !== null &&
		Date.now() - state.last_poll_at < SIDECAR_BACKOFF_INTERVAL_MS
	) {
		return { processed: 0, deduped: 0, error: null };
	}

	// Poll lease (#591): a tick that runs past 60s overlaps the next cron
	// invocation — both would read the same cursor and could pass the
	// per-message dedupe probe before either stores. The check-and-set is
	// atomic inside the DO (one round-trip); a held lease means another
	// poller owns this mailbox right now, so skip without touching state.
	// The TTL-expiry steal in acquirePollLease covers a crashed holder.
	if (!(await stub.acquirePollLease(Date.now(), POLL_LEASE_TTL_MS))) {
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
			// Lease release (#591) rides the state patch every completion path
			// (first-run, history-gap, steady state) already writes — no extra
			// DO round-trip.
			poll_lease_until: null,
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
			// Durable record (#594) BEFORE the state write: `last_error` is
			// transient (the next clean poll nulls it), so the gap evidence —
			// including the cursor jump that bounds the unscored window — must
			// land in the append-only sidecar_events log. Ordering gives
			// at-least-once: if this append throws, the cursor stays frozen and
			// the next poll retries the whole re-anchor branch.
			await stub.appendSidecarEvent({
				ts: new Date().toISOString(),
				kind: "history-gap",
				old_cursor: state.history_cursor,
				new_cursor: profile.historyId,
				detail: "cursor expired past Gmail history retention; mail arriving in the gap was never scored",
			});
			patch.history_cursor = profile.historyId;
			patch.last_error = "history gap: cursor expired; monitoring reinitialized from current historyId";
			await stub.putSidecarState(patch);
			return { processed: 0, deduped: 0, error: null };
		}

		// Cap on PROCESSED messages, not raw ids: deduped messages cost nothing
		// so a burst of >MAX already-stored ids can never wedge the mailbox
		// (each poll dedupes them for free and makes forward progress on the
		// tail). `hitCap` means we stopped early with work still pending.
		let hitCap = false;
		// Label writes are contained per-message (Fix 3): a 403 (e.g. a
		// gmail.readonly DWD grant in active mode) must NOT abort the batch and
		// lose the audit row + case. We tally failures and surface them in
		// health at the end instead of throwing. Successes are tallied too
		// (#590): only a successful write may clear the durable label-failure
		// signal.
		let labelFailures = 0;
		let labelSuccesses = 0;
		let firstLabelError: string | null = null;
		for (const gmailId of history.messageIds) {
			if (processed >= MAX_MESSAGES_PER_POLL) { hitCap = true; break; }
			const bytes = await getRawMessage(token, gmailId);
			const parsed = await new PostalMime().parse(bytes);
			// Replay dedupe (rule 7 + #593): RFC Message-ID when present;
			// otherwise the provider-native Gmail id persisted at ingest (see
			// the module docstring). One DO call per message either way.
			const rfcId = parsed.messageId ? extractMsgId(parsed.messageId) : null;
			const existingId = rfcId
				? await stub.findEmailIdByMessageId(rfcId)
				: await stub.findEmailIdByProviderMessageId(gmailId);
			if (existingId) {
				deduped += 1;
				// Label backfill (#590): a replayed message whose ACTIVE-mode
				// audit row shows the label write never landed (labels_applied
				// "[]") gets the label retried now. Ingest is NOT re-run — the
				// at-least-once invariant stands (no duplicate email row, audit
				// row, or Case); only the label write and an in-place audit-row
				// update happen. Observe mode never probes: it writes nothing by
				// design, and skipping keeps dedupe hits at one DO call there.
				// (Active-mode dedupe hits — the rare replay path — cost one
				// extra DO probe; dedupe misses stay one call.)
				if (cfg.mode === "active") {
					const pending = await stub.findSidecarAuditPendingLabels(gmailId);
					if (pending) {
						try {
							labelIds = await ensureLabels(token, [...SIDECAR_LABEL_NAMES], labelIds);
							const applied = await applyVerdictLabels(token, gmailId, pending.action, cfg.quarantine_behavior, labelIds);
							await stub.updateSidecarAuditLabels(pending.id, JSON.stringify(applied));
							labelSuccesses += 1;
						} catch (e) {
							labelFailures += 1;
							if (!firstLabelError) firstLabelError = (e as Error).message;
						}
					}
				}
				continue;
			}
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
				try {
					labelIds = await ensureLabels(token, [...SIDECAR_LABEL_NAMES], labelIds);
					applied = await applyVerdictLabels(token, gmailId, verdict.action, cfg.quarantine_behavior, labelIds);
					labelSuccesses += 1;
				} catch (e) {
					// Contain the failure: the audit row + case still get written
					// below so the flagged mail is never lost, and the wrong-scope
					// grant surfaces in health at end-of-batch.
					labelFailures += 1;
					if (!firstLabelError) firstLabelError = (e as Error).message;
				}
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

		// Rule 6: advance the cursor ONLY when the listing was complete (not
		// page-cap truncated) AND we worked through all of it (not batch-capped).
		if (!hitCap && !history.truncated) patch.history_cursor = history.historyId;
		if (labelIds) patch.label_ids = JSON.stringify(labelIds);
		// Label failures don't freeze the cursor (ingest succeeded — the cursor
		// rules above stand), but they DO surface in health so a wrong-scope
		// grant isn't buried by the next dedupe-only poll resetting
		// consecutive_failures to 0.
		if (labelFailures > 0) {
			const labelError = `label write failed for ${labelFailures} message(s): ${firstLabelError}`.slice(0, 500);
			patch.last_error = labelError;
			patch.consecutive_failures = state.consecutive_failures + 1;
			// Durable signal (#590), decoupled from the transient counters
			// above: those reset on the very next label-clean poll, flapping
			// health back to green while the misconfiguration (e.g. a
			// gmail.readonly DWD grant in active mode) persists. label_error /
			// label_failure_count clear ONLY when a label write succeeds.
			patch.label_error = labelError;
			patch.label_failure_count = state.label_failure_count + labelFailures;
		} else if (labelSuccesses > 0) {
			// A successful write proves the grant works again — clear the
			// persisted signal so health recovers.
			patch.label_error = null;
			patch.label_failure_count = 0;
		}
		// A label-quiet poll (no writes attempted) leaves both keys out of the
		// patch entirely: putSidecarState's patch-only semantics keep a raised
		// signal raised — the point-(a) fix in #590.
		await stub.putSidecarState(patch);
		return { processed, deduped, error: null };
	} catch (e) {
		const message = String((e as Error).message).slice(0, 500);
		await stub.putSidecarState({
			last_poll_at: Date.now(), last_error: message,
			consecutive_failures: state.consecutive_failures + 1,
			// Failure path releases the lease too (#591): a failing poll must
			// not hold the mailbox for the whole TTL. If THIS write also fails,
			// the lease simply expires on its own.
			poll_lease_until: null,
		}).catch((pe) => console.error("sidecar state write failed:", (pe as Error).message));
		return { processed, deduped, error: message };
	}
}

// -- Cron fan-out + retention reap (Task 8, issue #31) ------------------

/**
 * Minutely cron entry: poll every sidecar-configured mailbox sequentially.
 * Sequential (not Promise.all) keeps the subrequest burst bounded; per-
 * mailbox failures are contained by pollWorkspaceMailbox and never abort
 * the loop.
 */
export async function pollSidecarMailboxes(
	env: Env, ctx: ExecutionContext,
): Promise<{ polled: number; processed: number; failures: number }> {
	const mailboxes = await listMailboxes(env.BUCKET);
	let polled = 0, processed = 0, failures = 0;
	for (const m of mailboxes) {
		const raw = await getMailboxSettings(env, m.id).catch(() => null);
		const cfg = sidecarConfigOf(raw);
		if (!cfg) continue;
		polled += 1;
		const r = await pollWorkspaceMailbox(env, ctx, m.id, cfg);
		processed += r.processed;
		if (r.error) failures += 1;
	}
	return { polled, processed, failures };
}

/**
 * Hourly cron entry: strip message bodies (and R2 attachments) from sidecar
 * mailboxes past their retention window. Verdicts, headers, audit rows, and
 * case links survive — see the design spec's Storage & retention section.
 */
export async function reapSidecarBodies(env: Env): Promise<{ mailboxes: number; reaped: number }> {
	const mailboxes = await listMailboxes(env.BUCKET);
	let touched = 0, reaped = 0;
	for (const m of mailboxes) {
		const raw = await getMailboxSettings(env, m.id).catch(() => null);
		const cfg = sidecarConfigOf(raw);
		if (!cfg || cfg.retention_days === 0) continue;
		touched += 1;
		const cutoffIso = new Date(Date.now() - cfg.retention_days * 86_400_000).toISOString();
		const stub = env.MAILBOX.get(env.MAILBOX.idFromName(m.id)) as unknown as {
			listReapableSidecarEmails(cutoff: string): Promise<Array<{ id: string; attachments: Array<{ id: string; filename: string }> }>>;
			markBodiesReaped(ids: string[], ts: string): Promise<number>;
		};
		const rows = await stub.listReapableSidecarEmails(cutoffIso);
		if (rows.length === 0) continue;
		// Delete R2 attachment objects BEFORE marking, so a partial failure
		// re-lists the email next hour instead of orphaning blobs.
		for (const row of rows) {
			for (const att of row.attachments) {
				await env.BUCKET.delete(attachmentObjectKey(row.id, att.id, att.filename));
			}
		}
		reaped += await stub.markBodiesReaped(rows.map((r) => r.id), new Date().toISOString());
	}
	return { mailboxes: touched, reaped };
}
