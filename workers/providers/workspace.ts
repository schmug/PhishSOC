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

import type { Env } from "../types";
import type { MailProvider, MailboxInbound, NormalizedOutbound } from "./types";
import { ensureLabels, modifyMessage } from "./gmail-client";
import { sidecarConfigOf, type SidecarConfig } from "../lib/sidecar-config";
import { getMailboxSettings } from "../lib/mailbox-settings";
import { mintAccessToken, parseServiceAccountJson } from "./gmail-client";

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
