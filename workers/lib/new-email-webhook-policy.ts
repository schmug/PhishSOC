// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tiered resolution for the ops-visibility "new mail" webhook (#563 follow-up).
 *
 * Before this, `NEW_EMAIL_WEBHOOK_URL` was a single global secret: pointing a
 * second chat space at a subset of mail meant clobbering the first. Tiers let
 * an org-wide SOC channel, a per-domain channel, and a per-mailbox bot each
 * own their own scope.
 *
 * Override semantics — most specific tier wins, whole-object replace — the
 * same contract every other block resolves under in `resolveMailboxSettings`.
 * Deliberately NOT a union: a mailbox that sets its own webhook stops
 * appearing in the wider channel, which is routing rather than duplication.
 *
 * The tier stores the NAME of a Worker Secret, never the URL — see
 * `NEW_EMAIL_WEBHOOK_SECRET_PREFIX` in `shared/mailbox-settings.ts` for why.
 * This module does not read the secret; `dispatchNewEmailNotification`
 * re-checks the prefix and resolves the value at the use site, matching how
 * `SmtpRelayProvider` handles `relay.credentialsSecret`.
 */

import type { NewEmailWebhookSettings } from "../../shared/mailbox-settings";

export { NEW_EMAIL_WEBHOOK_SECRET_PREFIX } from "../../shared/mailbox-settings";

export interface ResolvedNewEmailWebhook {
	/**
	 * True when some tier set a `newEmailWebhook` block. Suppresses the legacy
	 * global `NEW_EMAIL_WEBHOOK_URL` fallback even when `secretName` is null —
	 * an operator who configured this scope and then muted or half-configured
	 * it must not have their mail quietly routed to the global channel instead.
	 */
	configured: boolean;
	/** Worker Secret name holding the URL, or null when muted or incomplete. */
	secretName: string | null;
}

/** The tier blocks `resolveMailboxSettings` already returns. */
export interface NewEmailWebhookTiers {
	raw?: { newEmailWebhook?: NewEmailWebhookSettings } | undefined;
	domain?: { newEmailWebhook?: NewEmailWebhookSettings } | undefined;
	org?: { newEmailWebhook?: NewEmailWebhookSettings } | undefined;
}

/**
 * Pick the winning tier's webhook secret name.
 *
 * `enabled` must be explicitly true. An absent `enabled` is off, matching
 * `resolveRelayPolicy` — an outbound flow of mail metadata defaults to off,
 * so a half-written block never starts shipping off-platform.
 */
export function resolveNewEmailWebhook(tiers: NewEmailWebhookTiers): ResolvedNewEmailWebhook {
	const block =
		tiers.raw?.newEmailWebhook ?? tiers.domain?.newEmailWebhook ?? tiers.org?.newEmailWebhook;
	if (!block) return { configured: false, secretName: null };
	if (block.enabled !== true) return { configured: true, secretName: null };
	return { configured: true, secretName: block.urlSecret ?? null };
}
