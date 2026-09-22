// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { z } from "zod";
import {
	AutoDraftSettings,
	IntelSettings,
	NewEmailWebhookSettings,
	SecuritySettings,
} from "./mailbox-settings";

/**
 * Per-domain catch-all probe capture and harvest-alert settings (#423 epic).
 *
 * - `enabled` / `retention_days` / `sample_limit` govern what `CatchallIntelDO`
 *   stores (wired in #426).
 * - `harvest_alert_threshold` / `harvest_alert_window_minutes` govern when
 *   `computeHarvestAlerts` fires an alert (this issue, #429).
 * - `hub_report_threshold` governs when a high-score probe is submitted to the
 *   community hub via the corroboration API (#437); default in
 *   `workers/intel/defaults.ts`.
 * - `deep_scan_threshold` governs when a high-score probe is dispatched for an
 *   async RDAP + redirect deep-scan (#438); default in
 *   `workers/intel/defaults.ts`.
 *
 * All fields are optional so absent-key-inherits semantics are preserved.
 * Defaults live in `workers/intel/catchall-alert.ts` (alert fields),
 * `workers/intel/defaults.ts` (hub-report threshold), and in the wiring layer
 * of #426 (capture fields), not on this schema.
 */
export const CatchallIntelSettings = z
	.object({
		enabled: z.boolean().optional(),
		retention_days: z.number().int().positive().optional(),
		sample_limit: z.number().int().positive().optional(),
		harvest_alert_threshold: z.number().int().positive().optional(),
		harvest_alert_window_minutes: z.number().int().positive().optional(),
		hub_report_threshold: z.number().int().min(0).max(100).optional(),
		deep_scan_threshold: z.number().int().min(0).max(100).optional(),
	})
	.passthrough();

export type CatchallIntelSettings = z.infer<typeof CatchallIntelSettings>;

/**
 * Per-domain inline-gateway relay policy (issue #32).
 *
 * When `enabled` with a `target.host`, inbound mail for this domain is
 * relayed to the backend over SMTP submission after the security pipeline
 * runs; the verdict action maps through `actions` to decide relay/hold/drop.
 *
 * All fields optional so absent-key-inherits semantics are preserved.
 * Defaults (port 587, STARTTLS, the fail-closed action map) live in
 * `workers/lib/relay-policy.ts`, not on this schema.
 */
export const RelayActionBehavior = z.enum(["relay", "hold", "drop"]);
export type RelayActionBehavior = z.infer<typeof RelayActionBehavior>;

export const RelaySettings = z
	.object({
		enabled: z.boolean().optional(),
		target: z
			.object({
				host: z.string().min(1).optional(),
				port: z.number().int().min(1).max(65535).optional(),
				implicitTls: z.boolean().optional(),
			})
			.passthrough()
			.optional(),
		/** Name of the Worker Secret holding `{"user":"...","pass":"..."}` JSON. */
		credentialsSecret: z
			.string()
			.min(1)
			.startsWith("RELAY_CREDS_", {
				message: "Secret name must start with RELAY_CREDS_",
			})
			.optional(),
		actions: z
			.object({
				allow: RelayActionBehavior.optional(),
				tag: RelayActionBehavior.optional(),
				quarantine: RelayActionBehavior.optional(),
				block: RelayActionBehavior.optional(),
			})
			.passthrough()
			.optional(),
	})
	.passthrough();

export type RelaySettings = z.infer<typeof RelaySettings>;

/**
 * Per-domain settings stored at R2 key `domains/<domain>.json` (#142).
 *
 * Sits between mailbox and org in the inheritance hierarchy:
 * `mailbox > domain > org > system default`. An MSP managing 12 mailboxes
 * under `acme.com` can set the agent prompt or security thresholds once at
 * the domain level instead of editing 12 mailbox files.
 *
 * Mirrors `MailboxSettings` minus the strictly-per-mailbox identity fields
 * (`fromName`, `signature`, `forwarding`, `autoReply`). The three
 * security-critical model fields (`injectionScannerModel`,
 * `draftVerifierModel`, `classifierModel`) are deliberately NOT here — they
 * live only in `OrgSettings` (per audit Q7 from #106; per-tier overrides
 * for the prompt-injection scanner are too sharp without UI guardrails).
 *
 * Whole-object replace across tiers — same rule as `OrgSettings`. A
 * domain-level `security` block carries the entire object; the org's
 * `security` is NOT deep-merged in. The per-field carve-outs are
 * narrow and explicit: allowlist-array extend-merge (#149) and
 * `business_hours` per-field merge across `mailbox > domain > org`
 * (#150 / #164). Every other security sub-field stays whole-replace.
 *
 * R2 key derivation lives in `workers/lib/domain-settings.ts`
 * (`domainSettingsKey(domain)`) so a future re-keying — e.g. multi-tenant
 * `orgs/<orgId>/domains/<domain>.json` — is one helper change rather than
 * a cross-cutting grep.
 */
export const DomainSettings = z
	.object({
		agentSystemPrompt: z.string().optional(),
		autoDraft: AutoDraftSettings.optional(),
		agentModel: z.string().optional(),
		security: SecuritySettings.optional(),
		intel: IntelSettings.optional(),
		catchall_intel: CatchallIntelSettings.optional(),
		relay: RelaySettings.optional(),
		newEmailWebhook: NewEmailWebhookSettings.optional(),
	})
	.passthrough();

export type DomainSettings = z.infer<typeof DomainSettings>;

/**
 * Parse a raw value as `DomainSettings`. Returns the parsed value on
 * success, or `null` when validation fails. Callers (the GET endpoint, the
 * resolver) treat a missing/malformed `domains/<domain>.json` as "no
 * domain-level overrides" — empty `{}` rather than throwing.
 */
export function parseDomainSettings(raw: unknown): DomainSettings | null {
	const result = DomainSettings.safeParse(raw ?? {});
	return result.success ? result.data : null;
}
