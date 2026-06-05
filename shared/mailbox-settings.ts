// shared/mailbox-settings.ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { z } from "zod";

/**
 * Per-mailbox settings stored at R2 key `mailboxes/<mailboxId>.json`.
 *
 * The schema is intentionally lenient on the write side (passthrough) so
 * future fields can land without coordinated frontend/backend deploys.
 *
 * `security` is a typed sub-shape: only `attachment_policy`,
 * `folder_policies`, and `classification` are validated here — the rest of
 * the object is passthrough so unrelated security fields (allowlist_senders,
 * thresholds, business_hours, etc.) round-trip untouched. Defaults are
 * intentionally NOT set in the schema; the resolver in
 * `workers/lib/mailbox-settings.ts` (`resolveMailboxSettings`) applies
 * `DEFAULT_SECURITY_SETTINGS` (defined in `workers/security/defaults.ts`)
 * as the bottom of the inheritance stack. See #106.
 */

const AttachmentAction = z.enum(["block", "score", "ignore"]);

const AttachmentPolicy = z
  .object({
    executable_action: AttachmentAction.optional(),
    container_action: AttachmentAction.optional(),
    macro_office_action: AttachmentAction.optional(),
    custom_blocklist_extensions: z.array(z.string()).optional(),
  })
  .passthrough();

const FolderPolicy = z
  .object({
    mode: z.enum(["skip_all", "skip_classifier"]).optional(),
    treat_as_verified: z.boolean().optional(),
  })
  .passthrough();

/**
 * Classifier-stage settings. Currently only the timeout-handling toggle
 * (issue #28). When `skip_on_timeout` is true (the default), an LLM
 * classifier timeout/AbortError contributes 0 to the verdict score and
 * tags the email with `llm_unavailable`. When false, the legacy
 * fail-closed-to-`suspicious` behavior is preserved for backward compat.
 */
const ClassificationSettings = z
  .object({
    skip_on_timeout: z.boolean().optional(),
  })
  .passthrough();

export const SecuritySettings = z
  .object({
    attachment_policy: AttachmentPolicy.optional(),
    folder_policies: z.record(z.string(), FolderPolicy).optional(),
    classification: ClassificationSettings.optional(),
  })
  .passthrough();

/**
 * Per-mailbox MISP-compatible threat-intel hub config (#97).
 *
 * Mirrors the backend `HubConfig` interface in `workers/lib/hub-config.ts`.
 * The API key itself is NEVER persisted in R2 — only the *name* of a worker
 * secret (`api_key_secret_name`) is stored, and the worker resolves the live
 * value from `c.env` at call time. That way an org can rotate the key with
 * `wrangler secret put` without rewriting the mailbox JSON.
 *
 * `loadHubConfig` requires `url`, `org_uuid`, and `api_key_secret_name` to be
 * non-empty strings, so the schema marks them required when `hub` is present.
 * The whole `intel` block is optional + passthrough so unrelated future intel
 * fields (#29 peer subscriptions) round-trip without a coordinated deploy.
 */
export const HubConfig = z
  .object({
    url: z.string().url().min(1),
    org_uuid: z.string().min(1),
    api_key_secret_name: z.string().min(1).startsWith("HUB_SECRET_"),
    default_sharing_group_uuid: z.string().optional(),
    auto_report: z.boolean().optional(),
  })
  .passthrough();

/**
 * Per-feed configuration for the threat-intel cron pipeline. Runtime shape
 * lives in `workers/intel/feeds.ts` (`MailboxIntelSettings.feeds`). Declared
 * here so the resolver can whole-replace the `intel.feeds` array cleanly
 * (was previously opaque via `.passthrough()`).
 */
export const IntelFeed = z
  .object({
    id: z.string().min(1),
    url: z.string().optional(),
    kind: z.enum(["domain", "url", "ip-cidr"]).optional(),
    refresh_hours: z.number().optional(),
    headers: z.record(z.string(), z.string()).optional(),
    auth_secret: z.string().min(1).startsWith("FEED_SECRET_", { message: "Secret name must start with FEED_SECRET_" }).optional(),
  })
  .passthrough();

export const IntelSettings = z
  .object({
    hub: HubConfig.optional(),
    feeds: z.array(IntelFeed).optional(),
  })
  .passthrough();

export const AutoDraftSettings = z
  .object({
    enabled: z.boolean().optional(),
  })
  .passthrough();

/**
 * Per-mailbox opt-in configuration for the yaramail async attachment-scanning
 * sidecar (issue #256). Off by default — a fresh mailbox never contacts the
 * sidecar unless the operator explicitly sets `enabled: true` and supplies
 * `endpoint_url`. The sidecar runs as an operator-supplied Docker container;
 * no Python code ships inside the Worker runtime.
 */
export const YaraMailScannerSettings = z
  .object({
    enabled: z.boolean().optional(),
    endpoint_url: z.string().optional(),
  })
  .passthrough();

export type YaraMailScannerSettings = z.infer<typeof YaraMailScannerSettings>;

/**
 * Per-mailbox settings stored at R2 key `mailboxes/<mailboxId>.json`.
 *
 * Semantic shift introduced by #106: **field absence = inherit**. Defaults
 * are NOT materialised at the schema layer — they live in
 * `workers/lib/mailbox-settings.ts` (`DEFAULT_MAILBOX_SETTINGS`) and are
 * applied as a final fallback inside `resolveMailboxSettings`. Putting
 * defaults on the schema would make every read look like an override, which
 * the inheritance hierarchy can't distinguish from an intentional one.
 *
 * Three security-critical model fields (`injectionScannerModel`,
 * `draftVerifierModel`, `classifierModel`) are declared here as optional
 * strings (#151 PR A). The resolver chain is `mailbox > org > default` —
 * domain tier is intentionally excluded (per-domain override carries the
 * same risk as per-mailbox without UI guardrails). The UI surfaces a
 * confirmation modal and a curated dropdown so the security trade-off is
 * explicit.
 */
export const MailboxSettings = z.object({
  agentSystemPrompt: z.string().optional(),
  autoDraft: AutoDraftSettings.optional(),
  agentModel: z.string().optional(),
  injectionScannerModel: z.string().optional(),
  draftVerifierModel: z.string().optional(),
  classifierModel: z.string().optional(),
  security: SecuritySettings.optional(),
  intel: IntelSettings.optional(),
  yaramail_scanner: YaraMailScannerSettings.optional(),
}).passthrough();

export type MailboxSettings = z.infer<typeof MailboxSettings>;

/**
 * Hand-curated list shown in the Settings model dropdown. The first entry
 * MUST match `DEFAULT_MAILBOX_SETTINGS.agentModel` (defined in
 * `workers/lib/mailbox-settings.ts`, applied as the bottom of the resolver
 * stack) so an unconfigured mailbox renders with a list option selected,
 * not "Custom".
 */
export const TEXT_MODELS = [
  "@cf/moonshotai/kimi-k2.5",
  "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
] as const;

/** System default for the agent model. Lives here (rather than at the schema
 *  default layer) so the resolver can distinguish "absent → inherit" from
 *  "explicitly set". Imported by `workers/lib/mailbox-settings.ts` for
 *  inclusion in `DEFAULT_MAILBOX_SETTINGS`. */
export const DEFAULT_AGENT_MODEL = "@cf/moonshotai/kimi-k2.5";

/** System default for the auto-draft toggle. Same rationale as
 *  `DEFAULT_AGENT_MODEL`. */
export const DEFAULT_AUTO_DRAFT_ENABLED = true;

/**
 * Defaults for the three security-critical AI surfaces (#67). These mirror
 * the hardcoded values in the worker call sites and are exported so the
 * settings UI can show them as the placeholder when no override is set.
 *
 * Switching the injection-scanner or classifier model can degrade
 * detection — only override when you know what you're doing.
 */
export const DEFAULT_INJECTION_SCANNER_MODEL =
  "@cf/meta/llama-3.1-8b-instruct-fast";
export const DEFAULT_DRAFT_VERIFIER_MODEL =
  "@cf/meta/llama-4-scout-17b-16e-instruct";
export const DEFAULT_CLASSIFIER_MODEL = "@cf/meta/llama-3.1-8b-instruct-fast";

/**
 * Pre-vetted model list for the three security-critical model dropdowns
 * (#151 PR A). Only these models are offered in the per-mailbox UI — no
 * free-form string entry. The first entry is the system default for
 * `injectionScannerModel` and `classifierModel`; the second is the default
 * for `draftVerifierModel`. BYO-key and local-model support land in PR B/C.
 */
export const SECURITY_MODELS = [
  "@cf/meta/llama-3.1-8b-instruct-fast",
  "@cf/meta/llama-4-scout-17b-16e-instruct",
] as const;
