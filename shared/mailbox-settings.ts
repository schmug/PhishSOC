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

/**
 * Compensating-control mitigations (issue #100). Each field enables or
 * disables a named mitigation. Absent key = on by default (absent-key-inherits).
 * See `MitigationConfig` and `DEFAULT_MITIGATION_CONFIG` in
 * `workers/security/verdict.ts`.
 */
const MitigationConfig = z
  .object({
    dmarc_pass_compensates_method_fail: z.boolean().optional(),
  })
  .passthrough();

const SenderGraphSettings = z
  .object({
    enabled: z.boolean().optional(),
  })
  .passthrough();

const DetectorSettings = z
  .object({
    sender_graph: SenderGraphSettings.optional(),
  })
  .passthrough();

export const SecuritySettings = z
  .object({
    attachment_policy: AttachmentPolicy.optional(),
    folder_policies: z.record(z.string(), FolderPolicy).optional(),
    classification: ClassificationSettings.optional(),
    mitigations: MitigationConfig.optional(),
    detectors: DetectorSettings.optional(),
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

/**
 * READ-side lenient parse for a settings tier (mailbox / org / domain).
 *
 * The strict schema is still used verbatim on WRITE paths (settings PUT
 * endpoints, `parseOrgSettings` / `parseDomainSettings`) so malformed input is
 * rejected at write time. But on READ, a *legacy stored blob* whose
 * `intel.hub.api_key_secret_name` (or a feed's `auth_secret`, or the sidecar's
 * `credentials_secret_name`) predates the `HUB_SECRET_` / `FEED_SECRET_` /
 * `SIDECAR_SECRET_` prefix invariant must not blow away the whole tier — a
 * strict `.parse()` throws on the entire object, which would silently drop
 * `agentModel`, `autoDraft`, `security`, etc. on every read.
 *
 * Strategy: parse strictly; on failure, drop ONLY the offending `intel.hub`,
 * the invalid `intel.feeds[]` entries, and/or the invalid `sidecar` block,
 * then retry. The runtime guards (`loadHubConfig` / `resolveFeeds` /
 * `sidecarConfigOf`) already enforce the prefix at use time, so a dropped
 * block merely disables that one feature rather than corrupting the tier.
 * Anything malformed beyond those known cases falls back to empty (prior
 * behaviour). NOTE: read-only — never use this on a write path.
 *
 * SECURITY NOTE (#592): salvage means DROP, never accept. An invalid block —
 * e.g. a `sidecar.credentials_secret_name` outside the `SIDECAR_SECRET_`
 * namespace, which could otherwise point the poller at an arbitrary worker
 * secret — is deleted from the parsed result, never passed through, "fixed
 * up", or written back to R2 (the stored blob is untouched). The strict
 * schemas stay the write-path gate and `sidecarConfigOf` / `loadHubConfig`
 * stay the runtime enforcement layer; this function only prevents the
 * failure mode where one bad block wipes every other setting (including
 * `security` overrides) to `{}` on read.
 */
export function parseSettingsLenient<T extends z.ZodTypeAny>(
  schema: T,
  raw: unknown,
): z.infer<T> {
  const first = schema.safeParse(raw ?? {});
  if (first.success) return first.data;

  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const rec = raw as Record<string, unknown>;
    const issues = first.error.issues;
    const salvaged: Record<string, unknown> = { ...rec };
    const droppedLabels: string[] = [];

    const intel = rec.intel;
    if (intel && typeof intel === "object" && !Array.isArray(intel)) {
      const dropHub = issues.some((i) => i.path[0] === "intel" && i.path[1] === "hub");
      const dropFeeds = issues.some(
        (i) => i.path[0] === "intel" && i.path[1] === "feeds",
      );
      if (dropHub || dropFeeds) {
        const salvagedIntel: Record<string, unknown> = {
          ...(intel as Record<string, unknown>),
        };
        if (dropHub) delete salvagedIntel.hub;
        if (dropFeeds) {
          salvagedIntel.feeds = Array.isArray(salvagedIntel.feeds)
            ? (salvagedIntel.feeds as unknown[]).filter(
                (f) => IntelFeed.safeParse(f).success,
              )
            : undefined;
        }
        salvaged.intel = salvagedIntel;
        droppedLabels.push(
          `intel.${[dropHub && "hub", dropFeeds && "feeds"]
            .filter(Boolean)
            .join("+")}`,
        );
      }
    }

    // #592: an invalid `sidecar` block (bad `SIDECAR_SECRET_` prefix, legacy
    // shape, manual R2 edit) is dropped wholesale — never partially accepted —
    // so it degrades to "sidecar disabled" on read instead of wiping the tier.
    const dropSidecar =
      "sidecar" in rec && issues.some((i) => i.path[0] === "sidecar");
    if (dropSidecar) {
      delete salvaged.sidecar;
      droppedLabels.push("sidecar");
    }

    // Same lenient-parse safety for domain-level relay config
    const dropRelay =
      "relay" in rec && issues.some((i) => i.path[0] === "relay");
    if (dropRelay) {
      delete salvaged.relay;
      droppedLabels.push("relay");
    }

    if (droppedLabels.length > 0) {
      const retry = schema.safeParse(salvaged);
      if (retry.success) {
        console.warn(
          `parseSettingsLenient: dropped invalid ${droppedLabels.join(
            "+",
          )} on read; preserved the rest of the tier`,
        );
        return retry.data;
      }
    }
  }

  return schema.parse({}) as z.infer<T>;
}

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
 * Honeypot mailbox configuration (issue #24). A honeypot is an ephemeral burner
 * address seeded where phishing is likely to find it. Everything that lands in
 * one is unsolicited by construction, so its inbound IOCs are auto-published to
 * the community hub with elevated trust and the inbox never surfaces in the
 * user UI. Honeypots are created via `POST /api/v1/honeypots`, not the normal
 * mailbox flow, and are reaped by the hourly cron once `expires_at` passes.
 */
export const HoneypotSettings = z
  .object({
    /** Marks this mailbox as a honeypot sensor (excluded from the UI listing). */
    enabled: z.boolean().optional(),
    /** ISO-8601 timestamp after which the cron reaps this honeypot + its blobs. */
    expires_at: z.string().optional(),
    /** Per-honeypot inbound cap; auto-disabled once exceeded (storage-abuse guard). */
    max_inbound: z.number().int().positive().optional(),
    /** Set true by the rate-cap auto-disable; suppresses further IOC publishing. */
    disabled: z.boolean().optional(),
  })
  .passthrough();

export type HoneypotSettings = z.infer<typeof HoneypotSettings>;

/**
 * API-sidecar configuration (issue #31). When present, this mailbox is a
 * *sidecar* mailbox: its authoritative message store is the operator's
 * existing Google Workspace inbox, and PhishSOC only polls, scores, and
 * (in active mode) labels it. Absence of this block = a normal local
 * mailbox. Defaults (observe mode, label-only, 7-day retention) are NOT
 * set here — `workers/lib/sidecar-config.ts` applies them at read time,
 * per the #106 absent-key-inherits convention.
 *
 * The service-account JSON is NEVER persisted in R2 — only the *name* of a
 * worker secret (`credentials_secret_name`), resolved from `env` at call
 * time. Same pattern (and same confused-deputy rationale) as
 * `HubConfig.api_key_secret_name`.
 */
export const SidecarSettings = z
  .object({
    provider: z.literal("workspace"),
    credentials_secret_name: z
      .string()
      .min(1)
      .startsWith("SIDECAR_SECRET_", { message: "Secret name must start with SIDECAR_SECRET_" }),
    mode: z.enum(["observe", "active"]).optional(),
    quarantine_behavior: z.enum(["label-only", "label-and-archive"]).optional(),
    retention_days: z.number().int().min(0).optional(),
  })
  .passthrough();

export type SidecarSettings = z.infer<typeof SidecarSettings>;

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
  honeypot: HoneypotSettings.optional(),
  sidecar: SidecarSettings.optional(),
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
