// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { z } from "zod";
import {
  AutoDraftSettings,
  IntelSettings,
  SecuritySettings,
} from "./mailbox-settings";

/**
 * Org-wide settings stored at R2 key `org/settings.json` (#106).
 *
 * Mirrors `MailboxSettings` minus the strictly-per-mailbox fields
 * (`fromName`, `signature`, `forwarding`, `autoReply`) and adds the three
 * security-critical model fields that are intentionally org-only at the v1
 * tier (`injectionScannerModel`, `draftVerifierModel`, `classifierModel`).
 *
 * All top-level fields are optional. The resolver treats absence as "inherit
 * the next layer down" (system default at the org tier). Nested objects
 * (`security`, `intel.hub`, `intel.feeds`) are replaced whole — never
 * deep-merged — so an org override carries the entire object including
 * arrays. Per-array extend semantics for allowlists are tracked as a
 * follow-up.
 *
 * Multi-tenant note: today this lives at the flat key `org/settings.json`
 * (single-org-per-deploy, matching #104). The R2 key is centralised in
 * `workers/lib/org-settings.ts` (`orgSettingsKey()`) so a future
 * multi-tenant refactor is one helper change rather than a cross-cutting
 * grep.
 */
export const OrgSettings = z
  .object({
    agentSystemPrompt: z.string().optional(),
    autoDraft: AutoDraftSettings.optional(),
    agentModel: z.string().optional(),
    /**
     * Org-only — security-critical model surfaces (#67). Per-mailbox
     * override for these is intentionally NOT supported today; the wrong
     * choice can let prompt-injection through. Tracked as a follow-up
     * feature (per-mailbox model overrides with user choice, local models,
     * own API keys) so the UI can surface the trade-off explicitly.
     */
    injectionScannerModel: z.string().optional(),
    draftVerifierModel: z.string().optional(),
    classifierModel: z.string().optional(),
    security: SecuritySettings.optional(),
    intel: IntelSettings.optional(),
    /**
     * UI-added receiving domains (#181). Unioned with the `DOMAINS` env-var
     * seed at `GET /api/v1/config` so operators can attach new domains
     * without redeploying. Absent (undefined) is the default — treated as
     * an empty list. Written via `POST /api/v1/org/domains` and
     * `DELETE /api/v1/org/domains/:domain`.
     */
    domains: z.array(z.string()).optional(),
    /**
     * Inline-gateway ARC sealer identity (issue #32). One sealer per
     * deployment; the PKCS8 private key lives in the
     * `ARC_SEAL_PRIVATE_KEY` Worker Secret, never in this blob.
     */
    gateway: z
      .object({
        arcSealerDomain: z.string().optional(),
        arcSelector: z.string().optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

export type OrgSettings = z.infer<typeof OrgSettings>;

/**
 * Parse a raw value as `OrgSettings`. Returns the parsed value on success,
 * or `null` when the input fails validation. Callers (the GET endpoint, the
 * resolver) treat a missing/malformed `org/settings.json` as "no org-level
 * overrides" — empty `{}` rather than throwing.
 */
export function parseOrgSettings(raw: unknown): OrgSettings | null {
  const result = OrgSettings.safeParse(raw ?? {});
  return result.success ? result.data : null;
}
