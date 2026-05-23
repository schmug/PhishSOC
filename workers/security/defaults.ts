// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Leaf module: types and default values for `MailboxSecuritySettings`.
 *
 * Split out of `workers/security/settings.ts` so the resolver
 * (`workers/lib/mailbox-settings.ts`) can import the defaults without
 * pulling in `getSecuritySettings`, which itself now calls the resolver.
 * Without this split the import graph cycles.
 */

import {
	DEFAULT_THRESHOLDS,
	DEFAULT_MITIGATION_CONFIG,
	type VerdictThresholds,
	type MitigationConfig,
} from "./verdict";
import { DEFAULT_ATTACHMENT_POLICY, type AttachmentPolicy } from "./attachments";

/**
 * Business-hours definition for the off-hours scrutiny tier.
 *
 * This is a *scoring* input — it tilts marginal verdicts, never decides them
 * alone. See `workers/security/time-rules.ts` for the rationale (BEC / wire
 * fraud is correlated with off-hours delivery). The short-circuit triage
 * layer is intentionally NOT wired to this signal: a trusted allowlisted
 * sender emailing at 3 AM is still a legitimate email.
 */
export interface BusinessHours {
	/** IANA timezone, e.g. `America/New_York`. Invalid values fall back to no contribution. */
	timezone: string;
	/** Inclusive start hour in 24h local time. 7 means 07:00 counts as in-hours. */
	start_hour: number;
	/** Exclusive end hour in 24h local time. 19 means 19:00 counts as out-of-hours. */
	end_hour: number;
	/** When true, Saturday and Sunday count as outside business hours regardless of the hour. */
	weekdays_only: boolean;
	/** Master switch so existing mailboxes opt-in explicitly. Defaults to false. */
	boost_on_off_hours: boolean;
}

/**
 * Classifier-stage tunables. Currently only one knob: how to treat an LLM
 * timeout/AbortError. See issue #28 and `workers/security/classification.ts`.
 */
export interface ClassificationSettings {
	/**
	 * When true (default), an LLM classifier timeout/AbortError contributes
	 * 0 to the verdict score and tags the email with `llm_unavailable`. When
	 * false, the legacy fail-closed-to-`suspicious` behavior is preserved.
	 */
	skip_on_timeout: boolean;
}

/**
 * Per-folder policy: either bypasses part of the pipeline (`mode`) or marks
 * the folder as a trust signal (`treat_as_verified` — moving mail in bumps
 * the sender's reputation). Both fields are independent.
 */
export interface FolderPolicy {
	mode?: "skip_all" | "skip_classifier";
	treat_as_verified?: boolean;
}

/**
 * Per-detector enable/disable controls (issue #26). Absent key = enabled
 * (matches the absent-key-inherits convention for security features whose
 * default is "on" for new mailboxes where false-positive risk is low).
 */
export interface DetectorSettings {
	sender_graph?: {
		/** When false, the BEC / display-name impersonation detector is
		 *  disabled for this mailbox. Defaults to true. */
		enabled?: boolean;
	};
}

export interface MailboxSecuritySettings {
	enabled: boolean;
	thresholds: VerdictThresholds;
	/** Learning mode: tag only, never auto-quarantine. */
	learning_mode: boolean;
	/** Exact sender addresses (lowercased) that short-circuit to allow when DMARC passes. */
	allowlist_senders: string[];
	/** Registrable domains (lowercased) that short-circuit to allow when DMARC passes. */
	allowlist_domains: string[];
	/**
	 * Lowercased list of trusted `authserv-id` values. Empty list falls back
	 * to first-header-wins (insecure against forgery). Operators should
	 * populate this list to match their mail path.
	 */
	trusted_authserv_ids: string[];
	/** Enable the hard-allow triage tier. Requires DMARC pass — never allowlist alone. */
	trusted_auto_allow: boolean;
	/** History-based hard-allow: if a sender has ≥ this many prior messages with avg_score < 20 (and DMARC passes), auto-allow. 0 disables. */
	trusted_auto_allow_min_messages: number;
	/** Enable the hard-block triage tier on confirmed intel-feed hits or flagged senders. */
	intel_auto_block: boolean;
	/** Optional per-mailbox business-hours policy. */
	business_hours?: BusinessHours;
	/** Per-folder bypass policies keyed by folder id. */
	folder_policies?: Record<string, FolderPolicy>;
	/** Attachment-type gate. Runs before hard-allow in triage. */
	attachment_policy: AttachmentPolicy;
	/** Classifier-stage settings (issue #28). */
	classification: ClassificationSettings;
	/**
	 * Issue #219: when true, post-aggregation verdicts whose `action` is
	 * `quarantine` but whose `confidence` is below
	 * `min_confidence_for_quarantine` are demoted to `tag` so operators can
	 * review them rather than seeing a hard quarantine on a shaky verdict.
	 * Defaults to false — existing mailboxes keep today's behaviour.
	 */
	confidence_aware_actions: boolean;
	/**
	 * Threshold in [0,1] used by `confidence_aware_actions`. A
	 * post-aggregation `quarantine` whose confidence is strictly less than
	 * this value is demoted to `tag`. Default 0.6.
	 */
	min_confidence_for_quarantine: number;
	/**
	 * Issue #100: per-mailbox compensating-control mitigations. Each field
	 * enables or disables a named mitigation. Absent key = on by default
	 * (matching the "absent-key-inherits" convention). See `MitigationConfig`
	 * and `DEFAULT_MITIGATION_CONFIG` in `workers/security/verdict.ts`.
	 */
	mitigations: MitigationConfig;
	/**
	 * Issue #171: DMARC RUF (forensic report) ingestion. Default-off because
	 * forensic reports can contain PII for legitimate users experiencing
	 * transient SPF/DKIM glitches. Both fields default false so a fresh
	 * mailbox never silently ingests forensic reports.
	 */
	ruf_ingestion: RufIngestionSettings;
	/** Issue #26: per-mailbox detector on/off controls. */
	detectors: DetectorSettings;
}

/**
 * Per-mailbox DMARC RUF forensic-report ingestion controls (issue #171).
 * Both default false — opt-in per mailbox.
 */
export interface RufIngestionSettings {
	/** When true, incoming `message/feedback-report` mail is parsed and stored. */
	enabled: boolean;
	/**
	 * When true, the original message body is stored alongside the failure
	 * record. **Privacy warning:** bodies may contain PII. Disabled by
	 * default; operators must acknowledge the privacy implications before
	 * enabling.
	 */
	retain_raw: boolean;
}

export type { MitigationConfig };

/**
 * Default for the new classification block. Skip-on-timeout is ON so the
 * common case (Workers-AI throttling, model cold start) doesn't dump a
 * burst of legitimate mail into the `suspicious` bucket.
 */
export const DEFAULT_CLASSIFICATION_SETTINGS: ClassificationSettings = {
	skip_on_timeout: true,
};

export const DEFAULT_RUF_INGESTION_SETTINGS: RufIngestionSettings = {
	enabled: false,
	retain_raw: false,
};

export const DEFAULT_DETECTOR_SETTINGS: DetectorSettings = {
	sender_graph: { enabled: true },
};

export const DEFAULT_SECURITY_SETTINGS: MailboxSecuritySettings = {
	enabled: false, // opt-in — existing mailboxes are unaffected until the user flips this
	thresholds: DEFAULT_THRESHOLDS,
	learning_mode: false,
	allowlist_senders: [],
	allowlist_domains: [],
	trusted_authserv_ids: [],
	trusted_auto_allow: true,
	trusted_auto_allow_min_messages: 10,
	intel_auto_block: true,
	attachment_policy: DEFAULT_ATTACHMENT_POLICY,
	classification: DEFAULT_CLASSIFICATION_SETTINGS,
	confidence_aware_actions: false,
	min_confidence_for_quarantine: 0.6,
	mitigations: DEFAULT_MITIGATION_CONFIG,
	ruf_ingestion: DEFAULT_RUF_INGESTION_SETTINGS,
	detectors: DEFAULT_DETECTOR_SETTINGS,
};
