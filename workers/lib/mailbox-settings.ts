// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import {
	DEFAULT_AGENT_MODEL,
	DEFAULT_AUTO_DRAFT_ENABLED,
	DEFAULT_CLASSIFIER_MODEL,
	DEFAULT_DRAFT_VERIFIER_MODEL,
	DEFAULT_INJECTION_SCANNER_MODEL,
	MailboxSettings,
	parseSettingsLenient,
	YaraMailScannerSettings,
} from "../../shared/mailbox-settings";

export { YaraMailScannerSettings } from "../../shared/mailbox-settings";
import type { OrgSettings } from "../../shared/org-settings";
import { getOrgSettings } from "./org-settings";
import type { DomainSettings } from "../../shared/domain-settings";
import { domainFromMailboxId, getDomainSettings } from "./domain-settings";
import {
	DEFAULT_DETECTOR_SETTINGS,
	DEFAULT_SECURITY_SETTINGS,
	type BusinessHours,
	type MailboxSecuritySettings,
} from "../security/defaults";

type R2BucketEnv = { BUCKET: R2Bucket };

/**
 * Read the per-mailbox settings blob from R2 and parse through the Zod
 * schema. Returns an empty object (not defaults) when the blob is missing
 * or unreadable — never throws.
 *
 * After #106, this returns the *raw* mailbox JSON only. Callers that need
 * inheritance-aware values must call {@link resolveMailboxSettings}; the
 * raw helper exists for the GET /api/v1/mailboxes/:id endpoint that
 * surfaces the override-only state to the UI.
 */
export async function getMailboxSettings(
	env: R2BucketEnv,
	mailboxId: string,
): Promise<MailboxSettings> {
	try {
		const obj = await env.BUCKET.get(`mailboxes/${mailboxId}.json`);
		if (obj) {
			const raw = await obj.json<Record<string, unknown>>();
			// Read-side lenient parse: a legacy hub/feed secret name that predates
			// the HUB_SECRET_/FEED_SECRET_ invariant must not wipe the whole tier.
			return parseSettingsLenient(MailboxSettings, raw);
		}
	} catch {
		// Fall through to empty — missing/malformed blob shouldn't break
		// downstream consumers. The resolver fills in defaults.
	}
	return MailboxSettings.parse({});
}

/**
 * System defaults applied as the bottom of the resolution stack. Lives
 * here (not on the Zod schema) so reads don't materialise defaults into
 * stored mailbox JSON — that distinction is what makes
 * "absent-key = inherit" possible. If any of these were on the schema,
 * the round-trip would be: read fills in default → write strips default →
 * next read fills it back in, indistinguishable from an explicit override.
 */
export const DEFAULT_MAILBOX_SETTINGS = {
	agentSystemPrompt: undefined as string | undefined,
	agentModel: DEFAULT_AGENT_MODEL,
	autoDraft: { enabled: DEFAULT_AUTO_DRAFT_ENABLED },
	injectionScannerModel: DEFAULT_INJECTION_SCANNER_MODEL,
	draftVerifierModel: DEFAULT_DRAFT_VERIFIER_MODEL,
	classifierModel: DEFAULT_CLASSIFIER_MODEL,
	security: DEFAULT_SECURITY_SETTINGS,
	intel: {} as { hub?: NonNullable<OrgSettings["intel"]>["hub"]; feeds?: NonNullable<OrgSettings["intel"]>["feeds"] },
} as const;

/**
 * Inheritance-resolved view of a mailbox's settings.
 *
 * Each field has been resolved through `mailbox > domain > org > system
 * default`. The domain tier (#142) sits between mailbox and org; an MSP
 * managing 12 mailboxes under one domain can set the agent prompt or
 * security policy once at the domain level instead of editing 12 mailbox
 * files.
 *
 * Fields that have a system default are guaranteed-present (e.g.
 * `agentModel: string`, not `string | undefined`). Fields with no
 * meaningful default (`agentSystemPrompt`) stay `string | undefined`.
 *
 * `intel.hub` and `intel.feeds` may be `undefined` when neither tier set
 * them — there's no system default for either.
 *
 * `raw` carries the per-mailbox JSON as-stored. `domain`, `org` carry the
 * raw blobs from the other tiers so the UI can introspect which tier
 * supplied each resolved field (the per-mailbox settings page renders
 * "Inherited from <domain>" / "Inherited from org" / "Default" badges
 * based on which tier has each field set).
 *
 * `domainName` is the domain the mailbox belongs to (or null when the
 * mailboxId can't be parsed). Surfaced so the UI can render the badge text.
 */
export interface ResolvedMailboxSettings {
	agentSystemPrompt: string | undefined;
	agentModel: string;
	autoDraft: { enabled: boolean };
	injectionScannerModel: string;
	draftVerifierModel: string;
	classifierModel: string;
	security: MailboxSecuritySettings;
	intel: {
		hub?: NonNullable<OrgSettings["intel"]>["hub"];
		feeds?: NonNullable<OrgSettings["intel"]>["feeds"];
	};
	raw: MailboxSettings;
	domain: DomainSettings;
	domainName: string | null;
	org: OrgSettings;
}

/**
 * Resolve a mailbox's effective settings through the full inheritance
 * hierarchy: `mailbox > domain > org > system default` (#142).
 *
 * Whole-object replacement for nested fields. If a mailbox sets `security`
 * (any sub-field), it carries the *whole* security object — the
 * domain/org `security` blocks are NOT deep-merged in. Same for
 * `intel.hub` and `intel.feeds`. This matches the v1 decision in #106's
 * audit (Q3, Q4, Q6).
 *
 * Carve-out (#149): `security.allowlist_senders` and
 * `security.allowlist_domains` extend across the org and mailbox tiers —
 * the resolved arrays are `unique(lowercased(org ++ mailbox))` when both
 * are set. Operator-as-extender is the right model for allowlists;
 * operator-as-replacer is the right model for everything else
 * (`thresholds`, `business_hours`, `attachment_policy`,
 * `folder_policies`, `classification`, `trusted_authserv_ids` all stay
 * whole-replace). This is per-field, not a generic deep-merge.
 *
 * Domain tier intentionally does NOT extend in this pass: when
 * `domain.security` wins (mailbox absent), it whole-replaces
 * `org.security` including allowlists. Domain-tier extend semantics
 * under the same pattern are tracked as the follow-up #150 — pulled out
 * of #149's scope per the issue's out-of-scope list.
 *
 * `security` is post-normalised (lowercased allowlists, trimmed
 * blocklist extensions, etc.) so consumers don't repeat the case fold at
 * runtime — for the carve-out fields, normalisation runs on the
 * post-extend union; for everything else, on whichever block won the
 * resolve.
 *
 * The domain layer is keyed off the mailboxId's domain part. A malformed
 * mailboxId (no `@`) skips the domain read entirely and falls through to
 * org/default — same behaviour as if no `domains/<domain>.json` existed.
 */
export async function resolveMailboxSettings(
	env: R2BucketEnv,
	mailboxId: string,
): Promise<ResolvedMailboxSettings> {
	const domainName = domainFromMailboxId(mailboxId);
	const [mailbox, domain, org] = await Promise.all([
		getMailboxSettings(env, mailboxId),
		domainName ? getDomainSettings(env, domainName) : Promise.resolve({} as DomainSettings),
		getOrgSettings(env),
	]);

	// Whole-object replace across tiers, in order: mailbox > domain > org.
	// Within the winning tier, mergeSecurityWithDefault completes any
	// unset fields with the system default so consumers see a fully-
	// populated MailboxSecuritySettings.
	const securityWinner = mailbox.security ?? domain.security ?? org.security;
	const securityBase = securityWinner
		? mergeSecurityWithDefault(securityWinner)
		: DEFAULT_SECURITY_SETTINGS;
	// Per-field carve-out (#149): when the mailbox tier sets a security
	// override, the two allowlist arrays extend with the org tier's
	// allowlists rather than whole-replacing them. Pulled from the *raw*
	// per-tier blobs (not from the winner) so a mailbox override doesn't
	// silently shadow upstream entries — which is the regression #149
	// exists to prevent.
	//
	// Domain tier is NOT in the union (out of scope per #149's issue).
	// When `domain.security` wins because mailbox is absent, it
	// whole-replaces org including allowlists, same as today.
	const securityWithAllowlists = mailbox.security
		? extendAllowlistsWithOrg(securityBase, org.security as RawSecurityAllowlists | undefined)
		: securityBase;

	// Post-resolve carve-out (#150, extended in #164): business_hours is
	// the ONE security sub-field that merges per-field across tiers
	// instead of whole-object replace. Resolution per field is
	// `mailbox > domain > org > undefined`; if all three tiers are absent
	// the resolved value stays undefined (we don't materialise an inert
	// default block). Every other security sub-field continues to follow
	// the whole-tier replace rule.
	const security = mergeBusinessHoursAcrossTiers(securityWithAllowlists, mailbox, domain, org);

	const intelRaw = (mailbox.intel ?? domain.intel ?? org.intel ?? {}) as NonNullable<MailboxSettings["intel"]>;

	return {
		agentSystemPrompt:
			mailbox.agentSystemPrompt ?? domain.agentSystemPrompt ?? org.agentSystemPrompt ?? undefined,
		agentModel:
			mailbox.agentModel ?? domain.agentModel ?? org.agentModel ?? DEFAULT_MAILBOX_SETTINGS.agentModel,
		autoDraft: resolveAutoDraft(mailbox.autoDraft, domain.autoDraft, org.autoDraft),
		// Security-critical model fields: mailbox > org > default (#151 PR A).
		// Domain tier is intentionally excluded — per-domain override carries
		// the same risk as per-mailbox without the UI guardrails shipped here.
		injectionScannerModel:
			mailbox.injectionScannerModel ?? org.injectionScannerModel ?? DEFAULT_MAILBOX_SETTINGS.injectionScannerModel,
		draftVerifierModel:
			mailbox.draftVerifierModel ?? org.draftVerifierModel ?? DEFAULT_MAILBOX_SETTINGS.draftVerifierModel,
		classifierModel:
			mailbox.classifierModel ?? org.classifierModel ?? DEFAULT_MAILBOX_SETTINGS.classifierModel,
		security: normalizeSecurity(security),
		intel: {
			hub: intelRaw.hub,
			feeds: intelRaw.feeds,
		},
		raw: mailbox,
		domain,
		domainName,
		org,
	};
}

function resolveAutoDraft(
	mailbox: MailboxSettings["autoDraft"],
	domain: DomainSettings["autoDraft"],
	org: OrgSettings["autoDraft"],
): { enabled: boolean } {
	const winner = mailbox ?? domain ?? org;
	if (!winner) return { enabled: DEFAULT_AUTO_DRAFT_ENABLED };
	return { enabled: winner.enabled ?? DEFAULT_AUTO_DRAFT_ENABLED };
}

/**
 * Complete a partial security override (from either tier) with the system
 * default. The override carries whatever keys it set; missing keys fall
 * through to the default. This is NOT cross-tier deep merge — by the time
 * we reach this function, `value` is whichever single tier won the
 * whole-object replace, and we're just filling in unset keys from
 * DEFAULT_SECURITY_SETTINGS so consumers don't see undefined thresholds /
 * attachment_policy / classification.
 */
function mergeSecurityWithDefault(value: unknown): MailboxSecuritySettings {
	const partial = (value ?? {}) as Partial<MailboxSecuritySettings>;
	return {
		...DEFAULT_SECURITY_SETTINGS,
		...partial,
		thresholds: { ...DEFAULT_SECURITY_SETTINGS.thresholds, ...(partial.thresholds ?? {}) },
		attachment_policy: {
			...DEFAULT_SECURITY_SETTINGS.attachment_policy,
			...(partial.attachment_policy ?? {}),
		},
		classification: {
			...DEFAULT_SECURITY_SETTINGS.classification,
			...(partial.classification ?? {}),
		},
		ruf_ingestion: {
			...DEFAULT_SECURITY_SETTINGS.ruf_ingestion,
			...(partial.ruf_ingestion ?? {}),
		},
		detectors: {
			...DEFAULT_DETECTOR_SETTINGS,
			...(partial.detectors ?? {}),
			sender_graph: {
				...DEFAULT_DETECTOR_SETTINGS.sender_graph,
				...(partial.detectors?.sender_graph ?? {}),
			},
		},
	};
}

/**
 * Per-field carve-out (#149) for `allowlist_senders` and
 * `allowlist_domains` only. Every other security sub-field stays
 * whole-replace by the winner tier. Resolved value for each carve-out
 * field is `unique(lowercased(org ++ mailbox))` with stable upstream-first
 * order (org entries first, mailbox second) so audit logs remain
 * comparable across tiers.
 *
 * Only invoked when the mailbox tier set a security override. Reads from
 * the *raw* per-tier blobs because the whole-object winner (the mailbox
 * block) has already discarded upstream entries — the union must still
 * surface the org's allowlist entries; that's the regression this fix
 * exists to prevent.
 *
 * Domain tier is intentionally NOT in the union. Strictly per-array, not
 * a generic deep-merge.
 */
/** Allowlist arrays as carried by the raw passthrough Zod blobs — the Zod
 *  schemas only nominally know `attachment_policy` / `folder_policies` /
 *  `classification`; the allowlist arrays travel via passthrough so we
 *  reach for them with this hand-rolled view. */
type RawSecurityAllowlists = {
	allowlist_senders?: readonly string[];
	allowlist_domains?: readonly string[];
};

function extendAllowlistsWithOrg(
	base: MailboxSecuritySettings,
	org: RawSecurityAllowlists | undefined,
): MailboxSecuritySettings {
	return {
		...base,
		allowlist_senders: unionLowerStable(org?.allowlist_senders, base.allowlist_senders),
		allowlist_domains: unionLowerStable(org?.allowlist_domains, base.allowlist_domains),
	};
}

/**
 * Stable upstream-first union: concatenate all provided arrays in order,
 * lowercase each entry, and dedupe by lowercased value (first occurrence
 * wins so the upstream-first order is preserved). Empty/undefined arrays
 * contribute nothing.
 */
function unionLowerStable(...lists: Array<readonly string[] | undefined>): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const list of lists) {
		if (!list) continue;
		for (const raw of list) {
			const v = raw.toLowerCase();
			if (seen.has(v)) continue;
			seen.add(v);
			out.push(v);
		}
	}
	return out;
}

/**
 * Per-field merge for `security.business_hours` across tiers (#150,
 * extended to the domain tier in #164).
 *
 * Unlike the rest of `security`, `business_hours` resolves field-by-field
 * across the full inheritance chain: `mailbox > domain > org > undefined`.
 * The motivating case is a mailbox (or domain) that wants its own
 * `timezone` without having to re-state all five fields from upstream.
 *
 * Important asymmetries vs the whole-object replace path:
 *
 *  - The `securityResolved.business_hours` value at the time of overlay
 *    might have been picked up from any tier via the whole-object replace;
 *    this function discards it deliberately and rebuilds from the raw
 *    per-tier blobs so the contract is "mailbox > domain > org > undefined"
 *    exactly as the acceptance specifies.
 *  - All three tiers absent → `business_hours` stays `undefined`. We do
 *    NOT materialise a default block; `boost_on_off_hours: false` would
 *    make it inert anyway, but the absence shape is the contract so
 *    consumers can detect "never configured" vs "configured but disabled".
 *
 * The `securityResolved` argument is the post-`mergeSecurityWithDefault`
 * block (with the #149 allowlist overlay already applied); we replace only
 * its `business_hours` slot. Every other sub-field (`thresholds`,
 * `attachment_policy`, `folder_policies`, `classification`,
 * `trusted_authserv_ids`, allowlists) is untouched by this overlay.
 */
function mergeBusinessHoursAcrossTiers(
	securityResolved: MailboxSecuritySettings,
	mailbox: MailboxSettings,
	domain: DomainSettings,
	org: OrgSettings,
): MailboxSecuritySettings {
	const mailboxBH = (mailbox.security as { business_hours?: Partial<BusinessHours> } | undefined)
		?.business_hours;
	const domainBH = (domain.security as { business_hours?: Partial<BusinessHours> } | undefined)
		?.business_hours;
	const orgBH = (org.security as { business_hours?: Partial<BusinessHours> } | undefined)
		?.business_hours;

	if (!mailboxBH && !domainBH && !orgBH) {
		// All three tiers absent — drop whatever the whole-object replace
		// might have surfaced and leave undefined.
		return { ...securityResolved, business_hours: undefined };
	}

	// Per-field precedence is mailbox > domain > org. Spread upstream-first
	// so later spreads overwrite per field.
	const merged: Partial<BusinessHours> = {
		...(orgBH ?? {}),
		...(domainBH ?? {}),
		...(mailboxBH ?? {}),
	};
	// Without a timezone the block is inert (normalizeSecurity drops it
	// anyway). Pass through whatever fields the tiers set; normalize fills
	// the rest from sensible defaults if a timezone exists.
	return { ...securityResolved, business_hours: merged as BusinessHours };
}

/**
 * Lowercase allowlists and trusted-authserv-ids, normalise attachment
 * blocklist extensions. Runs on the *resolved* security block so consumers
 * don't repeat the case fold. Materialises `business_hours` defaults only
 * when a timezone is set (a partially-specified block is otherwise inert
 * because `boost_on_off_hours` defaults to false).
 */
function normalizeSecurity(s: MailboxSecuritySettings): MailboxSecuritySettings {
	return {
		...s,
		allowlist_senders: s.allowlist_senders.map((v) => v.toLowerCase()),
		allowlist_domains: s.allowlist_domains.map((v) => v.toLowerCase()),
		trusted_authserv_ids: s.trusted_authserv_ids.map((v) => v.toLowerCase()),
		attachment_policy: {
			...s.attachment_policy,
			custom_blocklist_extensions: (s.attachment_policy.custom_blocklist_extensions ?? [])
				.map((e) => e.trim().toLowerCase().replace(/^\./, ""))
				.filter((e) => e.length > 0),
		},
		business_hours: s.business_hours && s.business_hours.timezone
			? {
				timezone: s.business_hours.timezone,
				start_hour: s.business_hours.start_hour ?? 7,
				end_hour: s.business_hours.end_hour ?? 19,
				weekdays_only: s.business_hours.weekdays_only ?? true,
				boost_on_off_hours: s.business_hours.boost_on_off_hours ?? false,
			}
			: undefined,
	};
}

/**
 * Strip fields from a settings PUT payload that are equal to the system
 * default — prevents a fresh PUT (mailbox or domain) from silently
 * overriding every upstream field (acceptance criterion 6 from #106 +
 * #142). Whole-object equality for nested fields: if `incoming.security`
 * deep-equals `DEFAULT_SECURITY_SETTINGS`, the whole `security` key is
 * dropped; otherwise the whole object is kept (we never partially strip
 * a nested block, since the override semantics are whole-object replace).
 *
 * Does NOT mutate the input. Returns a new object containing only the
 * keys that survived stripping. The signature is shared between
 * MailboxSettings, DomainSettings, and OrgSettings — they all carry the
 * same inheritable keys via passthrough, and the strip rule per key is
 * keyed on the key name, not the schema type.
 */
export function stripDefaultEqual<T extends Record<string, unknown>>(
	settings: T,
): T {
	const out: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(settings)) {
		if (value === undefined) continue;
		if (isDefaultEqual(key, value)) continue;
		out[key] = value;
	}
	return out as T;
}

function isDefaultEqual(key: string, value: unknown): boolean {
	switch (key) {
		case "agentModel":
			return value === DEFAULT_MAILBOX_SETTINGS.agentModel;
		case "injectionScannerModel":
			return value === DEFAULT_MAILBOX_SETTINGS.injectionScannerModel;
		case "draftVerifierModel":
			return value === DEFAULT_MAILBOX_SETTINGS.draftVerifierModel;
		case "classifierModel":
			return value === DEFAULT_MAILBOX_SETTINGS.classifierModel;
		case "autoDraft":
			return deepEqual(value, DEFAULT_MAILBOX_SETTINGS.autoDraft);
		case "agentSystemPrompt":
			return value === undefined || value === "";
		case "security":
			return deepEqual(value, DEFAULT_SECURITY_SETTINGS);
		case "intel":
			// No default for intel — only strip when the override is an empty object.
			return deepEqual(value, {});
		case "domains":
			// Empty domains array is the default; strip it so absent-key semantics
			// are preserved and the blob doesn't accumulate `"domains": []` on every write.
			return Array.isArray(value) && value.length === 0;
		case "yaramail_scanner":
			// Off by default — strip when disabled or empty so absent-key semantics
			// are preserved and a fresh save doesn't persist an inert block.
			return deepEqual(value, { enabled: false }) || deepEqual(value, {});
		case "catchall_intel":
			// Off by default — strip the disabled default so absent-key semantics
			// are preserved; an operator explicitly enabling it will survive.
			return deepEqual(value, { enabled: false, retention_days: 30, sample_limit: 50 })
				|| deepEqual(value, { enabled: false })
				|| deepEqual(value, {});
		default:
			return false;
	}
}

function deepEqual(a: unknown, b: unknown): boolean {
	if (a === b) return true;
	if (typeof a !== typeof b) return false;
	if (a === null || b === null) return false;
	if (typeof a !== "object") return false;
	if (Array.isArray(a)) {
		if (!Array.isArray(b) || a.length !== b.length) return false;
		return a.every((v, i) => deepEqual(v, (b as unknown[])[i]));
	}
	if (Array.isArray(b)) return false;
	const keysA = Object.keys(a as Record<string, unknown>);
	const keysB = Object.keys(b as Record<string, unknown>);
	if (keysA.length !== keysB.length) return false;
	return keysA.every((k) =>
		deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
	);
}
