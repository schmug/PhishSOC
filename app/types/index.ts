// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

export interface SignatureSettings {
	enabled: boolean;
	text: string;
	html?: string;
}

export interface BusinessHoursSettings {
	timezone: string;
	start_hour: number;
	end_hour: number;
	weekdays_only: boolean;
	boost_on_off_hours: boolean;
}

export interface VerdictThresholdSettings {
	tag: number;
	quarantine: number;
	block: number;
}

export type AttachmentAction = "block" | "score" | "ignore";

export interface AttachmentPolicySettings {
	executable_action?: AttachmentAction;
	container_action?: AttachmentAction;
	macro_office_action?: AttachmentAction;
	custom_blocklist_extensions?: string[];
}

export interface FolderPolicySettings {
	mode?: "skip_all" | "skip_classifier";
	treat_as_verified?: boolean;
}

/**
 * Per-mailbox threat-intel hub config (#97). Mirrors the backend `HubConfig`
 * shape in `workers/lib/hub-config.ts`. `api_key_secret_name` holds the NAME
 * of a worker secret, not the secret value — the raw key never leaves
 * `wrangler secret put`.
 */
export interface HubConfigSettings {
	url?: string;
	org_uuid?: string;
	api_key_secret_name?: string;
	default_sharing_group_uuid?: string;
	auto_report?: boolean;
}

export interface IntelSettings {
	hub?: HubConfigSettings;
}

export interface RufIngestionSettings {
	enabled?: boolean;
	retain_raw?: boolean;
}

export interface MitigationSettings {
	dmarc_pass_compensates_method_fail?: boolean;
}

export interface SecuritySettings {
	enabled?: boolean;
	learning_mode?: boolean;
	thresholds?: VerdictThresholdSettings;
	allowlist_senders?: string[];
	allowlist_domains?: string[];
	trusted_authserv_ids?: string[];
	trusted_auto_allow?: boolean;
	trusted_auto_allow_min_messages?: number;
	intel_auto_block?: boolean;
	/**
	 * Issue #105: when true, post-aggregation verdicts whose action is
	 * `quarantine` but whose aggregate confidence is below
	 * `min_confidence_for_quarantine` are demoted to `tag`.
	 * Default false — existing mailboxes keep today's behaviour.
	 */
	confidence_aware_actions?: boolean;
	/** Threshold in [0,1] for the confidence-aware demote. Default 0.6. */
	min_confidence_for_quarantine?: number;
	business_hours?: BusinessHoursSettings;
	attachment_policy?: AttachmentPolicySettings;
	folder_policies?: Record<string, FolderPolicySettings>;
	ruf_ingestion?: RufIngestionSettings;
	mitigations?: MitigationSettings;
}

export interface DmarcRufRecord {
	id: string;
	received_at: string;
	original_mail_from: string | null;
	source_ip: string | null;
	failure_type: string | null;
	reported_domain: string | null;
	feedback_type: string | null;
	auth_results: string | null;
	original_headers: string | null;
}

/**
 * Per-mailbox yaramail async attachment-scanning sidecar config (#258 / #256).
 * Mirrors `YaraMailScannerSettings` in `shared/mailbox-settings.ts`.
 */
export interface YaraMailScannerSettings {
	enabled?: boolean;
	endpoint_url?: string;
}

export interface MailboxSettings {
	fromName?: string;
	forwarding?: { enabled: boolean; email: string };
	signature?: SignatureSettings;
	autoReply?: { enabled: boolean; subject: string; message: string };
	agentSystemPrompt?: string;
	security?: SecuritySettings;
	intel?: IntelSettings;
	yaramail_scanner?: YaraMailScannerSettings;
}

export interface Mailbox {
	id: string;
	email: string;
	name: string;
	settings?: MailboxSettings;
	acl_status?: "scoped" | "unscoped";
}

export interface Email {
	id: string;
	thread_id?: string | null;
	folder_id?: string | null;
	subject: string;
	sender: string;
	recipient: string;
	cc?: string;
	bcc?: string;
	date: string;
	read: boolean;
	starred: boolean;
	body?: string | null;
	in_reply_to?: string | null;
	email_references?: string | null;
	message_id?: string | null;
	raw_headers?: string | null;
	attachments?: Attachment[];
	snippet?: string | null;
	// Thread aggregate fields (only present in threaded list view)
	thread_count?: number;
	thread_unread_count?: number;
	participants?: string;
	needs_reply?: boolean;
	has_draft?: boolean;
	// Security pipeline verdict (null when the pipeline didn't run)
	security_verdict?: string | null;
	security_score?: number | null;
	security_explanation?: string | null;
}

/** Shape of the JSON stored in Email.security_verdict. */
export interface SecurityVerdict {
	action: "allow" | "tag" | "quarantine" | "block";
	score: number;
	/** Aggregate pipeline confidence (0–1). Optional: pre-#105 persisted
	 * verdicts do not carry this field. UI renders "—" when absent. */
	confidence?: number;
	explanation: string;
	auth: {
		spf: string;
		dkim: string;
		dmarc: string;
		authservId?: string;
	};
	classification: {
		label: "safe" | "spam" | "phishing" | "bec" | "suspicious";
		confidence: number;
		reasoning: string;
	};
	signals: string[];
	/** Present when a triage tier short-circuited the pipeline. */
	triage?: "hard_allow" | "hard_block" | "attachment_block" | "folder_bypass";
}

export function parseVerdict(raw: string | null | undefined): SecurityVerdict | null {
	if (!raw) return null;
	try {
		return JSON.parse(raw) as SecurityVerdict;
	} catch {
		return null;
	}
}

export interface Attachment {
	id: string;
	filename: string;
	mimetype: string;
	size: number;
	content_id?: string;
	disposition?: string;
}

export interface EmailUrl {
	id: string;
	email_id: string;
	url: string;
	display_text: string | null;
	is_homograph: number;
	is_shortener: number;
	resolved_url: string | null;
	page_title: string | null;
	fetch_status: string | null;
	verdict: string | null;
	created_at: string;
}

export interface Folder {
	id: string;
	name: string;
	unreadCount: number;
}

export interface DashboardCase {
	id: string;
	title: string;
	status: string;
	updated_at: string;
}

export interface DashboardSummary {
	now: string;
	threatsBlocked: number;
	openCases: number;
	hubContributions: number;
	/**
	 * Count of own attributes corroborated by ≥1 other contributor on the hub
	 * within the last 24h (#72). Null when the hub is unreachable or the
	 * mailbox has no hub config — the UI renders "unavailable" rather than
	 * failing the whole dashboard.
	 */
	corroboration: number | null;
	pipelineSuccess: number | null;
	/** 95th-percentile pipeline duration over the last 24h, in ms. Null when no completed runs. */
	p95Ms: number | null;
	threatPressure: number[];
	recentCases: DashboardCase[];
}

export interface OrgVerdictMix {
	safe: number;
	suspicious: number;
	phishing: number;
	spam: number;
	bec: number;
}

export interface OrgTopThreatSample {
	emailId: string;
	subject: string;
	sender: string;
}

export interface OrgTopThreat {
	category: string;
	count: number;
	/**
	 * Up to N representative emails per category, deduped across mailboxes
	 * (#101). Optional so older deploys without samples render the count-only
	 * card unchanged.
	 */
	samples?: OrgTopThreatSample[];
}

export interface OrgPipelineHealth {
	successRate24h: number | null;
	/** Org-wide p95 latency in ms — unioned per-mailbox samples (#71). */
	p95Ms: number | null;
	runs24h: number;
}

export interface OrgOverview {
	now: string;
	threatsBlocked24h: number;
	threatsBlocked7d: number;
	openCasesTotal: number;
	mailboxesCount: number;
	domainsCount: number;
	verdictMix: OrgVerdictMix;
	/** 7-day verdict mix (#103). Always present, sums per-mailbox tallies. */
	verdictMix7d: OrgVerdictMix;
	topThreats: OrgTopThreat[];
	pipelineHealth: OrgPipelineHealth;
	hubContributions24h: number;
}

/**
 * DMARC posture surfaced on the per-domain dashboard (#85). v1 best-effort:
 * we don't have a real DMARC TXT-record / aggregate-report ingestion pipeline
 * scoped to the apex domain yet, so all fields are nullable. Real ingestion
 * is out of scope for #85 and tracked separately.
 */
export interface DmarcPosture {
	p: string | null;
	sp: string | null;
	pct: number | null;
	ruaConfigured: boolean | null;
	alignmentRate: number | null;
}

/** MTA-STS posture (#165). All fields nullable; an all-null posture renders
 * the same "unavailable / not configured" affordance as DMARC posture. */
export interface MtaStsPosture {
	mode: "enforce" | "testing" | "none" | null;
	mx: readonly string[] | null;
	maxAge: number | null;
	id: string | null;
}

/** BIMI posture (#245, part of #156).
 * `{ configured: false }` — lookup unavailable or no `v=BIMI1` record found.
 * `{ configured: true, hasVmc: boolean }` — record found; hasVmc indicates
 * whether the `a=` tag carries a non-empty Verified Mark Certificate URL. */
export type BimiPosture =
	| { configured: false }
	| { configured: true; hasVmc: boolean };

/** SPF posture (#167). All-null fields render the "unavailable" affordance.
 * `exceedsLimit: true` means the record fails permerror per RFC 7208 §4.6.4. */
export interface SpfPosture {
	record: string | null;
	allQualifier: "-" | "~" | "?" | "+" | null;
	mechanismCount: number | null;
	includes: number | null;
	totalLookups: number | null;
	exceedsLimit: boolean | null;
}

/** TLS-RPT posture (#168). `configured=null` is "lookup unavailable",
 * `configured=false` is "no `v=TLSRPTv1` record at `_smtp._tls.<domain>`".
 * `endpoints` is the parsed `rua=` URI list (mailto: / https:); empty list
 * when the record exists but carries no endpoint. */
export interface TlsRptPosture {
	configured: boolean | null;
	endpoints: readonly string[] | null;
}

/** DKIM published-record posture (#170, #358). Per-selector list from the
 * 30-day inbound-mail observation window AND/OR the active well-known-selector
 * probe, each with published status and provenance.
 *
 * `published: null` is the transient "lookup unavailable" sentinel; the UI
 * renders it identically to `false` but the cache layer keeps them separate.
 *
 * `source` (#358): `"observed"` — from inbound mail headers; `"probed"` —
 * found by active probe; `"both"` — observed and probed; absent — treat as
 * `"observed"` (pre-#358 payload). */
export interface DkimPosture {
	selectors: ReadonlyArray<{
		selector: string;
		published: boolean | null;
		source?: "observed" | "probed" | "both";
	}>;
}

/** DNSSEC posture (#324, part of #156).
 * `{ signed: false }` — unsigned or lookup unavailable.
 * `{ signed: true, hasDsAtParent: boolean }` — resolver AD-bit set;
 * `hasDsAtParent` reflects whether a DS record exists at the parent zone. */
export type DnssecPosture =
	| { signed: false }
	| { signed: true; hasDsAtParent: boolean };

/** One row in the `/api/v1/domains` list. */
export interface DomainListEntry {
	domain: string;
	mailboxesCount: number;
	threatsBlocked24h: number;
	openCases: number;
	verdictMix: OrgVerdictMix;
}

/** Mailbox row inside a `/api/v1/domains/:domain/stats` payload. */
export interface DomainMailboxRef {
	id: string;
	email: string;
	name: string;
}

/** `/api/v1/domains/:domain/stats` payload — drill-down dashboard for one domain. */
export interface DomainStats {
	now: string;
	domain: string;
	mailboxes: DomainMailboxRef[];
	threatsBlocked24h: number;
	threatsBlocked7d: number;
	openCases: number;
	verdictMix: OrgVerdictMix;
	dmarcPosture: DmarcPosture;
	mtaStsPosture: MtaStsPosture;
	bimiPosture: BimiPosture;
	spfPosture: SpfPosture;
	tlsRptPosture: TlsRptPosture;
	dkimPosture: DkimPosture;
	dnssec: DnssecPosture;
	recentCases: DashboardCase[];
}

/** Source-IP rollup row from CatchallIntelDO (#425/#427). */
export interface CatchallSourceRollup {
	source_ip: string;
	sender_domain: string;
	count: number;
	distinct_localparts: number;
	max_score: number;
	first_seen: string;
	last_seen: string;
}

/** Recent probe sample row from CatchallIntelDO (#425/#427).
 * `localpart`, `sender`, `subject_snippet` are attacker-controlled — render
 * as text only, never dangerouslySetInnerHTML. */
export interface CatchallRecentSample {
	id: string;
	ts: string;
	source_ip: string;
	sender_domain: string;
	sender: string;
	localpart: string;
	subject_snippet: string;
	score: number;
	band: string;
	signals_json: string;
}

/** Shape returned by `GET /api/v1/domains/:domain/catchall-intel` (#427). */
export interface CatchallSummary {
	totals: { probe_count: number; distinct_sources: number; distinct_localparts: number };
	topSources: CatchallSourceRollup[];
	recent: CatchallRecentSample[];
}

export interface HubContribution {
	uuid: string;
	info: string;
	date: string;
	timestamp: string;
	sharing_group_uuid?: string;
	attribute_count: number;
}

export interface HubSharingGroup {
	uuid: string;
	name: string;
	description?: string;
	role?: string;
}

/**
 * Every hub UI endpoint returns this envelope. `configured: false` is the
 * normal state for a mailbox without `intel.hub` set; the UI renders one
 * "Configure hub credentials" panel and stops querying.
 */
export type HubEnvelope<T> = { configured: true; data: T } | { configured: false };

export type HubContributionsResponse = HubEnvelope<HubContribution[]>;
export type HubDestroylistResponse = HubEnvelope<{ values: string[]; count: number }>;
export type HubSharingGroupsResponse = HubEnvelope<{ groups: HubSharingGroup[] }>;

/**
 * Hub invite request — mirrors the hub `POST /orgs/invite` zod schema. All
 * fields optional; `sharing_group_uuid` binds the invite to a specific
 * sharing group (the hub returns 403 if the inviter isn't a member).
 */
export interface HubInviteRequest {
	sharing_group_uuid?: string;
	note?: string;
	ttl_hours?: number;
}

/** Hub invite response — token is returned ONCE; the modal must show it
 * immediately and clear it on close. `expires_at` is an ISO timestamp. */
export interface HubInviteResponse {
	token: string;
	expires_at: string;
}
