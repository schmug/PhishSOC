// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Pure helpers for the operations dashboard. Live outside the Durable Object
 * so the bucketing + JSON-parsing logic is unit-testable without a
 * runtime SQL surface — the DO `getDashboardSummary` method composes these
 * with the SQL it owns.
 */

export type ThreatAction = "tag" | "quarantine" | "block";

export interface VerdictBucketRow {
	/** ISO 8601 timestamp from `emails.date`. */
	date: string | null;
	/** Raw `emails.security_verdict` cell — JSON-encoded `VerdictResult`. */
	security_verdict: string | null;
}

/**
 * Roll up recent emails into N equal-width time buckets, counting only
 * threat-actioned verdicts (tag/quarantine/block — `allow` is dropped).
 *
 * Buckets are oldest-first, so `result[0]` is the oldest window and
 * `result[N-1]` is the most recent. Rows outside the window or with
 * unparseable verdict JSON are silently dropped.
 */
export function bucketThreatPressure(
	rows: VerdictBucketRow[],
	options: { now?: Date; bucketCount?: number; windowHours?: number } = {},
): number[] {
	const now = options.now ?? new Date();
	const bucketCount = options.bucketCount ?? 12;
	const windowHours = options.windowHours ?? 24;

	const windowMs = windowHours * 60 * 60 * 1000;
	const windowStart = now.getTime() - windowMs;
	const bucketMs = windowMs / bucketCount;
	const buckets = new Array<number>(bucketCount).fill(0);

	for (const row of rows) {
		if (!row.date || !row.security_verdict) continue;

		const action = parseVerdictAction(row.security_verdict);
		if (action !== "tag" && action !== "quarantine" && action !== "block")
			continue;

		const t = Date.parse(row.date);
		if (Number.isNaN(t)) continue;
		if (t < windowStart || t > now.getTime()) continue;

		const idx = Math.min(
			Math.floor((t - windowStart) / bucketMs),
			bucketCount - 1,
		);
		buckets[idx] += 1;
	}

	return buckets;
}

function parseVerdictAction(json: string): string | null {
	const parsed = parseVerdict(json);
	return parsed?.action ?? null;
}

interface ParsedVerdict {
	action?: string;
	classification?: { label?: string };
}

// ⚡ Bolt: Cache parsed JSON verdicts to avoid overhead in large render/aggregation loops
const verdictCache = new Map<string, ParsedVerdict | null>();

function parseVerdict(json: string): ParsedVerdict | null {
	let result = verdictCache.get(json);
	if (result !== undefined) {
		return result;
	}

	try {
		result = JSON.parse(json) as ParsedVerdict;
		// ⚡ Bolt: Object.freeze(result) before caching to prevent shared object reference mutation bugs
		if (result) {
			Object.freeze(result);
			if (result.classification) {
				Object.freeze(result.classification);
			}
		}
	} catch {
		result = null;
	}

	if (verdictCache.size >= 1000) {
		const firstKey = verdictCache.keys().next().value;
		if (firstKey !== undefined) verdictCache.delete(firstKey);
	}
	verdictCache.set(json, result);
	return result;
}

export interface PipelineSuccessInput {
	completed: number;
	failed: number;
}

/**
 * Compute the pipeline-success ratio over the deep-scan-status counts. Returns
 * `null` when there's no data to report (UI surfaces an "—" placeholder rather
 * than a misleading 0%).
 */
export function pipelineSuccessRate(
	input: PipelineSuccessInput,
): number | null {
	const total = input.completed + input.failed;
	if (total === 0) return null;
	return input.completed / total;
}

/**
 * Compute the 95th-percentile value of a sample of durations using linear
 * interpolation between adjacent ranks. Returns `null` for an empty sample so
 * the dashboard can render a neutral placeholder rather than a misleading 0.
 *
 * Negative or non-finite inputs are dropped — they only show up if a clock
 * jumped backwards mid-run, and counting them would understate p95.
 */
export function computeP95(durationsMs: number[]): number | null {
	const sample = durationsMs
		.filter((d) => Number.isFinite(d) && d >= 0)
		.sort((a, b) => a - b);
	if (sample.length === 0) return null;
	if (sample.length === 1) return sample[0]!;
	const rank = 0.95 * (sample.length - 1);
	const lo = Math.floor(rank);
	const hi = Math.ceil(rank);
	if (lo === hi) return sample[lo]!;
	const weight = rank - lo;
	return sample[lo]! * (1 - weight) + sample[hi]! * weight;
}

// ── Org overview aggregation ─────────────────────────────────────────

/** Subset of the per-mailbox DO summary the org aggregator consumes. */
export interface OrgMailboxSummary {
	threatsBlocked: number;
	threatsBlocked7d: number;
	openCases: number;
	hubContributions: number;
	pipelineScan: PipelineSuccessInput;
	verdictRows: VerdictBucketRow[];
	/**
	 * Pre-aggregated 7d verdict mix from the DO (#103). Pre-aggregating
	 * server-side keeps the org-overview wire payload from doubling — only
	 * the five-key counts cross the boundary, not the raw 7d rows. Optional
	 * so older DO replicas mid-deploy degrade gracefully (counted as zero).
	 */
	verdictMix7d?: VerdictMix;
	/**
	 * Pre-aggregated representative emails per actioned classification
	 * label (#101). Each label maps to up to N most-recent samples from
	 * this mailbox; the org aggregator unions across mailboxes, dedupes
	 * by emailId, and slices to top-N per category. Optional so older DO
	 * replicas mid-deploy degrade gracefully.
	 */
	topThreatSamples?: Record<string, OrgTopThreatSample[]>;
	/**
	 * Per-pipeline-run durations from `pipeline_runs` (#71). Unioned across
	 * mailboxes to compute an org-wide p95. Optional so older DO replicas
	 * mid-deploy degrade gracefully (treated as no samples).
	 */
	pipelineDurationsMs?: number[];
}

export interface OrgMailboxRef {
	id: string;
	email: string;
}

export interface VerdictMix {
	safe: number;
	suspicious: number;
	phishing: number;
	spam: number;
	bec: number;
}

/** Representative email surfaced for a top-threats category (#101). */
export interface OrgTopThreatSample {
	emailId: string;
	subject: string;
	sender: string;
}

export interface OrgTopThreat {
	category: string;
	count: number;
	/**
	 * Up to N representative emails for this category, deduped by emailId
	 * across mailboxes (#101). Optional so older DO replicas mid-deploy
	 * (which don't ship `topThreatSamples`) gracefully omit the panel.
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
	verdictMix: VerdictMix;
	/**
	 * 7-day verdict mix (#103). Sums each mailbox's pre-aggregated 7d mix.
	 * Mailboxes with no `verdictMix7d` (older DO replicas mid-deploy)
	 * contribute zero, so the field is always present.
	 */
	verdictMix7d: VerdictMix;
	topThreats: OrgTopThreat[];
	pipelineHealth: OrgPipelineHealth;
	hubContributions24h: number;
}

/** Verdict-mix labels we surface; unknown labels (e.g. malformed JSON) drop. */
const VERDICT_MIX_KEYS: ReadonlyArray<keyof VerdictMix> = [
	"safe",
	"suspicious",
	"phishing",
	"spam",
	"bec",
];

function emptyVerdictMix(): VerdictMix {
	return { safe: 0, suspicious: 0, phishing: 0, spam: 0, bec: 0 };
}

/**
 * Pure helper: tally verdict-mix labels from a list of `(date,
 * security_verdict)` rows. Used by the DO to pre-aggregate the 7-day
 * window server-side so the org-overview payload doesn't have to ship
 * raw 7d rows over the wire.
 */
export function computeVerdictMix(rows: VerdictBucketRow[]): VerdictMix {
	const mix = emptyVerdictMix();
	for (const row of rows) {
		if (!row.security_verdict) continue;
		const parsed = parseVerdict(row.security_verdict);
		if (!parsed) continue;
		const label = parsed.classification?.label;
		if (
			typeof label === "string" &&
			(VERDICT_MIX_KEYS as readonly string[]).includes(label)
		) {
			mix[label as keyof VerdictMix] += 1;
		}
	}
	return mix;
}

interface AggregateOrgOverviewInput {
	mailboxes: OrgMailboxRef[];
	/**
	 * Per-mailbox summaries. Indices align with `mailboxes`. `null` slots are
	 * mailboxes whose DO call failed — they contribute 0 to all counts but
	 * still count toward `mailboxesCount` (the operator paid to provision them
	 * regardless of whether the DO answered today).
	 */
	summaries: Array<OrgMailboxSummary | null>;
	now?: string;
	/** How many top-threats to surface. Default 5. */
	topN?: number;
	/** How many representative samples per top-threat to keep. Default 3. */
	samplesPerThreat?: number;
}

/**
 * Reduce a fan-out of per-mailbox summaries into the single org-overview
 * payload the / dashboard renders. Pure function — accepts plain objects so
 * it's exercisable in unit tests without a runtime SQL surface.
 */
export function aggregateOrgOverview(
	input: AggregateOrgOverviewInput,
): OrgOverview {
	const { mailboxes, summaries } = input;
	const now = input.now ?? new Date().toISOString();
	const topN = input.topN ?? 5;
	const samplesPerThreat = input.samplesPerThreat ?? 3;

	let threatsBlocked24h = 0;
	let threatsBlocked7d = 0;
	let openCasesTotal = 0;
	let hubContributions24h = 0;
	let pipelineCompleted = 0;
	let pipelineFailed = 0;
	const allDurationsMs: number[] = [];

	const verdictMix = emptyVerdictMix();
	const verdictMix7d = emptyVerdictMix();
	const threatCounts = new Map<string, number>();
	// Per-category collected samples, deduped by emailId across mailboxes.
	const samplesByCategory = new Map<string, Map<string, OrgTopThreatSample>>();

	for (const summary of summaries) {
		if (!summary) continue;
		threatsBlocked24h += summary.threatsBlocked;
		threatsBlocked7d += summary.threatsBlocked7d;
		openCasesTotal += summary.openCases;
		hubContributions24h += summary.hubContributions;
		pipelineCompleted += summary.pipelineScan.completed;
		pipelineFailed += summary.pipelineScan.failed;
		if (summary.pipelineDurationsMs?.length) {
			allDurationsMs.push(...summary.pipelineDurationsMs);
		}

		// Pre-aggregated 7d mix per mailbox — sum into the org-wide tally.
		// Optional on the wire so older DO replicas degrade as zeros.
		if (summary.verdictMix7d) {
			for (const k of VERDICT_MIX_KEYS) {
				verdictMix7d[k] += summary.verdictMix7d[k];
			}
		}

		for (const row of summary.verdictRows) {
			if (!row.security_verdict) continue;
			const parsed = parseVerdict(row.security_verdict);
			if (!parsed) continue;
			const label = parsed.classification?.label;
			if (
				typeof label === "string" &&
				(VERDICT_MIX_KEYS as readonly string[]).includes(label)
			) {
				verdictMix[label as keyof VerdictMix] += 1;
			}
			// Top-threats: count tag/quarantine/block by classification label.
			// `allow` is excluded because it's not a threat — surfacing "safe"
			// as a top threat would be misleading.
			if (
				(parsed.action === "tag" ||
					parsed.action === "quarantine" ||
					parsed.action === "block") &&
				typeof label === "string" &&
				label !== "safe"
			) {
				threatCounts.set(label, (threatCounts.get(label) ?? 0) + 1);
			}
		}

		// Pre-aggregated samples per category from this mailbox (#101).
		// Dedup across mailboxes by emailId — first-seen wins, matching
		// the DO's "most-recent" ordering since DOs ship samples sorted.
		if (summary.topThreatSamples) {
			for (const [category, list] of Object.entries(summary.topThreatSamples)) {
				if (!Array.isArray(list)) continue;
				let bucket = samplesByCategory.get(category);
				if (!bucket) {
					bucket = new Map<string, OrgTopThreatSample>();
					samplesByCategory.set(category, bucket);
				}
				for (const sample of list) {
					if (!sample?.emailId) continue;
					if (!bucket.has(sample.emailId)) {
						bucket.set(sample.emailId, {
							emailId: sample.emailId,
							subject: sample.subject ?? "",
							sender: sample.sender ?? "",
						});
					}
				}
			}
		}
	}

	const topThreats: OrgTopThreat[] = [...threatCounts.entries()]
		.map(([category, count]) => {
			const bucket = samplesByCategory.get(category);
			const samples = bucket
				? [...bucket.values()].slice(0, samplesPerThreat)
				: undefined;
			return samples && samples.length > 0
				? { category, count, samples }
				: { category, count };
		})
		.sort((a, b) => b.count - a.count || a.category.localeCompare(b.category))
		.slice(0, topN);

	const pipelineHealth: OrgPipelineHealth = {
		successRate24h: pipelineSuccessRate({
			completed: pipelineCompleted,
			failed: pipelineFailed,
		}),
		p95Ms: computeP95(allDurationsMs),
		runs24h: pipelineCompleted + pipelineFailed,
	};

	const domains = new Set<string>();
	for (const m of mailboxes) {
		const domain = m.email.split("@")[1]?.toLowerCase();
		if (domain) domains.add(domain);
	}

	return {
		now,
		threatsBlocked24h,
		threatsBlocked7d,
		openCasesTotal,
		mailboxesCount: mailboxes.length,
		domainsCount: domains.size,
		verdictMix,
		verdictMix7d,
		topThreats,
		pipelineHealth,
		hubContributions24h,
	};
}

// ── Per-domain aggregation (#85) ─────────────────────────────────────

/** Recent-case shape mirrored from the per-mailbox dashboard summary. */
export interface DomainRecentCase {
	id: string;
	title: string;
	status: string;
	updated_at: string;
}

/** DMARC posture v1 — best-effort, all fields nullable.
 *
 * v1 best-effort — real DMARC report ingestion (parsing apex-domain TXT
 * records / aggregating rua reports across mailboxes into a single posture)
 * is out of scope (#85). Per-mailbox DMARC summaries already exist
 * (`workers/routes/dmarc.ts`) but they're scoped to source-IP rollups, not
 * apex-domain policy. Until that pipeline ships, we return null fields and
 * the UI renders an "unavailable" affordance. */
export interface DmarcPosture {
	p: string | null;
	sp: string | null;
	pct: number | null;
	ruaConfigured: boolean | null;
	alignmentRate: number | null;
}

/** MTA-STS posture (#165) — `mode`/`mx`/`max_age`/`id` from the published
 * policy at `https://mta-sts.<domain>/.well-known/mta-sts.txt`, gated by the
 * `_mta-sts.<domain>` TXT marker. All fields nullable; null fields render the
 * "unavailable" affordance shared with DMARC posture. */
export interface MtaStsPostureView {
	mode: "enforce" | "testing" | "none" | null;
	mx: readonly string[] | null;
	maxAge: number | null;
	id: string | null;
}

/** BIMI posture (#245, part of #156).
 *
 * `{ configured: false }` — either lookup unavailable (timeout, network
 * error, non-200) or no `v=BIMI1` record published. Both states surface as
 * "not configured" in the UI — the empty-sentinel pattern from `txt.ts`.
 *
 * `{ configured: true, hasVmc: boolean }` — a valid `v=BIMI1` record was
 * found. `hasVmc` is true when the `a=` tag carries a non-empty VMC URL. */
export type BimiPostureView =
	| { configured: false }
	| { configured: true; hasVmc: boolean };

/** SPF posture (#167) — apex `<domain>` TXT plus the bounded include-chain
 * resolution count. `exceedsLimit: true` means the record fails permerror
 * per RFC 7208 §4.6.4. All fields nullable; null fields mean "lookup
 * unavailable / no record / parse failure". */
export interface SpfPostureView {
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
export interface TlsRptPostureView {
	configured: boolean | null;
	endpoints: readonly string[] | null;
}

/** DKIM published-record posture (#170, #358). Per-selector list of selectors
 * observed over the last 30 days on inbound mail to this domain OR found by
 * the active well-known-selector probe, each with its published status and
 * provenance.
 *
 * `published: true` — DoH returned a TXT entry that's a valid DKIM record.
 * `published: false` — durable "no record" (NXDOMAIN, NOERROR-no-data, or
 *   `p=` empty / "key revoked").
 * `published: null` — transient "lookup unavailable" (DoH timed out, returned
 *   non-200, or non-cacheable status). The UI renders this with the same
 *   affordance as `false` per the #170 Constraints, but the cache layer
 *   keeps them separate.
 *
 * `source` (#358) records how the selector was discovered:
 *   - `"observed"` — lifted from inbound `Authentication-Results` headers.
 *   - `"probed"` — found by the active well-known-selector probe (always `published=true`).
 *   - `"both"` — observed inbound AND confirmed by the active probe.
 *   - absent (legacy / pre-#358 payloads) — treat as `"observed"`.
 *
 * Empty `selectors` is the natural state for a domain that's never sent
 * inbound DKIM-signed mail AND none of the well-known selectors are published;
 * the UI shows the empty-state affordance. */
export interface DkimPostureView {
	selectors: ReadonlyArray<{
		selector: string;
		published: boolean | null;
		source?: "observed" | "probed" | "both";
	}>;
}

/** DNSSEC posture (#324, part of #156).
 *
 * `{ signed: false }` — resolver did not set AD=true, or any lookup failed.
 * `{ signed: true, hasDsAtParent: boolean }` — AD=true; hasDsAtParent
 *   reflects whether a DS record (type=43) exists at the apex label. */
export type DnssecPostureView =
	| { signed: false }
	| { signed: true; hasDsAtParent: boolean };

export interface DomainListEntry {
	domain: string;
	mailboxesCount: number;
	threatsBlocked24h: number;
	openCases: number;
	verdictMix: VerdictMix;
}

export interface DomainMailboxRef {
	id: string;
	email: string;
	name: string;
}

export interface DomainStats {
	now: string;
	domain: string;
	mailboxes: DomainMailboxRef[];
	threatsBlocked24h: number;
	threatsBlocked7d: number;
	openCases: number;
	verdictMix: VerdictMix;
	dmarcPosture: DmarcPosture;
	/** MTA-STS posture (#165). All-null when the upstream lookup failed or
	 * the domain doesn't publish a policy. */
	mtaStsPosture: MtaStsPostureView;
	/** BIMI posture (#166). All-null when the upstream lookup failed; a
	 * `configured: false` posture means "no `v=BIMI1` record published". */
	bimiPosture: BimiPostureView;
	/** SPF posture (#167). All-null when the upstream lookup failed; the
	 * bounded include-chain resolver caps DoH calls at MAX_LOOKUPS. */
	spfPosture: SpfPostureView;
	/** TLS-RPT posture (#168). `configured: null` when the upstream lookup
	 * failed; `configured: false` when no `v=TLSRPTv1` record is published. */
	tlsRptPosture: TlsRptPostureView;
	/** DKIM published-record posture (#170). Per-selector list across the
	 * 30-day inbound-mail observation window. Empty `selectors` is the natural
	 * state for a domain that's never received DKIM-signed inbound mail. */
	dkimPosture: DkimPostureView;
	/** DNSSEC posture (#324). `signed: false` when unsigned or lookup failed;
	 * `signed: true` when the resolver's AD bit is set, with DS-at-parent. */
	dnssec: DnssecPostureView;
	recentCases: DomainRecentCase[];
}

/** Per-mailbox summary tail used by the org-overview path; we reuse the same
 * shape here so the handler can pass through `getDashboardSummary()` results
 * unchanged. `recentCases` lives on the live DO summary even though the org
 * aggregator drops it. */
export interface DomainMailboxSummary extends OrgMailboxSummary {
	recentCases?: DomainRecentCase[];
}

/** Lower-cased domain extracted from an email address, or null when malformed.
 *
 * Requires a non-empty local part and a non-empty domain part — `@nopart`
 * and `noatsymbol` both return null. */
export function domainOf(email: string): string | null {
	const at = email.lastIndexOf("@");
	if (at <= 0 || at === email.length - 1) return null;
	const domain = email.slice(at + 1).toLowerCase();
	return domain || null;
}

/** Empty DMARC posture sentinel — every field null, signalling
 * "no real ingestion yet" to the UI.
 *
 * Retained for unit tests and as a defensive fallback; the production handler
 * builds postures from the DoH TXT lookup + alignment-rate fan-out (#138)
 * and no longer threads this sentinel into `aggregateDomainStats`. */
export function emptyDmarcPosture(): DmarcPosture {
	return {
		p: null,
		sp: null,
		pct: null,
		ruaConfigured: null,
		alignmentRate: null,
	};
}

/** Empty MTA-STS posture sentinel — every field null, rendered as
 * "not configured / unavailable" (same affordance as DMARC). */
export function emptyMtaStsPostureView(): MtaStsPostureView {
	return { mode: null, mx: null, maxAge: null, id: null };
}

/** Empty BIMI posture sentinel — `configured: false` surfaces the same
 * "not configured" affordance whether the lookup failed or found no record. */
export function emptyBimiPostureView(): BimiPostureView {
	return { configured: false };
}

/** Empty SPF posture sentinel — every field null, rendered as "unavailable". */
export function emptySpfPostureView(): SpfPostureView {
	return {
		record: null,
		allQualifier: null,
		mechanismCount: null,
		includes: null,
		totalLookups: null,
		exceedsLimit: null,
	};
}

/** Empty TLS-RPT posture sentinel — `configured=null` distinguishes
 * "lookup unavailable" from a `configured=false` "no record published"
 * result. Mirrors the BIMI sentinel shape. */
export function emptyTlsRptPostureView(): TlsRptPostureView {
	return { configured: null, endpoints: null };
}

/** Empty DKIM posture sentinel — empty selector list, rendered by the UI
 * as "no DKIM selectors observed in the last 30 days". */
export function emptyDkimPostureView(): DkimPostureView {
	return { selectors: [] };
}

/** Empty DNSSEC posture sentinel — `signed: false` surfaces the same
 * "not configured" affordance whether the lookup failed or the domain is
 * genuinely unsigned. */
export function emptyDnssecPostureView(): DnssecPostureView {
	return { signed: false };
}

/** Per-mailbox alignment totals harvested from `dmarc_records` by the DO.
 *
 * `aligned` is the sum of `count` for records where DMARC alignment passed
 * (DKIM-pass OR SPF-pass per RFC 7489 §6.6.2 — not the strict `dkim AND spf`
 * the deep-scan path uses for "fully authenticated"). `total` is the sum
 * across all records in the window. `null` slots are mailboxes whose DO
 * call failed; they contribute nothing rather than skewing the rate. */
export interface DmarcAlignmentTotals {
	aligned: number;
	total: number;
}

/**
 * Reduce a fan-out of per-mailbox alignment totals into a single rate. Pure
 * helper so the math is unit-testable without a runtime SQL surface.
 *
 * Returns `null` when there's no data — UI surfaces an "unavailable"
 * affordance rather than rendering "0%" which would imply "every message
 * failed alignment". `null` slots (failed DO calls) are skipped so a single
 * unhealthy mailbox doesn't drag the org-wide rate to 0/0.
 */
export function reduceDmarcAlignmentRate(
	totals: ReadonlyArray<DmarcAlignmentTotals | null>,
): number | null {
	let aligned = 0;
	let total = 0;
	for (const t of totals) {
		if (!t) continue;
		if (!Number.isFinite(t.aligned) || !Number.isFinite(t.total)) continue;
		if (t.aligned < 0 || t.total < 0) continue;
		aligned += t.aligned;
		total += t.total;
	}
	if (total === 0) return null;
	// Clamp to [0, 1] — if a misbehaving DO returns aligned > total we'd
	// rather report 100% than `>1` and have the UI show ">100% aligned".
	return Math.min(1, aligned / total);
}

interface AggregateDomainsListInput {
	mailboxes: OrgMailboxRef[];
	/** Indices align with `mailboxes`. `null` = DO call failed → contributes 0. */
	summaries: Array<OrgMailboxSummary | null>;
}

/**
 * Reduce per-mailbox summaries into a per-domain list. Pure function —
 * mailboxes whose email doesn't have a domain part are skipped silently.
 */
export function aggregateDomainsList(
	input: AggregateDomainsListInput,
): DomainListEntry[] {
	const { mailboxes, summaries } = input;

	interface Acc {
		mailboxesCount: number;
		threatsBlocked24h: number;
		openCases: number;
		verdictMix: VerdictMix;
	}
	const byDomain = new Map<string, Acc>();

	for (let i = 0; i < mailboxes.length; i++) {
		const m = mailboxes[i]!;
		const domain = domainOf(m.email);
		if (!domain) continue;

		let acc = byDomain.get(domain);
		if (!acc) {
			acc = {
				mailboxesCount: 0,
				threatsBlocked24h: 0,
				openCases: 0,
				verdictMix: emptyVerdictMix(),
			};
			byDomain.set(domain, acc);
		}
		acc.mailboxesCount += 1;

		const summary = summaries[i];
		if (!summary) continue;
		acc.threatsBlocked24h += summary.threatsBlocked;
		acc.openCases += summary.openCases;

		// 24h verdict mix — sum each mailbox's parsed `verdictRows`. Mirrors
		// `aggregateOrgOverview`'s mix derivation so the per-domain numbers
		// reconcile with the org-wide totals.
		for (const row of summary.verdictRows) {
			if (!row.security_verdict) continue;
			const parsed = parseVerdict(row.security_verdict);
			if (!parsed) continue;
			const label = parsed.classification?.label;
			if (
				typeof label === "string" &&
				(VERDICT_MIX_KEYS as readonly string[]).includes(label)
			) {
				acc.verdictMix[label as keyof VerdictMix] += 1;
			}
		}
	}

	return [...byDomain.entries()]
		.map(([domain, acc]) => ({ domain, ...acc }))
		.sort((a, b) => a.domain.localeCompare(b.domain));
}

interface AggregateDomainStatsInput {
	domain: string;
	mailboxes: DomainMailboxRef[];
	/** Indices align with `mailboxes`. `null` = DO call failed → contributes 0. */
	summaries: Array<DomainMailboxSummary | null>;
	now?: string;
	/**
	 * Real apex-domain DMARC posture from the DoH TXT lookup +
	 * alignment-rate fan-out (#138). When omitted the helper falls back to
	 * the all-null sentinel — that path is exercised by tests and by the
	 * forward-compat case where the handler couldn't compute posture.
	 */
	dmarcPosture?: DmarcPosture;
	/**
	 * MTA-STS posture (#165) from the `_mta-sts.<domain>` TXT marker plus
	 * the published policy file. Omitted defaults to the all-null sentinel.
	 */
	mtaStsPosture?: MtaStsPostureView;
	/**
	 * BIMI posture (#166) from the `default._bimi.<domain>` DoH lookup.
	 * Omitted defaults to the all-null sentinel.
	 */
	bimiPosture?: BimiPostureView;
	/**
	 * SPF posture (#167) from the apex `<domain>` TXT lookup + bounded
	 * include-chain resolver. Omitted defaults to the all-null sentinel.
	 */
	spfPosture?: SpfPostureView;
	/**
	 * TLS-RPT posture (#168) from the `_smtp._tls.<domain>` DoH lookup.
	 * Omitted defaults to the all-null sentinel.
	 */
	tlsRptPosture?: TlsRptPostureView;
	/**
	 * DKIM posture (#170) from per-mailbox observed selectors fanned out
	 * across the domain plus DoH lookups against
	 * `<selector>._domainkey.<domain>`. Omitted defaults to the empty
	 * sentinel (no selectors observed).
	 */
	dkimPosture?: DkimPostureView;
	/**
	 * DNSSEC posture (#324) from the resolver AD-bit query plus DS-record
	 * check. Omitted defaults to the not-signed sentinel.
	 */
	dnssec?: DnssecPostureView;
}

/**
 * Reduce per-mailbox summaries scoped to a single domain. Caller is
 * responsible for filtering `mailboxes` to only those whose domain matches
 * (lower-cased). Returns `null` when the input is empty so the handler can
 * 404 cleanly without rendering a "0 mailboxes" page.
 */
export function aggregateDomainStats(
	input: AggregateDomainStatsInput,
): DomainStats | null {
	const { domain, mailboxes, summaries } = input;
	if (mailboxes.length === 0) return null;
	const now = input.now ?? new Date().toISOString();

	let threatsBlocked24h = 0;
	let threatsBlocked7d = 0;
	let openCases = 0;
	const verdictMix = emptyVerdictMix();
	const recentCases: DomainRecentCase[] = [];

	for (const summary of summaries) {
		if (!summary) continue;
		threatsBlocked24h += summary.threatsBlocked;
		threatsBlocked7d += summary.threatsBlocked7d;
		openCases += summary.openCases;

		for (const row of summary.verdictRows) {
			if (!row.security_verdict) continue;
			const parsed = parseVerdict(row.security_verdict);
			if (!parsed) continue;
			const label = parsed.classification?.label;
			if (
				typeof label === "string" &&
				(VERDICT_MIX_KEYS as readonly string[]).includes(label)
			) {
				verdictMix[label as keyof VerdictMix] += 1;
			}
		}

		if (Array.isArray(summary.recentCases)) {
			recentCases.push(...summary.recentCases);
		}
	}

	// Most-recent first, then cap. ISO-8601 strings sort lexically.
	recentCases.sort((a, b) => (a.updated_at < b.updated_at ? 1 : -1));

	return {
		now,
		domain,
		mailboxes,
		threatsBlocked24h,
		threatsBlocked7d,
		openCases,
		verdictMix,
		dmarcPosture: input.dmarcPosture ?? emptyDmarcPosture(),
		mtaStsPosture: input.mtaStsPosture ?? emptyMtaStsPostureView(),
		bimiPosture: input.bimiPosture ?? emptyBimiPostureView(),
		spfPosture: input.spfPosture ?? emptySpfPostureView(),
		tlsRptPosture: input.tlsRptPosture ?? emptyTlsRptPostureView(),
		dkimPosture: input.dkimPosture ?? emptyDkimPostureView(),
		dnssec: input.dnssec ?? emptyDnssecPostureView(),
		recentCases: recentCases.slice(0, 5),
	};
}
