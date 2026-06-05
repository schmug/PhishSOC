// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Loader } from "@cloudflare/kumo";
import {
	BriefcaseIcon,
	EnvelopeIcon,
	EyeIcon,
	ShieldCheckIcon,
	WarningIcon,
} from "@phosphor-icons/react";
import { Link as RouterLink, useParams } from "react-router";
import Shell from "~/components/phishsoc/Shell";
import { useCatchallIntel, useDomainStats, useRufRecords } from "~/queries/domains";
import type {
	CatchallRecentSample,
	CatchallSourceRollup,
	CatchallSummary,
	DmarcRufRecord,
	DnssecPosture,
	DomainStats,
	OrgVerdictMix,
} from "~/types";

export function meta({ params }: { params: { domain?: string } }) {
	return [{ title: `${params.domain ?? "Domain"} · PhishSOC` }];
}

export default function DomainDetailRoute() {
	const { domain } = useParams<{ domain: string }>();
	const { data, isLoading, isError, refetch } = useDomainStats(domain);
	const rufQuery = useRufRecords(domain);
	const catchallQuery = useCatchallIntel(domain);

	return (
		<Shell>
			<div className="px-6 md:px-10 py-8 max-w-[1280px] space-y-6">
				<DomainHeader domain={domain ?? ""} data={data} />

				{isLoading ? (
					<div className="flex justify-center py-20">
						<Loader size="lg" />
					</div>
				) : isError ? (
					<DomainError onRetry={() => refetch()} />
				) : data ? (
					<DomainBody data={data} rufData={rufQuery.data} catchallData={catchallQuery.data} catchallLoading={catchallQuery.isLoading} />
				) : null}
			</div>
		</Shell>
	);
}

function DomainHeader({
	domain,
	data,
}: { domain: string; data: DomainStats | undefined }) {
	const subtitle = data
		? `${data.mailboxes.length} mailbox${data.mailboxes.length === 1 ? "" : "es"}`
		: "Per-domain operations";
	return (
		<div>
			<div className="text-[11px] uppercase tracking-[0.08em] text-ink-3 mb-1">
				Domain · last 24 hours
			</div>
			<h1 className="pp-serif text-[40px] leading-none text-ink mb-2">
				{domain}
			</h1>
			<p className="pp-serif text-[24px] leading-tight text-ink-3 max-w-2xl">
				{subtitle}
			</p>
		</div>
	);
}

function DomainError({ onRetry }: { onRetry: () => void }) {
	return (
		<div className="pp-card p-6 flex items-start gap-3">
			<span className="flex h-8 w-8 items-center justify-center rounded-full bg-paper-2 text-ink-3 shrink-0">
				<WarningIcon size={18} />
			</span>
			<div>
				<div className="text-[14px] font-medium text-ink mb-1">
					Couldn't load this domain
				</div>
				<p className="text-[12.5px] text-ink-3 leading-relaxed mb-2">
					The domain stats endpoint didn't respond. Check the worker logs and retry.
				</p>
				<button
					type="button"
					onClick={onRetry}
					className="text-[12px] underline text-accent hover:opacity-80"
				>
					Retry
				</button>
			</div>
		</div>
	);
}

function DomainBody({
	data,
	rufData,
	catchallData,
	catchallLoading,
}: {
	data: DomainStats;
	rufData: import("~/queries/domains").RufRecordsResponse | undefined;
	catchallData: CatchallSummary | undefined;
	catchallLoading: boolean;
}) {
	return (
		<>
			<KpiGrid data={data} />
			<div className="grid gap-4 lg:grid-cols-3">
				<VerdictMixCard mix={data.verdictMix} />
				<DmarcPostureCard posture={data.dmarcPosture} />
			</div>
			<div className="grid gap-4 lg:grid-cols-3">
				<MtaStsPostureCard posture={data.mtaStsPosture} domain={data.domain} />
				<BimiPostureCard posture={data.bimiPosture} />
				<SpfPostureCard posture={data.spfPosture} />
			</div>
			<div className="grid gap-4 lg:grid-cols-3">
				<TlsRptPostureCard posture={data.tlsRptPosture} />
				<DkimPostureCard posture={data.dkimPosture} />
				<DnssecPostureCard posture={data.dnssec} />
			</div>
			<MailboxList mailboxes={data.mailboxes} />
			{data.recentCases.length > 0 && <RecentCasesList cases={data.recentCases} />}
			{rufData?.enabled && rufData.records.length > 0 && (
				<RufFailuresTable records={rufData.records} />
			)}
			<CatchallProbesCard data={catchallData} isLoading={catchallLoading} />
		</>
	);
}

interface Kpi {
	label: string;
	value: string;
}

function KpiGrid({ data }: { data: DomainStats }) {
	const kpis: Kpi[] = [
		{ label: "Threats blocked · 24h", value: String(data.threatsBlocked24h) },
		{ label: "Threats blocked · 7d", value: String(data.threatsBlocked7d) },
		{ label: "Open cases", value: String(data.openCases) },
		{ label: "Mailboxes", value: String(data.mailboxes.length) },
	];
	return (
		<div className="grid gap-4 grid-cols-1 sm:grid-cols-2 md:grid-cols-4">
			{kpis.map((k) => (
				<div key={k.label} className="pp-card p-4">
					<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-2">
						{k.label}
					</div>
					<div className="pp-serif text-[36px] leading-none text-ink">
						{k.value}
					</div>
				</div>
			))}
		</div>
	);
}

const VERDICT_LABEL: Record<keyof OrgVerdictMix, string> = {
	safe: "Safe",
	suspicious: "Suspicious",
	phishing: "Phishing",
	spam: "Spam",
	bec: "BEC",
};

function VerdictMixCard({ mix }: { mix: OrgVerdictMix }) {
	const entries = (Object.keys(VERDICT_LABEL) as Array<keyof OrgVerdictMix>).map(
		(k) => ({ key: k, label: VERDICT_LABEL[k], count: mix[k] }),
	);
	const total = entries.reduce((sum, e) => sum + e.count, 0);
	return (
		<div className="pp-card p-5 lg:col-span-2 flex flex-col gap-3">
			<div className="flex items-baseline justify-between gap-3">
				<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 flex items-center gap-1.5">
					<ShieldCheckIcon size={12} />
					Verdict mix · 24h
				</div>
				<div className="text-[12px] text-ink-3">{total} classified</div>
			</div>
			{total === 0 ? (
				<p className="text-[12.5px] text-ink-3">
					No classified mail in the window.
				</p>
			) : (
				<ul className="space-y-2">
					{entries.map((e) => {
						const pct = total === 0 ? 0 : (e.count / total) * 100;
						return (
							<li key={e.key} className="flex items-center gap-3">
								<div className="text-[12px] text-ink-2 w-24 shrink-0">
									{e.label}
								</div>
								<div className="flex-1 h-1.5 rounded-full bg-paper-3 overflow-hidden">
									<div
										className="h-full bg-accent"
										style={{ width: `${pct}%` }}
										aria-hidden
									/>
								</div>
								<div className="pp-mono text-[11px] text-ink-3 tabular-nums w-10 text-right">
									{e.count}
								</div>
							</li>
						);
					})}
				</ul>
			)}
		</div>
	);
}

function DmarcPostureCard({
	posture,
}: { posture: DomainStats["dmarcPosture"] }) {
	// All-null posture is the v1 norm — real DMARC report ingestion at the
	// apex-domain level isn't shipping in this iteration. Render an
	// "unavailable" affordance rather than misleading defaults.
	const allNull =
		posture.p === null &&
		posture.sp === null &&
		posture.pct === null &&
		posture.ruaConfigured === null &&
		posture.alignmentRate === null;
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<ShieldCheckIcon size={12} />
				DMARC posture
			</div>
			{allNull ? (
				<p className="text-[12.5px] text-ink-3">
					Apex-domain DMARC posture isn't ingested yet. The per-mailbox DMARC
					dashboard surfaces the report rollups available today.
				</p>
			) : (
				<dl className="space-y-1.5 text-[12.5px]">
					<PostureRow label="p" value={posture.p ?? "—"} />
					<PostureRow label="sp" value={posture.sp ?? "—"} />
					<PostureRow
						label="pct"
						value={posture.pct === null ? "—" : `${posture.pct}%`}
					/>
					<PostureRow
						label="rua"
						value={
							posture.ruaConfigured === null
								? "—"
								: posture.ruaConfigured
									? "configured"
									: "not configured"
						}
					/>
					<PostureRow
						label="alignment"
						value={
							posture.alignmentRate === null
								? "—"
								: `${Math.round(posture.alignmentRate * 100)}%`
						}
					/>
				</dl>
			)}
		</div>
	);
}

function MtaStsPostureCard({
	posture,
	domain,
}: { posture: DomainStats["mtaStsPosture"]; domain: string }) {
	const allNull =
		posture.mode === null &&
		posture.mx === null &&
		posture.maxAge === null &&
		posture.id === null;
	const txtPublishedPolicyAbsent =
		posture.id !== null &&
		posture.mode === null &&
		posture.mx === null &&
		posture.maxAge === null;
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<ShieldCheckIcon size={12} />
				MTA-STS posture
			</div>
			{allNull ? (
				<p className="text-[12.5px] text-ink-3">
					MTA-STS isn't published for this domain (or the lookup failed). Operators
					configure it by publishing a `_mta-sts` TXT record plus a policy file at
					`mta-sts.&lt;domain&gt;/.well-known/mta-sts.txt`.
				</p>
			) : txtPublishedPolicyAbsent ? (
				<p className="text-[12.5px] text-ink-3">
					TXT record present (id: <span className="pp-mono">{posture.id}</span>) but
					policy file unreachable — check that{" "}
					<span className="pp-mono">
						mta-sts.{domain}/.well-known/mta-sts.txt
					</span>{" "}
					resolves and returns 200.
				</p>
			) : (
				<dl className="space-y-1.5 text-[12.5px]">
					<PostureRow label="mode" value={posture.mode ?? "—"} />
					<PostureRow
						label="mx"
						value={
							posture.mx && posture.mx.length > 0
								? posture.mx.join(", ")
								: "—"
						}
					/>
					<PostureRow
						label="max_age"
						value={posture.maxAge === null ? "—" : `${posture.maxAge}s`}
					/>
					<PostureRow label="id" value={posture.id ?? "—"} />
				</dl>
			)}
		</div>
	);
}

function BimiPostureCard({
	posture,
}: { posture: DomainStats["bimiPosture"] }) {
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<ShieldCheckIcon size={12} />
				BIMI
			</div>
			{posture.configured === false ? (
				<p className="text-[12.5px] text-ink-3">not configured</p>
			) : (
				<p className="text-[12.5px] text-ink">
					{posture.hasVmc ? "configured (with VMC)" : "configured (without VMC)"}
				</p>
			)}
		</div>
	);
}

function SpfPostureCard({
	posture,
}: { posture: DomainStats["spfPosture"] }) {
	const allNull =
		posture.record === null &&
		posture.allQualifier === null &&
		posture.mechanismCount === null &&
		posture.totalLookups === null;
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<ShieldCheckIcon size={12} />
				SPF posture
			</div>
			{allNull ? (
				<p className="text-[12.5px] text-ink-3">
					SPF lookup unavailable, or no `v=spf1` record published. The dashboard
					re-tries on the next domain stats refresh.
				</p>
			) : (
				<dl className="space-y-1.5 text-[12.5px]">
					<PostureRow
						label="all"
						value={posture.allQualifier ?? "—"}
					/>
					<PostureRow
						label="mechanisms"
						value={posture.mechanismCount === null ? "—" : String(posture.mechanismCount)}
					/>
					<PostureRow
						label="includes"
						value={posture.includes === null ? "—" : String(posture.includes)}
					/>
					<PostureRow
						label="DNS lookups"
						value={
							posture.totalLookups === null
								? "—"
								: posture.exceedsLimit
									? `${posture.totalLookups} (exceeds 10-lookup limit — permerror)`
									: `${posture.totalLookups} / 10`
						}
					/>
				</dl>
			)}
		</div>
	);
}

function TlsRptPostureCard({
	posture,
}: { posture: DomainStats["tlsRptPosture"] }) {
	// Per #168 constraint: "Unavailable" (configured=null) and "genuinely
	// missing" (configured=false) render the SAME empty-state affordance.
	// Operators don't need to distinguish "lookup blip" from "no record" at
	// the tile level — both cases mean the same actionable thing: "publish
	// a TLS-RPT record". The KV layer still distinguishes the two so a
	// transient blip doesn't poison the cache for an hour.
	const notConfigured = posture.configured !== true;
	const endpoints = posture.endpoints ?? [];
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<ShieldCheckIcon size={12} />
				TLS-RPT posture
			</div>
			{notConfigured ? (
				<p className="text-[12.5px] text-ink-3">
					TLS reporting not configured for this domain (or the lookup was
					unavailable). Operators publish a `_smtp._tls.&lt;domain&gt;` TXT
					record like `v=TLSRPTv1; rua=mailto:tlsrpt@&lt;domain&gt;` to enable
					it.
				</p>
			) : (
				<>
					<dl className="space-y-1.5 text-[12.5px]">
						<PostureRow label="reporting" value="configured (v=TLSRPTv1)" />
						<PostureRow
							label="endpoints"
							value={endpoints.length === 0 ? "—" : String(endpoints.length)}
						/>
					</dl>
					{endpoints.length > 0 ? (
						// Keep the URI list outside the `<dl>` — `<dl>` can only contain
						// `<dt>`/`<dd>` pairs, and we want the URLs as a flat list.
						<ul className="space-y-1 mt-2">
							{endpoints.map((ep) => (
								<li
									key={ep}
									className="pp-mono text-[11px] text-ink-2 break-all"
								>
									{ep}
								</li>
							))}
						</ul>
					) : null}
				</>
			)}
		</div>
	);
}

function DkimSourceBadge({ source }: { source?: "observed" | "probed" | "both" }) {
	if (!source || source === "observed") return null;
	const label = source === "both" ? "observed+probed" : "probed";
	return (
		<span className="ml-1.5 inline-block text-[10px] px-1.5 py-0.5 rounded bg-surface-2 text-ink-3 pp-mono leading-none">
			{label}
		</span>
	);
}

function DkimPostureCard({
	posture,
}: { posture: DomainStats["dkimPosture"] }) {
	// Per #170 constraint: "Unavailable" (published=null) and "genuinely
	// missing" (published=false) render the SAME affordance — the operator
	// just sees "missing" and re-checks on the next refresh. The KV layer
	// distinguishes the two so a transient blip doesn't poison the cache.
	const selectors = posture.selectors;
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<ShieldCheckIcon size={12} />
				DKIM posture
			</div>
			{selectors.length === 0 ? (
				<p className="text-[12.5px] text-ink-3">
					No DKIM selectors observed signing as this domain (`d=`) in the
					last 30 days. Selectors are lifted from messages where
					`header.d=` matches this domain — mail your mailboxes receive
					from other senders is signed under their own `d=`, so those
					selectors don't appear here. Each selector is resolved at
					`&lt;selector&gt;._domainkey.&lt;domain&gt;` to confirm the
					record is still published.
				</p>
			) : (
				<dl className="space-y-1.5 text-[12.5px]">
					{selectors.map((s) => (
						<div key={s.selector} className="flex items-baseline justify-between gap-3">
							<dt className="text-ink-3 flex items-center">
								{s.selector}
								<DkimSourceBadge source={s.source} />
							</dt>
							<dd className="pp-mono text-ink-2 tabular-nums">
								{s.published === true ? "published" : "missing"}
							</dd>
						</div>
					))}
				</dl>
			)}
		</div>
	);
}

function RufFailuresTable({ records }: { records: DmarcRufRecord[] }) {
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<ShieldCheckIcon size={12} />
				DMARC RUF failures · recent
			</div>
			<div className="overflow-x-auto">
				<table className="w-full text-[12px] text-ink-2">
					<thead>
						<tr className="text-left text-[10.5px] uppercase tracking-[0.06em] text-ink-3 border-b border-line">
							<th className="pb-2 pr-4 font-normal">Received</th>
							<th className="pb-2 pr-4 font-normal">Source IP</th>
							<th className="pb-2 pr-4 font-normal">Reported domain</th>
							<th className="pb-2 pr-4 font-normal">Failure type</th>
							<th className="pb-2 font-normal">Auth results</th>
						</tr>
					</thead>
					<tbody className="divide-y divide-line">
						{records.map((r) => (
							<tr key={r.id} className="align-top">
								<td className="py-2 pr-4 pp-mono tabular-nums text-ink-3 whitespace-nowrap">
									{r.received_at
										? new Date(r.received_at).toLocaleString(undefined, {
												month: "short",
												day: "numeric",
												hour: "2-digit",
												minute: "2-digit",
											})
										: "—"}
								</td>
								<td className="py-2 pr-4 pp-mono text-ink-2">
									{r.source_ip ?? "—"}
								</td>
								<td className="py-2 pr-4 text-ink-2">
									{r.reported_domain ?? "—"}
								</td>
								<td className="py-2 pr-4 text-ink-2">
									{r.failure_type ?? "—"}
								</td>
								<td className="py-2 text-ink-3 max-w-xs truncate">
									{r.auth_results ?? "—"}
								</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</div>
	);
}

function DnssecPostureCard({ posture }: { posture: DnssecPosture }) {
	let statusText: string;
	if (!posture.signed) {
		statusText = "not signed";
	} else if (posture.hasDsAtParent) {
		statusText = "signed (DS at parent)";
	} else {
		statusText = "signed (no DS at parent — broken chain)";
	}
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<ShieldCheckIcon size={12} />
				DNSSEC
			</div>
			<p className={`text-[12.5px] ${posture.signed ? "text-ink" : "text-ink-3"}`}>
				{statusText}
			</p>
		</div>
	);
}

function PostureRow({ label, value }: { label: string; value: string }) {
	return (
		<div className="flex items-baseline justify-between gap-3">
			<dt className="text-ink-3">{label}</dt>
			<dd className="pp-mono text-ink-2 tabular-nums">{value}</dd>
		</div>
	);
}

function MailboxList({
	mailboxes,
}: { mailboxes: DomainStats["mailboxes"] }) {
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<EnvelopeIcon size={12} />
				Mailboxes
			</div>
			{mailboxes.length === 0 ? (
				<p className="text-[12.5px] text-ink-3">
					No mailboxes for this domain.
				</p>
			) : (
				<ul className="divide-y divide-line">
					{mailboxes.map((m) => (
						<li key={m.id} className="py-2">
							<RouterLink
								to={`/mailbox/${encodeURIComponent(m.id)}/dashboard`}
								className="flex items-center justify-between gap-3 text-[13px] text-ink hover:text-accent transition-colors"
							>
								<span className="truncate">{m.email}</span>
								<span className="text-[11px] text-ink-3">Dashboard</span>
							</RouterLink>
						</li>
					))}
				</ul>
			)}
		</div>
	);
}

function RecentCasesList({
	cases,
}: { cases: DomainStats["recentCases"] }) {
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<BriefcaseIcon size={12} />
				Recent cases
			</div>
			<ul className="divide-y divide-line">
				{cases.map((c) => (
					<li
						key={c.id}
						className="py-2 flex items-baseline justify-between gap-3"
					>
						<span className="text-[13px] text-ink truncate">{c.title}</span>
						<span className="pp-mono text-[11px] text-ink-3 tabular-nums shrink-0">
							{c.status}
						</span>
					</li>
				))}
			</ul>
		</div>
	);
}

function CatchallProbesCard({
	data,
	isLoading,
}: {
	data: CatchallSummary | undefined;
	isLoading: boolean;
}) {
	if (isLoading) {
		return (
			<div className="pp-card p-5">
				<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
					<EyeIcon size={12} />
					Catch-all probes
				</div>
				<div className="flex justify-center py-4">
					<Loader size="sm" />
				</div>
			</div>
		);
	}

	const empty = !data || data.totals.probe_count === 0;
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<EyeIcon size={12} />
				Catch-all probes
			</div>
			{empty ? (
				<p className="text-[12.5px] text-ink-3">
					No catch-all probe activity recorded. Enable <span className="pp-mono">catchall_intel</span> on this domain to start collecting directory-harvest data.
				</p>
			) : (
				<div className="space-y-5">
					<dl className="grid grid-cols-3 gap-4">
						<div>
							<dt className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-1">Probes</dt>
							<dd className="pp-serif text-[28px] leading-none text-ink">{data.totals.probe_count}</dd>
						</div>
						<div>
							<dt className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-1">Sources</dt>
							<dd className="pp-serif text-[28px] leading-none text-ink">{data.totals.distinct_sources}</dd>
						</div>
						<div>
							<dt className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-1">Local-parts tried</dt>
							<dd className="pp-serif text-[28px] leading-none text-ink">{data.totals.distinct_localparts}</dd>
						</div>
					</dl>
					{data.topSources.length > 0 && (
						<CatchallTopSourcesTable sources={data.topSources} />
					)}
					{data.recent.length > 0 && (
						<CatchallRecentSamplesTable samples={data.recent} />
					)}
				</div>
			)}
		</div>
	);
}

function CatchallTopSourcesTable({ sources }: { sources: CatchallSourceRollup[] }) {
	return (
		<div>
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-2">
				Top sources
			</div>
			<div className="overflow-x-auto">
				<table className="w-full text-[12px] text-ink-2">
					<thead>
						<tr className="text-left text-[10.5px] uppercase tracking-[0.06em] text-ink-3 border-b border-line">
							<th className="pb-2 pr-4 font-normal">Source IP</th>
							<th className="pb-2 pr-4 font-normal">Sender domain</th>
							<th className="pb-2 pr-4 font-normal text-right">Probes</th>
							<th className="pb-2 pr-4 font-normal text-right">Local-parts</th>
							<th className="pb-2 font-normal text-right">Max score</th>
						</tr>
					</thead>
					<tbody className="divide-y divide-line">
						{sources.map((s) => (
							<tr key={`${s.source_ip}:${s.sender_domain}`} className="align-top">
								<td className="py-2 pr-4 pp-mono text-ink-2">{s.source_ip}</td>
								<td className="py-2 pr-4 text-ink-2">{s.sender_domain}</td>
								<td className="py-2 pr-4 pp-mono tabular-nums text-ink-2 text-right">{s.count}</td>
								<td className="py-2 pr-4 pp-mono tabular-nums text-ink-2 text-right">{s.distinct_localparts}</td>
								<td className="py-2 pp-mono tabular-nums text-ink-2 text-right">{s.max_score}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</div>
	);
}

function CatchallRecentSamplesTable({ samples }: { samples: CatchallRecentSample[] }) {
	return (
		<div>
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-2">
				Recent samples
			</div>
			<div className="overflow-x-auto">
				<table className="w-full text-[12px] text-ink-2">
					<thead>
						<tr className="text-left text-[10.5px] uppercase tracking-[0.06em] text-ink-3 border-b border-line">
							<th className="pb-2 pr-4 font-normal">Time</th>
							<th className="pb-2 pr-4 font-normal">Local-part</th>
							<th className="pb-2 pr-4 font-normal">Sender</th>
							<th className="pb-2 pr-4 font-normal">Source IP</th>
							<th className="pb-2 font-normal">Score / band</th>
						</tr>
					</thead>
					<tbody className="divide-y divide-line">
						{samples.map((s) => (
							<tr key={s.id} className="align-top">
								<td className="py-2 pr-4 pp-mono tabular-nums text-ink-3 whitespace-nowrap">
									{new Date(s.ts).toLocaleString(undefined, {
										month: "short",
										day: "numeric",
										hour: "2-digit",
										minute: "2-digit",
									})}
								</td>
								{/* attacker-controlled fields — rendered as text; React escapes by default */}
								<td className="py-2 pr-4 pp-mono text-ink-2 max-w-[10rem] truncate">{s.localpart}</td>
								<td className="py-2 pr-4 text-ink-2 max-w-[12rem] truncate">{s.sender}</td>
								<td className="py-2 pr-4 pp-mono text-ink-2">{s.source_ip}</td>
								<td className="py-2 pp-mono tabular-nums text-ink-2">{s.score} · {s.band}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</div>
	);
}
