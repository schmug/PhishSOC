// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Loader } from "@cloudflare/kumo";
import {
	BriefcaseIcon,
	BuildingsIcon,
	ShieldCheckIcon,
	WarningIcon,
} from "@phosphor-icons/react";
import { useState } from "react";
import { Link as RouterLink } from "react-router";
import Shell from "~/components/phishsoc/Shell";
import { useAutoProvisionMailboxes } from "~/hooks/useAutoProvisionMailboxes";
import { useDomains } from "~/queries/domains";
import { useMailboxes } from "~/queries/mailboxes";
import { useOrgOverview } from "~/queries/org";
import { ApiError } from "~/services/api";
import type { OrgOverview, OrgVerdictMix } from "~/types";

export function meta() {
	return [{ title: "PhishSOC" }];
}

export default function HomeRoute() {
	useAutoProvisionMailboxes();
	const { data, isLoading, isError, error, refetch } = useOrgOverview();
	const { data: mailboxes = [] } = useMailboxes();

	return (
		<Shell>
			<div className="px-6 md:px-10 py-8 max-w-[1280px] space-y-6">
				<OrgHeader data={data} mailboxCount={mailboxes.length} />

				{isLoading ? (
					<div className="flex justify-center py-20">
						<Loader size="lg" />
					</div>
				) : isError ? (
					<OrgError onRetry={() => refetch()} error={error} />
				) : data ? (
					<OrgBody data={data} mailboxCount={mailboxes.length} />
				) : null}
			</div>
		</Shell>
	);
}

function OrgHeader({
	data,
	mailboxCount,
}: { data: OrgOverview | undefined; mailboxCount: number }) {
	const summary = data
		? `${data.mailboxesCount} mailbox${data.mailboxesCount === 1 ? "" : "es"} · ${data.domainsCount} domain${data.domainsCount === 1 ? "" : "s"}`
		: mailboxCount > 0
			? `${mailboxCount} mailbox${mailboxCount === 1 ? "" : "es"}`
			: "Org overview";
	return (
		<div>
			<div className="text-[11px] uppercase tracking-[0.08em] text-ink-3 mb-1">
				Operations · last 24 hours
			</div>
			<h1 className="pp-serif text-[40px] leading-none text-ink mb-2">
				Across the fleet.
			</h1>
			<p className="pp-serif text-[24px] leading-tight text-ink-3 max-w-2xl">
				{summary}
			</p>
		</div>
	);
}

function OrgError({ onRetry, error }: { onRetry: () => void; error?: unknown }) {
	const isCfAccessError =
		error instanceof ApiError && (error.status === 401 || error.status === 403);

	if (isCfAccessError) {
		return (
			<div className="pp-card p-6 flex items-start gap-3">
				<span className="flex h-8 w-8 items-center justify-center rounded-full bg-paper-2 text-ink-3 shrink-0">
					<WarningIcon size={18} />
				</span>
				<div>
					<div className="text-[14px] font-medium text-ink mb-1">
						CF Access not configured
					</div>
					<p className="text-[12.5px] text-ink-3 leading-relaxed mb-2">
						The Worker is reachable but Cloudflare Access rejected the request.
						This usually means the Access application isn't assigned to your account
						or the JWT cookie has expired.
					</p>
					<div className="flex items-center gap-4">
						<a
							href="https://github.com/schmug/PhishSOC/blob/main/README.md#troubleshooting-access"
							target="_blank"
							rel="noreferrer"
							className="text-[12px] underline text-accent hover:opacity-80"
						>
							Troubleshooting steps
						</a>
						<button
							type="button"
							onClick={onRetry}
							className="text-[12px] underline text-accent hover:opacity-80"
						>
							Retry
						</button>
					</div>
				</div>
			</div>
		);
	}

	return (
		<div className="pp-card p-6 flex items-start gap-3">
			<span className="flex h-8 w-8 items-center justify-center rounded-full bg-paper-2 text-ink-3 shrink-0">
				<WarningIcon size={18} />
			</span>
			<div>
				<div className="text-[14px] font-medium text-ink mb-1">
					Couldn't load the org overview
				</div>
				<p className="text-[12.5px] text-ink-3 leading-relaxed mb-2">
					The overview endpoint didn't respond. Check the worker logs and retry.
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

function OrgBody({
	data,
	mailboxCount,
}: { data: OrgOverview; mailboxCount: number }) {
	if (data.mailboxesCount === 0 && mailboxCount === 0) {
		return <EmptyOrg />;
	}
	return (
		<>
			<KpiGrid data={data} />
			<div className="grid gap-4 lg:grid-cols-3">
				<VerdictMixCard
					mix24h={data.verdictMix}
					mix7d={data.verdictMix7d}
				/>
				<TopThreatsCard threats={data.topThreats} />
			</div>
			<TopDomainsCard domainsCount={data.domainsCount} />
		</>
	);
}

function EmptyOrg() {
	return (
		<div className="pp-card py-10 px-8">
			<h3 className="text-base font-semibold text-ink mb-1.5">
				No mailboxes yet — set one up to start triaging mail.
			</h3>
			<p className="text-sm text-ink-3 mb-6">Start here:</p>
			<ol className="space-y-5">
				<li className="flex gap-3">
					<span className="pp-mono text-[11px] font-semibold text-ink-3 mt-0.5 w-4 shrink-0">1.</span>
					<div>
						<div className="text-sm font-medium text-ink">Configure Cloudflare Email Routing</div>
						<p className="text-[12.5px] text-ink-3 mt-0.5 leading-relaxed">
							Forward your domain's catch-all to this Worker.
						</p>
					</div>
				</li>
				<li className="flex gap-3">
					<span className="pp-mono text-[11px] font-semibold text-ink-3 mt-0.5 w-4 shrink-0">2.</span>
					<div>
						<div className="text-sm font-medium text-ink">Create your first mailbox</div>
						<RouterLink to="/mailboxes" className="text-[12.5px] text-accent hover:opacity-80 mt-0.5 block">
							Go to Mailboxes →
						</RouterLink>
					</div>
				</li>
				<li className="flex gap-3">
					<span className="pp-mono text-[11px] font-semibold text-ink-3 mt-0.5 w-4 shrink-0">3.</span>
					<div>
						<div className="text-sm font-medium text-ink">Set up domain security (DMARC / SPF / DKIM)</div>
						<RouterLink to="/domains" className="text-[12.5px] text-accent hover:opacity-80 mt-0.5 block">
							Go to Domains →
						</RouterLink>
					</div>
				</li>
				<li className="flex gap-3">
					<span className="pp-mono text-[11px] font-semibold text-ink-3 mt-0.5 w-4 shrink-0">4.</span>
					<div>
						<div className="text-sm font-medium text-ink">
							Connect a threat-intel hub <span className="text-ink-3 font-normal">(optional)</span>
						</div>
						<RouterLink to="/hub" className="text-[12.5px] text-accent hover:opacity-80 mt-0.5 block">
							Go to Hub →
						</RouterLink>
					</div>
				</li>
			</ol>
		</div>
	);
}

interface Kpi {
	label: string;
	value: string;
	/**
	 * Optional drill-down target. When set, the KPI card renders as a link so
	 * an operator scanning the org overview can click straight through to the
	 * matching detail surface (e.g. `Domains` → `/domains`). Issue #141.
	 */
	to?: string;
}

function KpiGrid({ data }: { data: OrgOverview }) {
	const kpis: Kpi[] = [
		{ label: "Threats blocked · 24h", value: String(data.threatsBlocked24h) },
		{ label: "Threats blocked · 7d", value: String(data.threatsBlocked7d) },
		{ label: "Open cases", value: String(data.openCasesTotal) },
		{
			label: "Pipeline success · 24h",
			value:
				data.pipelineHealth.successRate24h === null
					? "—"
					: `${Math.round(data.pipelineHealth.successRate24h * 100)}%`,
		},
		{
			label: "Pipeline p95 · 24h",
			value:
				data.pipelineHealth.p95Ms === null
					? "—"
					: formatLatency(data.pipelineHealth.p95Ms),
		},
		{ label: "Mailboxes", value: String(data.mailboxesCount) },
		// Drill-down: home → /domains list (#141). Even with the dedicated
		// "Top domains · 24h" widget below, the count itself is a low-cost
		// secondary affordance for operators who land here looking for a
		// domain they don't see in the top-N.
		{ label: "Domains", value: String(data.domainsCount), to: "/domains" },
		{
			label: "Hub contributions · 24h",
			value: String(data.hubContributions24h),
		},
		{
			label: "Pipeline runs · 24h",
			value: String(data.pipelineHealth.runs24h),
		},
	];
	return (
		<div className="grid gap-4 grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4">
			{kpis.map((k) => (
				<KpiCard key={k.label} kpi={k} />
			))}
		</div>
	);
}

function KpiCard({ kpi }: { kpi: Kpi }) {
	const body = (
		<>
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-2">
				{kpi.label}
			</div>
			<div className="pp-serif text-[36px] leading-none text-ink">
				{kpi.value}
			</div>
		</>
	);
	if (kpi.to) {
		return (
			<RouterLink
				to={kpi.to}
				className="pp-card p-4 block hover:bg-paper-2 transition-colors"
			>
				{body}
			</RouterLink>
		);
	}
	return <div className="pp-card p-4">{body}</div>;
}

const VERDICT_LABEL: Record<keyof OrgVerdictMix, string> = {
	safe: "Safe",
	suspicious: "Suspicious",
	phishing: "Phishing",
	spam: "Spam",
	bec: "BEC",
};

type VerdictWindow = "24h" | "7d";

function VerdictMixCard({
	mix24h,
	mix7d,
}: {
	mix24h: OrgVerdictMix;
	mix7d: OrgVerdictMix;
}) {
	const [window, setWindow] = useState<VerdictWindow>("24h");
	const mix = window === "24h" ? mix24h : mix7d;
	const entries = (Object.keys(VERDICT_LABEL) as Array<keyof OrgVerdictMix>).map(
		(k) => ({ key: k, label: VERDICT_LABEL[k], count: mix[k] }),
	);
	const total = entries.reduce((sum, e) => sum + e.count, 0);
	return (
		<div className="pp-card p-5 lg:col-span-2 flex flex-col gap-3">
			<div className="flex items-baseline justify-between gap-3">
				<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 flex items-center gap-1.5">
					<ShieldCheckIcon size={12} />
					Verdict mix
				</div>
				<div
					role="tablist"
					aria-label="Verdict-mix window"
					className="flex items-center gap-1 rounded-md bg-paper-2 p-0.5"
					onKeyDown={(e) => {
						if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
							e.preventDefault();
							const tabs = ["24h", "7d"] as const;
							const idx = tabs.indexOf(window);
							const nextIdx =
								e.key === "ArrowRight" ? (idx + 1) % 2 : (idx - 1 + 2) % 2;
							setWindow(tabs[nextIdx]);
							document.getElementById(`verdict-tab-${tabs[nextIdx]}`)?.focus();
						}
					}}
				>
					{(["24h", "7d"] as const).map((w) => (
						<button
							key={w}
							id={`verdict-tab-${w}`}
							type="button"
							role="tab"
							aria-selected={window === w}
							aria-controls="verdict-tab-panel"
							tabIndex={window === w ? 0 : -1}
							onClick={() => setWindow(w)}
							className={`px-2 py-0.5 rounded text-[11px] tabular-nums transition-colors ${
								window === w
									? "bg-paper text-ink shadow-sm"
									: "text-ink-3 hover:text-ink"
							}`}
						>
							{w}
						</button>
					))}
				</div>
				<div className="text-[12px] text-ink-3">{total} classified</div>
			</div>
			<div
				id="verdict-tab-panel"
				role="tabpanel"
				aria-labelledby={`verdict-tab-${window}`}
			>
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
		</div>
	);
}

function formatLatency(ms: number): string {
	if (ms < 1000) return `${Math.round(ms)}ms`;
	const seconds = ms / 1000;
	return seconds >= 10 ? `${Math.round(seconds)}s` : `${seconds.toFixed(1)}s`;
}

function TopThreatsCard({
	threats,
}: { threats: OrgOverview["topThreats"] }) {
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<BriefcaseIcon size={12} />
				Top threats · 24h
			</div>
			{threats.length === 0 ? (
				<p className="text-[12.5px] text-ink-3">No threats actioned yet.</p>
			) : (
				<ul className="space-y-1.5">
					{threats.map((t) => (
						<TopThreatRow key={t.category} threat={t} />
					))}
				</ul>
			)}
		</div>
	);
}

/**
 * "Top domains · 24h" — a per-domain rollup widget that lets MSP-shape
 * operators answer "which of my N domains is having the worst day?" without
 * leaving home (#141). Sorts the same `/api/v1/domains` list the `/domains`
 * route uses by `threatsBlocked24h` desc and renders the top three.
 *
 * Hidden when only one domain is configured: the widget exists to compare
 * domains, and a single-row table doesn't earn its space. Also hidden while
 * the underlying query is loading or errors out — those failure modes are
 * already surfaced by the `/domains` route itself, so duplicating them here
 * just adds noise to the home overview.
 */
const TOP_DOMAINS_LIMIT = 3;

function TopDomainsCard({ domainsCount }: { domainsCount: number }) {
	const { data, isLoading, isError } = useDomains();

	// Hide entirely when there's only one (or zero) domains — the widget
	// exists to compare domains, and a single-row table doesn't earn its
	// space on the org overview. Issue #141 acceptance criteria.
	if (domainsCount <= 1) return null;
	if (isLoading || isError || !data) return null;

	const sorted = [...data].sort(
		(a, b) => b.threatsBlocked24h - a.threatsBlocked24h,
	);
	const top = sorted.slice(0, TOP_DOMAINS_LIMIT);

	return (
		<div className="pp-card p-5">
			<div className="flex items-baseline justify-between gap-3 mb-3">
				<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 flex items-center gap-1.5">
					<BuildingsIcon size={12} />
					Top domains · 24h
				</div>
				<RouterLink
					to="/domains"
					className="text-[12px] text-accent hover:opacity-80"
				>
					View all domains →
				</RouterLink>
			</div>
			<ul className="space-y-1.5">
				{top.map((d) => (
					<li
						key={d.domain}
						className="flex items-baseline justify-between gap-3 py-1"
					>
						<RouterLink
							to={`/domains/${encodeURIComponent(d.domain)}`}
							className="text-[13px] text-ink hover:text-accent transition-colors truncate"
						>
							{d.domain}
						</RouterLink>
						<span className="pp-mono text-[12px] text-ink-3 tabular-nums">
							{d.threatsBlocked24h}
						</span>
					</li>
				))}
			</ul>
		</div>
	);
}

function TopThreatRow({
	threat,
}: { threat: OrgOverview["topThreats"][number] }) {
	const samples = threat.samples ?? [];
	if (samples.length === 0) {
		return (
			<li className="flex items-baseline justify-between gap-3 py-1">
				<span className="text-[13px] text-ink capitalize">{threat.category}</span>
				<span className="pp-mono text-[12px] text-ink-3 tabular-nums">
					{threat.count}
				</span>
			</li>
		);
	}
	return (
		<li>
			<details className="group">
				<summary className="flex items-baseline justify-between gap-3 py-1 cursor-pointer list-none [&::-webkit-details-marker]:hidden hover:text-ink">
					<span className="text-[13px] text-ink capitalize flex items-center gap-1.5">
						<span
							aria-hidden
							className="pp-mono text-[10px] text-ink-3 transition-transform group-open:rotate-90"
						>
							›
						</span>
						{threat.category}
					</span>
					<span className="pp-mono text-[12px] text-ink-3 tabular-nums">
						{threat.count}
					</span>
				</summary>
				<ul className="mt-1 mb-1.5 ml-3 space-y-1 border-l border-line pl-3">
					{samples.map((s) => (
						<li key={s.emailId} className="text-[12px] leading-tight">
							<div className="text-ink truncate">{s.subject || "(no subject)"}</div>
							<div className="text-ink-3 truncate">
								{s.sender || "(unknown sender)"}
							</div>
						</li>
					))}
				</ul>
			</details>
		</li>
	);
}
