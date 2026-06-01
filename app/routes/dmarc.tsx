// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Loader } from "@cloudflare/kumo";
import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router";

/** RFC 4180 field escape: always wraps in double-quotes, escapes embedded quotes by doubling. */
export function csvEscapeField(value: string | number): string {
	return `"${String(value).replace(/"/g, '""')}"`;
}

export function sourcesToCsv(sources: DmarcSource[]): string {
	const header = "source_ip,total_count,pass_count,quarantine_count,reject_count,first_seen,last_seen";
	const rows = sources.map((s) =>
		[s.source_ip, s.total_count, s.pass_count, s.quarantine_count, s.reject_count, s.first_seen, s.last_seen]
			.map(csvEscapeField)
			.join(","),
	);
	return [header, ...rows].join("\r\n");
}

interface DmarcReport {
	id: string;
	received_at: string;
	org_name: string | null;
	domain: string;
	date_range_begin: string | null;
	date_range_end: string | null;
	policy_p: string | null;
	policy_adkim?: string | null;
	policy_aspf?: string | null;
	policy_sp?: string | null;
	policy_pct?: string | null;
}

interface DmarcSource {
	source_ip: string;
	total_count: number;
	pass_count: number;
	quarantine_count: number;
	reject_count: number;
	first_seen: string;
	last_seen: string;
	label?: string | null;
	legitimate: number;
}

interface DmarcAuthResultDkim {
	domain?: string;
	selector?: string;
	result?: string;
}

interface DmarcAuthResultSpf {
	domain?: string;
	result?: string;
}

interface DmarcAuthResults {
	dkim: DmarcAuthResultDkim[];
	spf: DmarcAuthResultSpf[];
}

interface DrillDownRecord {
	report_id: string;
	count: number;
	disposition?: string | null;
	dkim_result?: string | null;
	spf_result?: string | null;
	auth_results?: DmarcAuthResults | null;
	date_range_begin?: string | null;
	date_range_end?: string | null;
	org_name?: string | null;
}

const RANGE_PRESETS = [7, 30, 90] as const;
type RangeDays = (typeof RANGE_PRESETS)[number];
interface DmarcRollupRow {
	domain: string;
	total: number;
	aligned: number;
	failing: number;
}

interface DmarcRollup {
	window_days: number;
	since: string;
	domains: DmarcRollupRow[];
}

/**
 * DMARC aggregate-report dashboard. Shows legitimate vs forged sending
 * sources for a domain over the selected date window.
 */
export default function DmarcRoute() {
	const { mailboxId } = useParams<{ mailboxId: string }>();
	const [reports, setReports] = useState<DmarcReport[] | null>(null);
	const [domain, setDomain] = useState<string | null>(null);
	const [sources, setSources] = useState<DmarcSource[] | null>(null);
	const [days, setDays] = useState<RangeDays>(90);
	const [selectedIp, setSelectedIp] = useState<string | null>(null);
	const [drillDown, setDrillDown] = useState<DrillDownRecord[] | null>(null);
	const [drillDownLoading, setDrillDownLoading] = useState(false);
	const [rollup, setRollup] = useState<DmarcRollup | null>(null);
	const [showUnknownOnly, setShowUnknownOnly] = useState(false);
	const [togglingIp, setTogglingIp] = useState<string | null>(null);

	useEffect(() => {
		if (!mailboxId) return;
		fetch(`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/dmarc/reports?limit=100`)
			.then((r) => r.json() as Promise<{ reports: DmarcReport[] }>)
			.then((r) => {
				setReports(r.reports);
				if (r.reports.length > 0 && !domain) setDomain(r.reports[0].domain);
			})
			.catch((e) => console.error("dmarc reports fetch failed", e));
	}, [mailboxId, domain]);

	useEffect(() => {
		if (!mailboxId || !domain) return;
		setSources(null);
		fetch(`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/dmarc/summary?domain=${encodeURIComponent(domain)}&days=${days}`)
			.then((r) => r.json() as Promise<{ sources: DmarcSource[] }>)
			.then((r) => setSources(r.sources))
			.catch((e) => console.error("dmarc summary fetch failed", e));
	}, [mailboxId, domain, days]);

	// Fetch per-record detail for the selected source IP across recent reports.
	useEffect(() => {
		if (!mailboxId || !selectedIp || !reports) return;
		setDrillDown(null);
		setDrillDownLoading(true);
		const domainReports = reports.filter((r) => !domain || r.domain === domain);
		Promise.all(
			domainReports.map((rep) =>
				fetch(`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/dmarc/reports/${encodeURIComponent(rep.id)}/records`)
					.then((r) => r.json() as Promise<{ records: Array<{ source_ip: string; count: number; disposition?: string | null; dkim_result?: string | null; spf_result?: string | null; auth_results?: DmarcAuthResults | null }> }>)
					.then((r) => r.records
						.filter((rec) => rec.source_ip === selectedIp)
						.map((rec) => ({
							report_id: rep.id,
							count: rec.count,
							disposition: rec.disposition,
							dkim_result: rec.dkim_result,
							spf_result: rec.spf_result,
							auth_results: rec.auth_results,
							date_range_begin: rep.date_range_begin,
							date_range_end: rep.date_range_end,
							org_name: rep.org_name,
						})),
					)
					.catch(() => [] as DrillDownRecord[]),
			),
		).then((groups) => {
			setDrillDown(groups.flat());
			setDrillDownLoading(false);
		});
	}, [mailboxId, selectedIp, reports, domain]);

	useEffect(() => {
		if (!mailboxId) return;
		fetch(`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/dmarc/rollup`)
			.then((r) => r.json() as Promise<DmarcRollup>)
			.then((r) => setRollup(r))
			.catch((e) => console.error("dmarc rollup fetch failed", e));
	}, [mailboxId]);

	const domains = useMemo(() => {
		if (!reports) return [];
		const set = new Set(reports.map((r) => r.domain));
		return Array.from(set).sort();
	}, [reports]);

	function handleDownloadCsv() {
		if (!sources || sources.length === 0) return;
		const blob = new Blob([sourcesToCsv(sources)], { type: "text/csv;charset=utf-8;" });
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = `dmarc-sources-${domain ?? "export"}.csv`;
		a.click();
		URL.revokeObjectURL(url);
	}

	async function toggleLegitimate(source: DmarcSource) {
		if (!mailboxId) return;
		setTogglingIp(source.source_ip);
		try {
			await fetch(
				`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/dmarc/sources/${encodeURIComponent(source.source_ip)}`,
				{
					method: "PATCH",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ legitimate: source.legitimate === 0 }),
				},
			);
			setSources((prev) =>
				prev
					? prev.map((s) =>
							s.source_ip === source.source_ip
								? { ...s, legitimate: source.legitimate === 0 ? 1 : 0 }
								: s,
					  )
					: prev,
			);
		} catch (e) {
			console.error("toggle legitimate failed", e);
		} finally {
			setTogglingIp(null);
		}
	}

	if (!reports) {
		return <div className="flex justify-center py-20"><Loader size="lg" /></div>;
	}

	if (reports.length === 0) {
		return (
			<div className="max-w-3xl px-4 py-6 md:px-8">
				<h1 className="pp-serif text-ink mb-4">DMARC Reports</h1>
				<div className="rounded-lg border border-line p-6 text-ink-3">
					No DMARC reports received yet. Publish <code>rua=mailto:dmarc-reports@your-domain</code>
					in your domain's DMARC record to start receiving them.
				</div>
			</div>
		);
	}

	const activePolicyReport = reports.find((r) => !domain || r.domain === domain);
	const displayedSources = sources
		? showUnknownOnly
			? sources.filter((s) => s.legitimate === 0)
			: sources
		: null;

	return (
		<div className="max-w-5xl px-4 py-6 md:px-8 h-full overflow-y-auto">
			<h1 className="pp-serif text-ink mb-4">DMARC Reports</h1>

			{rollup && rollup.domains.length > 1 && (
				<section className="mb-8">
					<h2 className="text-sm font-semibold text-ink mb-1">All-domain rollup</h2>
					<p className="text-xs text-ink-3 mb-3">
						Ingested RUA data · last {rollup.window_days} days · sorted by worst alignment first
					</p>
					<div className="overflow-x-auto rounded-lg border border-line">
						<table className="w-full text-sm">
							<thead className="bg-paper-3 text-ink-3 text-xs uppercase">
								<tr>
									<th className="text-left px-3 py-2">Domain</th>
									<th className="text-right px-3 py-2">Messages</th>
									<th className="text-right px-3 py-2">Aligned</th>
									<th className="text-right px-3 py-2">Failing</th>
									<th className="text-left px-3 py-2">Alignment rate</th>
								</tr>
							</thead>
							<tbody>
								{rollup.domains.map((row) => {
									const rate = row.total > 0 ? row.aligned / row.total : 0;
									const isBad = rate < 0.5 && row.total >= 5;
									return (
										<tr
											key={row.domain}
											className={`border-t border-line cursor-pointer hover:bg-paper-3 transition-colors ${isBad ? "bg-paper-3" : ""}`}
											onClick={() => setDomain(row.domain)}
											title={`View ${row.domain} in detail below`}
										>
											<td className="px-3 py-2 font-mono text-ink">{row.domain}</td>
											<td className="px-3 py-2 text-right">{row.total}</td>
											<td className="px-3 py-2 text-right text-safe">{row.aligned}</td>
											<td className="px-3 py-2 text-right text-danger">{row.failing}</td>
											<td className="px-3 py-2">
												<span className={isBad ? "text-danger" : "text-ink"}>
													{Math.round(rate * 100)}%
												</span>
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>
				</section>
			)}

			<div className="mb-6 flex items-center gap-4 flex-wrap">
				<div className="flex items-center gap-2">
					<label className="text-sm text-ink-3">Domain:</label>
					<select
						value={domain ?? ""}
						onChange={(e) => setDomain(e.target.value)}
						className="rounded border border-line bg-paper-3 px-2 py-1 text-sm"
					>
						{domains.map((d) => <option key={d} value={d}>{d}</option>)}
					</select>
				</div>
				<div className="flex items-center gap-2">
					<label className="text-sm text-ink-3">Range:</label>
					<div className="flex rounded border border-line overflow-hidden text-sm">
						{RANGE_PRESETS.map((d) => (
							<button
								key={d}
								type="button"
								onClick={() => setDays(d)}
								className={`px-3 py-1 ${days === d ? "bg-accent text-white" : "bg-paper-3 text-ink hover:bg-paper-2"}`}
							>
								{d}d
							</button>
						))}
					</div>
				</div>
			</div>

			{activePolicyReport && (activePolicyReport.policy_adkim || activePolicyReport.policy_aspf || activePolicyReport.policy_sp || activePolicyReport.policy_pct) && (
				<div className="mb-6 flex flex-wrap gap-3">
					{activePolicyReport.policy_adkim && (
						<span className="inline-flex items-center gap-1 rounded-full border border-line bg-paper-3 px-2 py-0.5 text-xs text-ink-3">
							<span className="font-medium text-ink">adkim</span>={activePolicyReport.policy_adkim}
						</span>
					)}
					{activePolicyReport.policy_aspf && (
						<span className="inline-flex items-center gap-1 rounded-full border border-line bg-paper-3 px-2 py-0.5 text-xs text-ink-3">
							<span className="font-medium text-ink">aspf</span>={activePolicyReport.policy_aspf}
						</span>
					)}
					{activePolicyReport.policy_sp && (
						<span className="inline-flex items-center gap-1 rounded-full border border-line bg-paper-3 px-2 py-0.5 text-xs text-ink-3">
							<span className="font-medium text-ink">sp</span>={activePolicyReport.policy_sp}
						</span>
					)}
					{activePolicyReport.policy_pct && (
						<span className="inline-flex items-center gap-1 rounded-full border border-line bg-paper-3 px-2 py-0.5 text-xs text-ink-3">
							<span className="font-medium text-ink">pct</span>={activePolicyReport.policy_pct}%
						</span>
					)}
				</div>
			)}

			<section className="mb-8">
				<div className="flex items-center justify-between mb-3">
					<h2 className="text-sm font-semibold text-ink">Sending sources</h2>
					{sources && sources.length > 0 && (
						<div className="flex items-center gap-3">
							<label className="flex items-center gap-2 text-sm text-ink-3 cursor-pointer">
								<input
									type="checkbox"
									checked={showUnknownOnly}
									onChange={(e) => setShowUnknownOnly(e.target.checked)}
									className="rounded"
								/>
								Show only unknown sources
							</label>
							<button
								type="button"
								onClick={handleDownloadCsv}
								className="text-xs px-2 py-1 rounded border border-line bg-paper-3 hover:bg-paper-2 text-ink-2"
							>
								Download CSV
							</button>
						</div>
					)}
				</div>
				{!displayedSources ? (
					<div className="text-ink-3 text-sm">Loading…</div>
				) : displayedSources.length === 0 ? (
					<div className="text-ink-3 text-sm">
						{showUnknownOnly && sources && sources.length > 0
							? "No unknown sources — all sources marked legitimate."
							: "No records for this domain."}
					</div>
				) : (
					<div className="overflow-x-auto rounded-lg border border-line">
						<table className="w-full text-sm">
							<thead className="bg-paper-3 text-ink-3 text-xs uppercase">
								<tr>
									<th className="text-left px-3 py-2">Source IP</th>
									<th className="text-left px-3 py-2">Source</th>
									<th className="text-right px-3 py-2">Messages</th>
									<th className="text-right px-3 py-2">Pass</th>
									<th className="text-right px-3 py-2">Quarantine</th>
									<th className="text-right px-3 py-2">Reject</th>
									<th className="text-left px-3 py-2">Pass rate</th>
									<th className="text-left px-3 py-2">Status</th>
								</tr>
							</thead>
							<tbody>
								{displayedSources.map((s) => {
									const rate = s.total_count > 0 ? s.pass_count / s.total_count : 0;
									const suspect = rate < 0.5 && s.total_count >= 5;
									const isSelected = selectedIp === s.source_ip;
									const isUnknown = s.legitimate === 0;
									const isToggling = togglingIp === s.source_ip;
									return (
										<tr
											key={s.source_ip}
											className={`border-t border-line cursor-pointer hover:bg-paper-2 ${suspect ? "bg-paper-3" : ""} ${isSelected ? "ring-1 ring-inset ring-accent" : ""}`}
											onClick={() => setSelectedIp(isSelected ? null : s.source_ip)}
										>
											<td className="px-3 py-2 font-mono text-ink">{s.source_ip}</td>
											<td className="px-3 py-2 text-ink-3">{s.label ?? s.source_ip}</td>
											<td className="px-3 py-2 text-right">{s.total_count}</td>
											<td className="px-3 py-2 text-right text-safe">{s.pass_count}</td>
											<td className="px-3 py-2 text-right text-suspect">{s.quarantine_count}</td>
											<td className="px-3 py-2 text-right text-danger">{s.reject_count}</td>
											<td className="px-3 py-2">
												<span className={suspect ? "text-danger" : "text-ink"}>
													{Math.round(rate * 100)}%
												</span>
											</td>
											<td className="px-3 py-2">
												<div className="flex items-center gap-2">
													{isUnknown ? (
														<span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400">
															Shadow IT / Unknown
														</span>
													) : (
														<span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
															Legitimate
														</span>
													)}
													<button
														onClick={() => toggleLegitimate(s)}
														disabled={isToggling}
														className="text-xs text-ink-3 hover:text-ink underline disabled:opacity-50"
													>
														{isToggling ? "…" : isUnknown ? "Mark legitimate" : "Mark unknown"}
													</button>
												</div>
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>
				)}
			</section>

			{selectedIp && (
				<section className="mb-8 rounded-lg border border-line p-4">
					<div className="flex items-center justify-between mb-3">
						<h2 className="text-sm font-semibold text-ink">
							Auth results for <span className="font-mono">{selectedIp}</span>
						</h2>
						<button
							type="button"
							onClick={() => setSelectedIp(null)}
							className="text-xs text-ink-3 hover:text-ink"
						>
							✕ Close
						</button>
					</div>
					{drillDownLoading ? (
						<div className="text-ink-3 text-sm">Loading…</div>
					) : !drillDown || drillDown.length === 0 ? (
						<div className="text-ink-3 text-sm">No detail records found.</div>
					) : (
						<div className="space-y-3">
							{drillDown.map((entry, i) => (
								<div key={`${entry.report_id}-${i}`} className="rounded border border-line p-3 text-xs">
									<div className="flex flex-wrap gap-3 mb-2 text-ink-3">
										{entry.org_name && <span>Reporter: <span className="text-ink">{entry.org_name}</span></span>}
										{entry.date_range_begin && (
											<span>
												Period: <span className="text-ink">
													{new Date(Number(entry.date_range_begin) * 1000).toLocaleDateString()} – {new Date(Number(entry.date_range_end) * 1000).toLocaleDateString()}
												</span>
											</span>
										)}
										<span>Messages: <span className="text-ink">{entry.count}</span></span>
										{entry.disposition && <span>Disposition: <span className={entry.disposition === "none" ? "text-safe" : "text-danger"}>{entry.disposition}</span></span>}
									</div>
									{entry.auth_results && (
										<div className="flex flex-wrap gap-4">
											{entry.auth_results.dkim.length > 0 && (
												<div>
													<div className="font-medium text-ink-3 mb-1">DKIM</div>
													{entry.auth_results.dkim.map((d, j) => (
														<div key={j} className="font-mono text-ink">
															{d.domain}{d.selector ? `/${d.selector}` : ""}&nbsp;
															<span className={d.result === "pass" ? "text-safe" : "text-danger"}>{d.result}</span>
														</div>
													))}
												</div>
											)}
											{entry.auth_results.spf.length > 0 && (
												<div>
													<div className="font-medium text-ink-3 mb-1">SPF</div>
													{entry.auth_results.spf.map((s, j) => (
														<div key={j} className="font-mono text-ink">
															{s.domain}&nbsp;
															<span className={s.result === "pass" ? "text-safe" : "text-danger"}>{s.result}</span>
														</div>
													))}
												</div>
											)}
										</div>
									)}
								</div>
							))}
						</div>
					)}
				</section>
			)}

			<section>
				<h2 className="text-sm font-semibold text-ink mb-3">Recent reports</h2>
				<div className="overflow-x-auto rounded-lg border border-line">
					<table className="w-full text-sm">
						<thead className="bg-paper-3 text-ink-3 text-xs uppercase">
							<tr>
								<th className="text-left px-3 py-2">Received</th>
								<th className="text-left px-3 py-2">Reporter</th>
								<th className="text-left px-3 py-2">Domain</th>
								<th className="text-left px-3 py-2">Policy</th>
							</tr>
						</thead>
						<tbody>
							{reports.filter((r) => !domain || r.domain === domain).map((r) => (
								<tr key={r.id} className="border-t border-line">
									<td className="px-3 py-2 text-ink-3">{new Date(r.received_at).toLocaleString()}</td>
									<td className="px-3 py-2">{r.org_name ?? "unknown"}</td>
									<td className="px-3 py-2 font-mono">{r.domain}</td>
									<td className="px-3 py-2">{r.policy_p ?? "none"}</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			</section>
		</div>
	);
}
