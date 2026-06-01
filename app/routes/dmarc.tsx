// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Loader } from "@cloudflare/kumo";
import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router";

interface DmarcReport {
	id: string;
	received_at: string;
	org_name: string | null;
	domain: string;
	date_range_begin: string | null;
	date_range_end: string | null;
	policy_p: string | null;
	policy_adkim: string | null;
	policy_aspf: string | null;
	policy_sp: string | null;
	policy_pct: string | null;
}

interface DmarcSource {
	source_ip: string;
	total_count: number;
	pass_count: number;
	quarantine_count: number;
	reject_count: number;
	first_seen: string;
	last_seen: string;
}

interface AuthDkimResult {
	domain?: string;
	selector?: string;
	result?: string;
}

interface AuthSpfResult {
	domain?: string;
	result?: string;
}

interface AuthResults {
	dkim: AuthDkimResult[];
	spf: AuthSpfResult[];
}

interface DmarcRecord {
	id: string;
	source_ip: string;
	count: number;
	disposition: string | null;
	dkim_result: string | null;
	spf_result: string | null;
	header_from: string | null;
	auth_results: AuthResults | null;
}

/**
 * DMARC aggregate-report dashboard. Shows legitimate vs forged sending
 * sources for a domain over the last 90 days of ingested reports.
 */
export default function DmarcRoute() {
	const { mailboxId } = useParams<{ mailboxId: string }>();
	const [reports, setReports] = useState<DmarcReport[] | null>(null);
	const [domain, setDomain] = useState<string | null>(null);
	const [sources, setSources] = useState<DmarcSource[] | null>(null);
	const [selectedReport, setSelectedReport] = useState<DmarcReport | null>(null);
	const [drillRecords, setDrillRecords] = useState<DmarcRecord[] | null>(null);
	const [drillLoading, setDrillLoading] = useState(false);

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
		fetch(`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/dmarc/summary?domain=${encodeURIComponent(domain)}`)
			.then((r) => r.json() as Promise<{ sources: DmarcSource[] }>)
			.then((r) => setSources(r.sources))
			.catch((e) => console.error("dmarc summary fetch failed", e));
	}, [mailboxId, domain]);

	function openDrill(report: DmarcReport) {
		if (selectedReport?.id === report.id) {
			setSelectedReport(null);
			setDrillRecords(null);
			return;
		}
		setSelectedReport(report);
		setDrillRecords(null);
		setDrillLoading(true);
		fetch(`/api/v1/mailboxes/${encodeURIComponent(mailboxId!)}/dmarc/reports/${encodeURIComponent(report.id)}/records`)
			.then((r) => r.json() as Promise<{ records: DmarcRecord[] }>)
			.then((r) => { setDrillRecords(r.records); setDrillLoading(false); })
			.catch((e) => { console.error("dmarc records fetch failed", e); setDrillLoading(false); });
	}

	const domains = useMemo(() => {
		if (!reports) return [];
		const set = new Set(reports.map((r) => r.domain));
		return Array.from(set).sort();
	}, [reports]);

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

	const filteredReports = reports.filter((r) => !domain || r.domain === domain);

	return (
		<div className="max-w-5xl px-4 py-6 md:px-8 h-full overflow-y-auto">
			<h1 className="pp-serif text-ink mb-4">DMARC Reports</h1>

			<div className="mb-6 flex items-center gap-3">
				<label className="text-sm text-ink-3">Domain:</label>
				<select
					value={domain ?? ""}
					onChange={(e) => { setDomain(e.target.value); setSelectedReport(null); setDrillRecords(null); }}
					className="rounded border border-line bg-paper-3 px-2 py-1 text-sm"
				>
					{domains.map((d) => <option key={d} value={d}>{d}</option>)}
				</select>
			</div>

			<section className="mb-8">
				<h2 className="text-sm font-semibold text-ink mb-3">Sending sources</h2>
				{!sources ? (
					<div className="text-ink-3 text-sm">Loading…</div>
				) : sources.length === 0 ? (
					<div className="text-ink-3 text-sm">No records for this domain.</div>
				) : (
					<div className="overflow-x-auto rounded-lg border border-line">
						<table className="w-full text-sm">
							<thead className="bg-paper-3 text-ink-3 text-xs uppercase">
								<tr>
									<th className="text-left px-3 py-2">Source IP</th>
									<th className="text-right px-3 py-2">Messages</th>
									<th className="text-right px-3 py-2">Pass</th>
									<th className="text-right px-3 py-2">Quarantine</th>
									<th className="text-right px-3 py-2">Reject</th>
									<th className="text-left px-3 py-2">Pass rate</th>
								</tr>
							</thead>
							<tbody>
								{sources.map((s) => {
									const rate = s.total_count > 0 ? s.pass_count / s.total_count : 0;
									const suspect = rate < 0.5 && s.total_count >= 5;
									return (
										<tr key={s.source_ip} className={`border-t border-line ${suspect ? "bg-paper-3" : ""}`}>
											<td className="px-3 py-2 font-mono text-ink">{s.source_ip}</td>
											<td className="px-3 py-2 text-right">{s.total_count}</td>
											<td className="px-3 py-2 text-right text-safe">{s.pass_count}</td>
											<td className="px-3 py-2 text-right text-suspect">{s.quarantine_count}</td>
											<td className="px-3 py-2 text-right text-danger">{s.reject_count}</td>
											<td className="px-3 py-2">
												<span className={suspect ? "text-danger" : "text-ink"}>
													{Math.round(rate * 100)}%
												</span>
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>
				)}
			</section>

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
								<th className="text-left px-3 py-2">adkim / aspf</th>
								<th className="text-left px-3 py-2">sp / pct</th>
							</tr>
						</thead>
						<tbody>
							{filteredReports.map((r) => (
								<tr
									key={r.id}
									className={`border-t border-line cursor-pointer hover:bg-paper-3 ${selectedReport?.id === r.id ? "bg-paper-3" : ""}`}
									onClick={() => openDrill(r)}
								>
									<td className="px-3 py-2 text-ink-3">{new Date(r.received_at).toLocaleString()}</td>
									<td className="px-3 py-2">{r.org_name ?? "unknown"}</td>
									<td className="px-3 py-2 font-mono">{r.domain}</td>
									<td className="px-3 py-2">{r.policy_p ?? "none"}</td>
									<td className="px-3 py-2 text-ink-3">{r.policy_adkim ?? "—"} / {r.policy_aspf ?? "—"}</td>
									<td className="px-3 py-2 text-ink-3">{r.policy_sp ?? "—"} / {r.policy_pct != null ? `${r.policy_pct}%` : "—"}</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>

				{selectedReport && (
					<div className="mt-4 rounded-lg border border-line p-4">
						<div className="flex items-center justify-between mb-3">
							<h3 className="text-sm font-semibold text-ink">
								Source detail — {selectedReport.org_name ?? "unknown"}{" "}
								<span className="font-normal text-ink-3">
									({selectedReport.domain}, policy: {selectedReport.policy_p ?? "none"})
								</span>
							</h3>
							<button
								className="text-xs text-ink-3 hover:text-ink"
								onClick={() => { setSelectedReport(null); setDrillRecords(null); }}
							>
								✕ close
							</button>
						</div>

						{drillLoading ? (
							<div className="text-ink-3 text-sm">Loading…</div>
						) : drillRecords && drillRecords.length === 0 ? (
							<div className="text-ink-3 text-sm">No records for this report.</div>
						) : drillRecords ? (
							<div className="overflow-x-auto">
								<table className="w-full text-xs">
									<thead className="bg-paper-3 text-ink-3 uppercase">
										<tr>
											<th className="text-left px-2 py-1">Source IP</th>
											<th className="text-right px-2 py-1">Count</th>
											<th className="text-left px-2 py-1">Disposition</th>
											<th className="text-left px-2 py-1">DKIM auth</th>
											<th className="text-left px-2 py-1">SPF auth</th>
										</tr>
									</thead>
									<tbody>
										{drillRecords.map((rec) => (
											<tr key={rec.id} className="border-t border-line">
												<td className="px-2 py-1 font-mono">{rec.source_ip}</td>
												<td className="px-2 py-1 text-right">{rec.count}</td>
												<td className="px-2 py-1">{rec.disposition ?? "—"}</td>
												<td className="px-2 py-1">
													{rec.auth_results?.dkim && rec.auth_results.dkim.length > 0 ? (
														<div className="space-y-0.5">
															{rec.auth_results.dkim.map((d, i) => (
																<div key={i} className="font-mono">
																	{d.domain ?? "?"}{d.selector ? `·${d.selector}` : ""}{" "}
																	<span className={d.result === "pass" ? "text-safe" : "text-danger"}>
																		{d.result ?? "?"}
																	</span>
																</div>
															))}
														</div>
													) : <span className="text-ink-3">—</span>}
												</td>
												<td className="px-2 py-1">
													{rec.auth_results?.spf && rec.auth_results.spf.length > 0 ? (
														<div className="space-y-0.5">
															{rec.auth_results.spf.map((s, i) => (
																<div key={i} className="font-mono">
																	{s.domain ?? "?"}{" "}
																	<span className={s.result === "pass" ? "text-safe" : "text-danger"}>
																		{s.result ?? "?"}
																	</span>
																</div>
															))}
														</div>
													) : <span className="text-ink-3">—</span>}
												</td>
											</tr>
										))}
									</tbody>
								</table>
							</div>
						) : null}
					</div>
				)}
			</section>
		</div>
	);
}
