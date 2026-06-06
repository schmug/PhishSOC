// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Loader } from "@cloudflare/kumo";
import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router";

// ⚡ Bolt: Cache Intl.DateTimeFormat instance to prevent expensive instantiations
// inside loops (e.g. mapping over table rows).
// We use the default options for toLocaleString (date and time) by specifying both.
const defaultDateTimeFormatter = new Intl.DateTimeFormat(undefined, {
	year: "numeric",
	month: "numeric",
	day: "numeric",
	hour: "numeric",
	minute: "numeric",
	second: "numeric",
});

interface TlsRptReport {
	id: string;
	received_at: string;
	org_name: string | null;
	domain: string;
	date_range_begin: string | null;
	date_range_end: string | null;
	contact_info: string | null;
}

interface TlsRptSource {
	sending_mta_ip: string | null;
	receiving_mx_hostname: string | null;
	successful_session_count: number;
	failed_session_count: number;
	first_seen: string;
	last_seen: string;
}

interface TlsRptFailure {
	result_type: string;
	failed_session_count: number;
}

/**
 * TLS-RPT (RFC 8460) inbound report dashboard. Shows per-MTA session
 * counts and per-result-type failure rollups for the selected domain
 * over all ingested reports.
 */
export default function TlsRptRoute() {
	const { mailboxId } = useParams<{ mailboxId: string }>();
	const [reports, setReports] = useState<TlsRptReport[] | null>(null);
	const [domain, setDomain] = useState<string | null>(null);
	const [sources, setSources] = useState<TlsRptSource[] | null>(null);
	const [failures, setFailures] = useState<TlsRptFailure[] | null>(null);

	useEffect(() => {
		if (!mailboxId) return;
		fetch(
			`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/tlsrpt/reports?limit=100`,
		)
			.then((r) => r.json() as Promise<{ reports: TlsRptReport[] }>)
			.then((r) => {
				setReports(r.reports);
				if (r.reports.length > 0 && !domain) setDomain(r.reports[0].domain);
			})
			.catch((e) => console.error("tlsrpt reports fetch failed", e));
	}, [mailboxId, domain]);

	useEffect(() => {
		if (!mailboxId || !domain) return;
		fetch(
			`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/tlsrpt/summary?domain=${encodeURIComponent(domain)}`,
		)
			.then(
				(r) =>
					r.json() as Promise<{
						sources: TlsRptSource[];
						failures: TlsRptFailure[];
					}>,
			)
			.then((r) => {
				setSources(r.sources);
				setFailures(r.failures);
			})
			.catch((e) => console.error("tlsrpt summary fetch failed", e));
	}, [mailboxId, domain]);

	const domains = useMemo(() => {
		if (!reports) return [];
		const set = new Set(reports.map((r) => r.domain));
		return Array.from(set).sort();
	}, [reports]);

	if (!reports) {
		return (
			<div className="flex justify-center py-20">
				<Loader size="lg" />
			</div>
		);
	}

	if (reports.length === 0) {
		return (
			<div className="max-w-3xl px-4 py-6 md:px-8">
				<h1 className="pp-serif text-ink mb-4">TLS-RPT Reports</h1>
				<div className="rounded-lg border border-line p-6 text-ink-3">
					No TLS-RPT reports received yet. Publish{" "}
					<code>v=TLSRPTv1; rua=mailto:tlsrpt@your-domain</code> in your
					domain's <code>_smtp._tls</code> TXT record to start receiving them.
				</div>
			</div>
		);
	}

	return (
		<div className="max-w-5xl px-4 py-6 md:px-8 h-full overflow-y-auto">
			<h1 className="pp-serif text-ink mb-4">TLS-RPT Reports</h1>

			<div className="mb-6 flex items-center gap-3">
				<label className="text-sm text-ink-3">Domain:</label>
				<select
					value={domain ?? ""}
					onChange={(e) => setDomain(e.target.value)}
					className="rounded border border-line bg-paper-3 px-2 py-1 text-sm"
				>
					{domains.map((d) => (
						<option key={d} value={d}>
							{d}
						</option>
					))}
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
									<th className="text-left px-3 py-2">Sending MTA IP</th>
									<th className="text-left px-3 py-2">Receiving MX</th>
									<th className="text-right px-3 py-2">Successful</th>
									<th className="text-right px-3 py-2">Failed</th>
									<th className="text-left px-3 py-2">Success rate</th>
								</tr>
							</thead>
							<tbody>
								{sources.map((s) => {
									const total =
										s.successful_session_count + s.failed_session_count;
									const rate =
										total > 0 ? s.successful_session_count / total : 0;
									const suspect = rate < 0.5 && total >= 5;
									const ipLabel = s.sending_mta_ip ?? "(policy summary)";
									const mxLabel = s.receiving_mx_hostname ?? "—";
									return (
										<tr
											key={`${s.sending_mta_ip ?? "summary"}|${s.receiving_mx_hostname ?? "any"}`}
											className={`border-t border-line ${suspect ? "bg-paper-3" : ""}`}
										>
											<td className="px-3 py-2 font-mono text-ink">
												{ipLabel}
											</td>
											<td className="px-3 py-2 font-mono text-ink-2">
												{mxLabel}
											</td>
											<td className="px-3 py-2 text-right text-safe">
												{s.successful_session_count}
											</td>
											<td className="px-3 py-2 text-right text-danger">
												{s.failed_session_count}
											</td>
											<td className="px-3 py-2">
												<span className={suspect ? "text-danger" : "text-ink"}>
													{total === 0 ? "—" : `${Math.round(rate * 100)}%`}
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

			{failures && failures.length > 0 && (
				<section className="mb-8">
					<h2 className="text-sm font-semibold text-ink mb-3">Failure types</h2>
					<div className="overflow-x-auto rounded-lg border border-line">
						<table className="w-full text-sm">
							<thead className="bg-paper-3 text-ink-3 text-xs uppercase">
								<tr>
									<th className="text-left px-3 py-2">Result type</th>
									<th className="text-right px-3 py-2">Failed sessions</th>
								</tr>
							</thead>
							<tbody>
								{failures.map((f) => (
									<tr key={f.result_type} className="border-t border-line">
										<td className="px-3 py-2 font-mono text-ink">
											{f.result_type}
										</td>
										<td className="px-3 py-2 text-right text-danger">
											{f.failed_session_count}
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
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
								<th className="text-left px-3 py-2">Contact</th>
							</tr>
						</thead>
						<tbody>
							{reports
								.filter((r) => !domain || r.domain === domain)
								.map((r) => (
									<tr key={r.id} className="border-t border-line">
										<td className="px-3 py-2 text-ink-3">
											{defaultDateTimeFormatter.format(
												Date.parse(r.received_at),
											)}
										</td>
										<td className="px-3 py-2">{r.org_name ?? "unknown"}</td>
										<td className="px-3 py-2 font-mono">{r.domain}</td>
										<td className="px-3 py-2 text-ink-3">
											{r.contact_info ?? "—"}
										</td>
									</tr>
								))}
						</tbody>
					</table>
				</div>
			</section>
		</div>
	);
}
