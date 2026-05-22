// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Input, Loader, Select } from "@cloudflare/kumo";
import { useState } from "react";
import Shell from "~/components/phishsoc/Shell";
import { useOrgAclOverview } from "~/queries/org";

export function meta() {
	return [{ title: "Access Overview · PhishSOC" }];
}

function domainOf(email: string): string {
	const at = email.indexOf("@");
	return at >= 0 ? email.slice(at + 1) : email;
}

export default function OrgAclRoute() {
	const { data: rows = [], isLoading } = useOrgAclOverview();

	const domains = Array.from(new Set(rows.map((r) => domainOf(r.email)))).sort();
	const [filterDomain, setFilterDomain] = useState("__all__");
	const [filterText, setFilterText] = useState("");

	const filtered = rows.filter((r) => {
		if (filterDomain !== "__all__" && domainOf(r.email) !== filterDomain) return false;
		if (filterText) {
			const q = filterText.toLowerCase();
			const inEmail = r.email.toLowerCase().includes(q);
			const inOwner = r.owner?.toLowerCase().includes(q) ?? false;
			const inMembers = r.members.some((m) => m.toLowerCase().includes(q));
			if (!inEmail && !inOwner && !inMembers) return false;
		}
		return true;
	});

	const scopedCount = rows.filter((r) => r.acl_status === "scoped").length;
	const unscopedCount = rows.filter((r) => r.acl_status === "unscoped").length;

	return (
		<Shell>
			<div className="max-w-5xl mx-auto px-4 py-8 space-y-6">
				<div>
					<h1 className="text-xl font-semibold text-ink">Access Overview</h1>
					<p className="text-sm text-subtle mt-1">
						All mailboxes and their access grants. Any authenticated user in your
						Cloudflare Access policy can view this page — this is intentional (no
						org-admin role exists; the Access policy is the org boundary).
					</p>
				</div>

				{isLoading ? (
					<div className="flex items-center justify-center py-16">
						<Loader />
					</div>
				) : (
					<>
						<div className="flex items-center gap-4 flex-wrap">
							<p className="text-sm text-subtle">
								{rows.length} mailbox{rows.length !== 1 ? "es" : ""}
								{" · "}
								<span className="text-green-600">{scopedCount} scoped</span>
								{unscopedCount > 0 && (
									<>
										{" · "}
										<span className="text-amber-600">{unscopedCount} unscoped</span>
									</>
								)}
							</p>
						</div>

						<div className="flex items-center gap-3 flex-wrap">
							{domains.length > 1 && (
								<Select
									value={filterDomain}
									onValueChange={(v) => { if (v) setFilterDomain(v); }}
									aria-label="Filter by domain"
								>
									<Select.Option value="__all__">All domains</Select.Option>
									{domains.map((d) => (
										<Select.Option key={d} value={d}>
											{d}
										</Select.Option>
									))}
								</Select>
							)}
							<Input
								placeholder="Filter by email or member…"
								aria-label="Filter mailboxes"
								value={filterText}
								onChange={(e) => setFilterText(e.target.value)}
							/>
						</div>

						{filtered.length === 0 ? (
							<p className="text-sm text-subtle py-8 text-center">No mailboxes match the filter.</p>
						) : (
							<div className="overflow-x-auto rounded border border-border">
								<table className="min-w-full text-sm">
									<thead className="bg-surface border-b border-border">
										<tr>
											<th className="text-left px-4 py-2 font-medium text-subtle">Mailbox</th>
											<th className="text-left px-4 py-2 font-medium text-subtle">Status</th>
											<th className="text-left px-4 py-2 font-medium text-subtle">Owner</th>
											<th className="text-left px-4 py-2 font-medium text-subtle">Members</th>
										</tr>
									</thead>
									<tbody className="divide-y divide-border">
										{filtered.map((row) => (
											<tr key={row.email} className="hover:bg-surface/50">
												<td className="px-4 py-2 font-mono text-xs text-ink">{row.email}</td>
												<td className="px-4 py-2">
													{row.acl_status === "scoped" ? (
														<span className="inline-flex items-center rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700">
															Scoped
														</span>
													) : (
														<span className="inline-flex items-center rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-700">
															Unscoped
														</span>
													)}
												</td>
												<td className="px-4 py-2 text-xs text-subtle">
													{row.owner ?? <span className="italic text-muted">—</span>}
												</td>
												<td className="px-4 py-2 text-xs text-subtle">
													{row.members.length === 0 ? (
														<span className="italic text-muted">none</span>
													) : (
														<ul className="space-y-0.5">
															{row.members.map((m) => (
																<li key={m}>{m}</li>
															))}
														</ul>
													)}
												</td>
											</tr>
										))}
									</tbody>
								</table>
							</div>
						)}
					</>
				)}
			</div>
		</Shell>
	);
}
