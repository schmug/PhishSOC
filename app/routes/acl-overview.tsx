// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Input, Loader } from "@cloudflare/kumo";
import { useState } from "react";
import Shell from "~/components/phishsoc/Shell";
import { useOrgAclOverview } from "~/queries/org";
import type { OrgAclOverviewEntry } from "~/types";

export function meta() {
	return [{ title: "ACL Overview · PhishSOC" }];
}

function domainOf(email: string): string {
	const idx = email.indexOf("@");
	return idx >= 0 ? email.slice(idx + 1) : email;
}

function groupByDomain(
	entries: OrgAclOverviewEntry[],
): Map<string, OrgAclOverviewEntry[]> {
	const groups = new Map<string, OrgAclOverviewEntry[]>();
	for (const entry of entries) {
		const domain = domainOf(entry.email);
		const bucket = groups.get(domain);
		if (bucket) {
			bucket.push(entry);
		} else {
			groups.set(domain, [entry]);
		}
	}
	return groups;
}

export default function AclOverviewRoute() {
	const { data, isLoading, isError } = useOrgAclOverview();
	const [filter, setFilter] = useState("");

	const filtered = (data ?? []).filter((entry) => {
		const q = filter.trim().toLowerCase();
		if (!q) return true;
		return (
			entry.email.toLowerCase().includes(q) ||
			(entry.owner?.toLowerCase().includes(q) ?? false) ||
			entry.members.some((m) => m.toLowerCase().includes(q))
		);
	});

	const grouped = groupByDomain(filtered);
	const sortedDomains = [...grouped.keys()].sort();

	return (
		<Shell>
			<div className="mx-auto max-w-4xl px-4 py-8 md:px-6 md:py-16">
				<div className="mb-8">
					<h1 className="pp-serif text-[40px] leading-none text-ink">
						ACL Overview
					</h1>
					<p className="text-sm text-ink-3 mt-2">
						Every mailbox with its access-control status, owner, and members.
						Unscoped mailboxes have no ACL and are visible to all admitted users.
					</p>
				</div>

				{isLoading ? (
					<div className="flex justify-center py-20">
						<Loader size="lg" />
					</div>
				) : isError ? (
					<div className="pp-card px-5 py-8 text-center text-sm text-ink-3">
						Failed to load ACL overview.
					</div>
				) : (
					<>
						<div className="mb-6">
							<Input
								placeholder="Filter by email, owner, or member…"
								value={filter}
								onChange={(e) => setFilter(e.target.value)}
								className="max-w-sm"
							/>
						</div>

						{sortedDomains.length === 0 ? (
							<div className="pp-card px-5 py-8 text-center text-sm text-ink-3">
								No mailboxes found.
							</div>
						) : (
							<div className="space-y-8">
								{sortedDomains.map((domain) => {
									const entries = grouped.get(domain)!;
									return (
										<div key={domain}>
											<h2 className="text-sm font-semibold text-ink-3 uppercase tracking-wide mb-3">
												{domain}
											</h2>
											<div className="pp-card overflow-hidden">
												<table className="w-full text-sm">
													<thead>
														<tr className="border-b border-line text-left text-xs text-ink-3">
															<th className="px-4 py-2.5 font-medium">
																Mailbox
															</th>
															<th className="px-4 py-2.5 font-medium">
																Status
															</th>
															<th className="px-4 py-2.5 font-medium">
																Owner
															</th>
															<th className="px-4 py-2.5 font-medium">
																Members
															</th>
														</tr>
													</thead>
													<tbody>
														{entries.map((entry, idx) => (
															<tr
																key={entry.email}
																className={
																	idx > 0
																		? "border-t border-line"
																		: ""
																}
															>
																<td className="px-4 py-3 font-mono text-xs text-ink">
																	{entry.email}
																</td>
																<td className="px-4 py-3">
																	{entry.acl_status === "unscoped" ? (
																		<span className="inline-flex items-center rounded px-1.5 py-0.5 text-[10.5px] font-medium bg-amber-50 text-amber-700 border border-amber-200">
																			Unscoped
																		</span>
																	) : (
																		<span className="inline-flex items-center rounded px-1.5 py-0.5 text-[10.5px] font-medium bg-green-50 text-green-700 border border-green-200">
																			Scoped
																		</span>
																	)}
																</td>
																<td className="px-4 py-3 text-xs text-ink-3 font-mono">
																	{entry.owner ?? (
																		<span className="text-ink-4">—</span>
																	)}
																</td>
																<td className="px-4 py-3">
																	{entry.members.length === 0 ? (
																		<span className="text-xs text-ink-4">
																			—
																		</span>
																	) : (
																		<ul className="space-y-0.5">
																			{entry.members.map((m) => (
																				<li
																					key={m}
																					className="text-xs text-ink-3 font-mono"
																				>
																					{m}
																				</li>
																			))}
																		</ul>
																	)}
																</td>
															</tr>
														))}
													</tbody>
												</table>
											</div>
										</div>
									);
								})}
							</div>
						)}
					</>
				)}
			</div>
		</Shell>
	);
}
