// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Loader } from "@cloudflare/kumo";
import { useQuery } from "@tanstack/react-query";
import Shell from "~/components/phishsoc/Shell";
import api from "~/services/api";

export function meta() {
	return [{ title: "ACL Overview · PhishSOC" }];
}

type AclOverviewEntry = {
	email: string;
	acl_status: "scoped" | "unscoped";
	owner: string | null;
	members: string[];
};

export default function AclOverviewRoute() {
	const { data: entries = [], isLoading } = useQuery<AclOverviewEntry[]>({
		queryKey: ["org", "acl-overview"],
		queryFn: () => api.getAclOverview(),
	});

	// Group by domain (the part after @).
	const byDomain = new Map<string, AclOverviewEntry[]>();
	for (const entry of entries) {
		const domain = entry.email.split("@")[1] ?? entry.email;
		if (!byDomain.has(domain)) byDomain.set(domain, []);
		byDomain.get(domain)!.push(entry);
	}

	const unscopedCount = entries.filter((e) => e.acl_status === "unscoped").length;

	return (
		<Shell>
			<div className="mx-auto max-w-4xl px-4 py-8 md:px-6 md:py-16">
				<div className="mb-8">
					<h1 className="pp-serif text-[40px] leading-none text-ink">ACL Overview</h1>
					<p className="text-sm text-ink-3 mt-1">
						Who can access which mailboxes across your org.
						{unscopedCount > 0 && (
							<>
								{" "}
								<span className="text-amber-600 font-medium">{unscopedCount} unscoped</span>
								{" "}— visible to all admitted users.
							</>
						)}
					</p>
				</div>

				{isLoading ? (
					<div className="flex justify-center py-20">
						<Loader size="lg" />
					</div>
				) : entries.length === 0 ? (
					<p className="text-ink-3 text-sm">No mailboxes found.</p>
				) : (
					<div className="space-y-8">
						{[...byDomain.entries()].map(([domain, mailboxes]) => (
							<div key={domain}>
								<h2 className="text-xs font-semibold text-ink-3 uppercase tracking-wide mb-2">
									{domain}
								</h2>
								<div className="pp-card overflow-hidden">
									<table className="w-full text-sm">
										<thead>
											<tr className="border-b border-line text-xs text-ink-3">
												<th className="px-4 py-2 text-left font-medium">Mailbox</th>
												<th className="px-4 py-2 text-left font-medium">Status</th>
												<th className="px-4 py-2 text-left font-medium">Owner</th>
												<th className="px-4 py-2 text-left font-medium">Members</th>
											</tr>
										</thead>
										<tbody>
											{mailboxes.map((entry, idx) => (
												<tr
													key={entry.email}
													className={idx > 0 ? "border-t border-line" : ""}
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
													<td className="px-4 py-3 text-ink-3 text-xs">
														{entry.owner ?? <span className="opacity-40">—</span>}
													</td>
													<td className="px-4 py-3 text-ink-3 text-xs">
														{entry.members.length === 0 ? (
															<span className="opacity-40">—</span>
														) : (
															entry.members.join(", ")
														)}
													</td>
												</tr>
											))}
										</tbody>
									</table>
								</div>
							</div>
						))}
					</div>
				)}
			</div>
		</Shell>
	);
}
