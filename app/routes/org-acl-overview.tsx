// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Badge, Input, Loader } from "@cloudflare/kumo";
import { WarningIcon } from "@phosphor-icons/react";
import { useMemo, useState } from "react";
import Shell from "~/components/phishsoc/Shell";
import { useOrgAclOverview } from "~/queries/mailboxes";

export function meta() {
	return [{ title: "Access overview · PhishSOC" }];
}

type AclEntry = {
	email: string;
	acl_status: "scoped" | "unscoped";
	owner: string | null;
	members: string[];
};

function domainOf(email: string): string {
	const at = email.indexOf("@");
	return at >= 0 ? email.slice(at + 1) : email;
}

export default function OrgAclOverviewRoute() {
	const { data, isLoading, isError } = useOrgAclOverview();
	const [filter, setFilter] = useState("");

	const entries: AclEntry[] = data?.mailboxes ?? [];

	const visible = useMemo(() => {
		const q = filter.trim().toLowerCase();
		if (!q) return entries;
		return entries.filter(
			(e) =>
				e.email.toLowerCase().includes(q) ||
				(e.owner ?? "").toLowerCase().includes(q) ||
				e.members.some((m) => m.toLowerCase().includes(q)),
		);
	}, [entries, filter]);

	const grouped = useMemo(() => {
		const map = new Map<string, AclEntry[]>();
		for (const entry of visible) {
			const d = domainOf(entry.email);
			const bucket = map.get(d) ?? [];
			bucket.push(entry);
			map.set(d, bucket);
		}
		return Array.from(map.entries()).sort(([a], [b]) => a.localeCompare(b));
	}, [visible]);

	const unscopedCount = entries.filter((e) => e.acl_status === "unscoped").length;

	return (
		<Shell>
			<div className="p-6 max-w-5xl mx-auto">
				<div className="flex items-center justify-between mb-4 gap-4">
					<div>
						<h1 className="text-xl font-semibold">Access overview</h1>
						<p className="text-sm text-gray-500 mt-1">
							Who can access which mailboxes across the org.
						</p>
					</div>
					{!isLoading && unscopedCount > 0 && (
						<div className="flex items-center gap-1.5 text-amber-600 text-sm">
							<WarningIcon size={16} />
							<span>{unscopedCount} unscoped {unscopedCount === 1 ? "mailbox" : "mailboxes"}</span>
						</div>
					)}
				</div>

				<div className="mb-4 max-w-xs">
					<Input
						type="text"
						placeholder="Filter by mailbox, owner, or member…"
						value={filter}
						onChange={(e) => setFilter(e.target.value)}
					/>
				</div>

				{isLoading && (
					<div className="flex justify-center py-12">
						<Loader />
					</div>
				)}

				{isError && (
					<p className="text-red-500 text-sm py-4">Failed to load access overview.</p>
				)}

				{!isLoading && !isError && grouped.length === 0 && (
					<p className="text-gray-500 text-sm py-4">
						{filter ? "No mailboxes match the filter." : "No mailboxes found."}
					</p>
				)}

				{!isLoading && !isError && grouped.map(([domain, domainEntries]) => (
					<div key={domain} className="mb-6">
						<h2 className="text-xs font-semibold uppercase tracking-wide text-gray-400 mb-2">
							{domain}
						</h2>
						<table className="w-full text-sm border-collapse">
							<thead>
								<tr className="border-b border-gray-200">
									<th className="text-left py-2 pr-4 font-medium text-gray-600 w-1/3">Mailbox</th>
									<th className="text-left py-2 pr-4 font-medium text-gray-600 w-20">Access</th>
									<th className="text-left py-2 pr-4 font-medium text-gray-600 w-1/4">Owner</th>
									<th className="text-left py-2 font-medium text-gray-600">Members</th>
								</tr>
							</thead>
							<tbody>
								{domainEntries.map((entry) => (
									<tr key={entry.email} className="border-b border-gray-100 hover:bg-gray-50">
										<td className="py-2 pr-4 font-mono text-xs">{entry.email}</td>
										<td className="py-2 pr-4">
											{entry.acl_status === "unscoped" ? (
												<Badge variant="destructive">Unscoped</Badge>
											) : (
												<Badge variant="success">Scoped</Badge>
											)}
										</td>
										<td className="py-2 pr-4 text-gray-700">
											{entry.owner
												? entry.owner
												: <span className="text-gray-400 italic">—</span>}
										</td>
										<td className="py-2 text-gray-600">
											{entry.members.length === 0 ? (
												<span className="text-gray-400 italic">—</span>
											) : (
												entry.members.join(", ")
											)}
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				))}
			</div>
		</Shell>
	);
}
