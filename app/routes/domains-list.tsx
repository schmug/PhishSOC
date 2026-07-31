// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Button, Dialog, Loader, Tooltip } from "@cloudflare/kumo";
import {
	BuildingsIcon,
	PlusIcon,
	TrashIcon,
	WarningIcon,
} from "@phosphor-icons/react";
import { useMemo, useState } from "react";
import { Link as RouterLink } from "react-router";
import Shell from "~/components/phishsoc/Shell";
import { useFeedback } from "~/lib/feedback";
import { useAddDomain, useDomains, useRemoveDomain } from "~/queries/domains";
import type { DomainListEntry } from "~/types";

export function meta() {
	return [{ title: "Domains · PhishSOC" }];
}

type SortKey = "name" | "threatsBlocked24h" | "openCases" | "mailboxesCount";

const SORT_OPTIONS: ReadonlyArray<{ value: SortKey; label: string }> = [
	{ value: "name", label: "Name (A→Z)" },
	{ value: "threatsBlocked24h", label: "Threats blocked · 24h" },
	{ value: "openCases", label: "Open cases" },
	{ value: "mailboxesCount", label: "Mailboxes" },
];

function sortDomains(
	domains: DomainListEntry[],
	key: SortKey,
): DomainListEntry[] {
	const next = [...domains];
	if (key === "name") {
		next.sort((a, b) => a.domain.localeCompare(b.domain));
	} else {
		next.sort((a, b) => b[key] - a[key]);
	}
	return next;
}

function filterDomains(
	domains: DomainListEntry[],
	query: string,
): DomainListEntry[] {
	const q = query.trim().toLowerCase();
	if (q === "") return domains;
	return domains.filter((d) => d.domain.toLowerCase().includes(q));
}

/** Inline validator — rejects empty, protocol-prefixed, path/@ inputs, single-label. */
function isValidRegistrableDomain(d: string): boolean {
	if (!d || d.length > 253) return false;
	if (
		d.includes("://") ||
		d.includes("/") ||
		d.includes("@") ||
		d.includes(" ")
	)
		return false;
	const labels = d.split(".");
	if (labels.length < 2) return false;
	return labels.every((l) => l.length > 0 && /^[a-zA-Z0-9-]+$/.test(l));
}

export default function DomainsListRoute() {
	const feedback = useFeedback();
	const { data, isLoading, isError, refetch } = useDomains();
	const addDomain = useAddDomain();
	const removeDomain = useRemoveDomain();

	const [sortKey, setSortKey] = useState<SortKey>("name");
	const [filter, setFilter] = useState("");
	const [isAddOpen, setIsAddOpen] = useState(false);
	const [domainToDelete, setDomainToDelete] = useState<string | null>(null);

	const visible = useMemo(() => {
		if (!data) return [];
		return sortDomains(filterDomains(data, filter), sortKey);
	}, [data, filter, sortKey]);

	const handleAdd = async (domain: string) => {
		try {
			await addDomain.mutateAsync(domain);
			feedback.success(`${domain} added to available domains`);
			setIsAddOpen(false);
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Failed to add domain";
			throw new Error(msg);
		}
	};

	const handleRemove = async () => {
		if (!domainToDelete) return;
		try {
			await removeDomain.mutateAsync(domainToDelete);
			feedback.info(`${domainToDelete} removed from available domains`);
			setDomainToDelete(null);
		} catch {
			feedback.error("Failed to remove domain");
		}
	};

	return (
		<Shell>
			<div className="px-6 md:px-10 py-8 max-w-[1280px] space-y-6">
				<DomainsHeader
					count={data?.length ?? 0}
					onAddDomain={() => setIsAddOpen(true)}
				/>

				{isLoading ? (
					<div className="flex justify-center py-20">
						<Loader size="lg" />
					</div>
				) : isError ? (
					<DomainsError onRetry={() => refetch()} />
				) : data ? (
					data.length === 0 ? (
						<EmptyDomains onAddDomain={() => setIsAddOpen(true)} />
					) : (
						<>
							<DomainsControls
								sortKey={sortKey}
								onSortKeyChange={setSortKey}
								filter={filter}
								onFilterChange={setFilter}
							/>
							{visible.length === 0 ? (
								<NoDomainsMatch query={filter} onClear={() => setFilter("")} />
							) : (
								<DomainsTable
									domains={visible}
									onRemoveDomain={setDomainToDelete}
								/>
							)}
						</>
					)
				) : null}
			</div>

			<AddDomainDialog
				open={isAddOpen}
				onOpenChange={setIsAddOpen}
				onAdd={handleAdd}
			/>

			<DeleteDomainConfirmDialog
				domain={domainToDelete}
				onConfirm={handleRemove}
				onCancel={() => setDomainToDelete(null)}
			/>
		</Shell>
	);
}

function DomainsHeader({
	count,
	onAddDomain,
}: {
	count: number;
	onAddDomain: () => void;
}) {
	return (
		<div className="flex items-start justify-between gap-4">
			<div>
				<div className="text-[11px] uppercase tracking-[0.08em] text-ink-3 mb-1">
					Org · domains
				</div>
				<h1 className="pp-serif text-[40px] leading-none text-ink mb-2">
					Domains.
				</h1>
				<p className="pp-serif text-[24px] leading-tight text-ink-3 max-w-2xl">
					{count > 0
						? `${count} domain${count === 1 ? "" : "s"} provisioned.`
						: "No domains provisioned yet."}
				</p>
			</div>
			<Button
				variant="primary"
				size="sm"
				icon={<PlusIcon size={14} />}
				onClick={onAddDomain}
				className="shrink-0 mt-2"
			>
				Add domain
			</Button>
		</div>
	);
}

function DomainsError({ onRetry }: { onRetry: () => void }) {
	return (
		<div className="pp-card p-6 flex items-start gap-3">
			<span className="flex h-8 w-8 items-center justify-center rounded-full bg-paper-2 text-ink-3 shrink-0">
				<WarningIcon size={18} />
			</span>
			<div>
				<div className="text-[14px] font-medium text-ink mb-1">
					Couldn't load the domains list
				</div>
				<p className="text-[12.5px] text-ink-3 leading-relaxed mb-2">
					The domains endpoint didn't respond. Check the worker logs and retry.
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

function EmptyDomains({ onAddDomain }: { onAddDomain: () => void }) {
	return (
		<div className="pp-card py-16 px-6">
			<div className="flex flex-col items-center text-center">
				<div className="mb-4">
					<BuildingsIcon size={48} weight="thin" className="text-ink-3" />
				</div>
				<h3 className="text-base font-semibold text-ink mb-1.5">
					No domains yet
				</h3>
				<p className="text-sm text-ink-3 max-w-sm mb-2">
					Add a receiving domain, then provision a mailbox on it. Domains appear
					here once a mailbox is active.
				</p>
				<DomainPrepChecklist className="mb-5 text-left max-w-sm" />
				<div className="flex gap-3">
					<Button
						variant="primary"
						size="sm"
						icon={<PlusIcon size={14} />}
						onClick={onAddDomain}
					>
						Add domain
					</Button>
					<RouterLink
						to="/mailboxes"
						className="text-[13px] underline text-accent hover:opacity-80 self-center"
					>
						Go to Mailboxes
					</RouterLink>
				</div>
			</div>
		</div>
	);
}

/** Checklist of manual DNS / Email Routing steps the operator must complete before a domain receives mail. */
function DomainPrepChecklist({ className }: { className?: string }) {
	return (
		<div className={className}>
			<p className="text-[11px] uppercase tracking-[0.06em] text-ink-3 mb-1.5">
				Before mail arrives, complete these steps:
			</p>
			<ol className="space-y-1 text-[12.5px] text-ink-3 list-decimal list-inside">
				<li>
					Enable <strong className="text-ink">Email Routing</strong> on the
					domain in the Cloudflare dashboard and add a catch-all rule forwarding
					to this Worker.
				</li>
				<li>
					Verify or add the <strong className="text-ink">MX records</strong>{" "}
					that Cloudflare Email Routing requires.
				</li>
				<li>
					Publish a <strong className="text-ink">DMARC TXT record</strong> at{" "}
					<code className="text-[11px]">_dmarc.&lt;domain&gt;</code> (at minimum{" "}
					<code className="text-[11px]">v=DMARC1; p=none</code>).
				</li>
			</ol>
			<a
				href="https://github.com/schmug/PhishSOC/blob/main/README.md#to-set-up"
				target="_blank"
				rel="noopener noreferrer"
				className="text-[12px] underline text-accent hover:opacity-80 mt-1.5 inline-block"
			>
				Full setup guide →
			</a>
		</div>
	);
}

function NoDomainsMatch({
	query,
	onClear,
}: {
	query: string;
	onClear: () => void;
}) {
	return (
		<div className="pp-card p-6 flex items-start gap-3">
			<span className="flex h-8 w-8 items-center justify-center rounded-full bg-paper-2 text-ink-3 shrink-0">
				<BuildingsIcon size={18} />
			</span>
			<div>
				<div className="text-[14px] font-medium text-ink mb-1">
					No domains match "{query}"
				</div>
				<p className="text-[12.5px] text-ink-3 leading-relaxed mb-2">
					Try a different substring, or clear the filter to see every
					provisioned domain.
				</p>
				<button
					type="button"
					onClick={onClear}
					className="text-[12px] underline text-accent hover:opacity-80"
				>
					Clear filter
				</button>
			</div>
		</div>
	);
}

function DomainsControls({
	sortKey,
	onSortKeyChange,
	filter,
	onFilterChange,
}: {
	sortKey: SortKey;
	onSortKeyChange: (key: SortKey) => void;
	filter: string;
	onFilterChange: (value: string) => void;
}) {
	return (
		<div className="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4">
			<label className="flex items-center gap-2 text-[12px] text-ink-3">
				<span className="uppercase tracking-[0.06em] text-[10.5px]">
					Filter
				</span>
				<input
					type="search"
					value={filter}
					onChange={(e) => onFilterChange(e.target.value)}
					placeholder="domain substring"
					aria-label="Filter domains by name"
					className="rounded-md border border-line bg-paper px-2.5 py-1 text-[13px] text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent w-full sm:w-64"
				/>
			</label>
			<label className="flex items-center gap-2 text-[12px] text-ink-3 sm:ml-auto">
				<span className="uppercase tracking-[0.06em] text-[10.5px]">Sort</span>
				<select
					value={sortKey}
					onChange={(e) => onSortKeyChange(e.target.value as SortKey)}
					aria-label="Sort domains"
					className="rounded-md border border-line bg-paper px-2 py-1 text-[13px] text-ink focus:outline-none focus:ring-1 focus:ring-accent"
				>
					{SORT_OPTIONS.map((opt) => (
						<option key={opt.value} value={opt.value}>
							{opt.label}
						</option>
					))}
				</select>
			</label>
		</div>
	);
}

function DomainsTable({
	domains,
	onRemoveDomain,
}: {
	domains: DomainListEntry[];
	onRemoveDomain: (domain: string) => void;
}) {
	return (
		<div className="pp-card overflow-hidden">
			<table className="w-full text-[13px]">
				<thead>
					<tr className="text-left text-[10.5px] uppercase tracking-[0.06em] text-ink-3 border-b border-line">
						<th className="px-4 py-2.5 font-normal">Domain</th>
						<th className="px-4 py-2.5 font-normal text-right">Mailboxes</th>
						<th className="px-4 py-2.5 font-normal text-right">
							Threats blocked · 24h
						</th>
						<th className="px-4 py-2.5 font-normal text-right">Open cases</th>
						<th className="px-4 py-2.5 font-normal w-10" />
					</tr>
				</thead>
				<tbody>
					{domains.map((d) => (
						<tr
							key={d.domain}
							className="border-b border-line last:border-b-0 hover:bg-paper-2 transition-colors group"
						>
							<td className="px-4 py-3">
								<RouterLink
									to={`/domains/${encodeURIComponent(d.domain)}`}
									className="text-ink hover:text-accent transition-colors"
								>
									{d.domain}
								</RouterLink>
							</td>
							<td className="px-4 py-3 text-right pp-mono tabular-nums text-ink-2">
								{d.mailboxesCount}
							</td>
							<td className="px-4 py-3 text-right pp-mono tabular-nums text-ink-2">
								{d.threatsBlocked24h}
							</td>
							<td className="px-4 py-3 text-right pp-mono tabular-nums text-ink-2">
								{d.openCases}
							</td>
							<td className="px-4 py-3 text-right">
								<Tooltip
									content={`Remove ${d.domain} from available domains`}
									asChild
								>
									<button
										type="button"
										aria-label={`Remove ${d.domain} from available domains`}
										onClick={() => onRemoveDomain(d.domain)}
										className="opacity-0 group-hover:opacity-100 transition-opacity text-ink-3 hover:text-red-500"
									>
										<TrashIcon size={14} />
									</button>
								</Tooltip>
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

function AddDomainDialog({
	open,
	onOpenChange,
	onAdd,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	onAdd: (domain: string) => Promise<void>;
}) {
	const [value, setValue] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [adding, setAdding] = useState(false);

	const reset = () => {
		setValue("");
		setError(null);
		setAdding(false);
	};

	const handleOpenChange = (next: boolean) => {
		if (!next) reset();
		onOpenChange(next);
	};

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		const trimmed = value.trim().toLowerCase();
		if (!isValidRegistrableDomain(trimmed)) {
			setError(
				"Enter a valid domain (e.g. acme.example). No protocol, path, or @ allowed; must have at least two labels.",
			);
			return;
		}
		setError(null);
		setAdding(true);
		try {
			await onAdd(trimmed);
			reset();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Failed to add domain";
			setError(
				msg.includes("already")
					? "This domain is already in the available list."
					: msg,
			);
			setAdding(false);
		}
	};

	return (
		<Dialog.Root open={open} onOpenChange={handleOpenChange}>
			<Dialog size="sm" className="p-6">
				<Dialog.Title className="text-base font-semibold mb-1">
					Add domain
				</Dialog.Title>
				<Dialog.Description className="text-ink-3 text-sm mb-4">
					Adds the domain to the{" "}
					<strong className="text-ink">New Mailbox</strong> dropdown. The domain
					will appear in this list once a mailbox is provisioned on it.
				</Dialog.Description>

				<form onSubmit={handleSubmit} className="space-y-4">
					<div>
						<label
							htmlFor="add-domain-input"
							className="block text-xs text-ink mb-1"
						>
							Domain
						</label>
						<input
							id="add-domain-input"
							type="text"
							placeholder="acme.example"
							value={value}
							onChange={(e) => {
								setValue(e.target.value);
								setError(null);
							}}
							className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent pp-mono"
							autoComplete="off"
							spellCheck={false}
						/>
						{error && <p className="text-[12px] text-red-500 mt-1">{error}</p>}
					</div>

					<DomainPrepChecklist />

					<div className="flex justify-end gap-2 pt-1">
						<Button
							variant="secondary"
							size="sm"
							type="button"
							onClick={() => handleOpenChange(false)}
						>
							Cancel
						</Button>
						<Button variant="primary" size="sm" type="submit" loading={adding}>
							Add domain
						</Button>
					</div>
				</form>
			</Dialog>
		</Dialog.Root>
	);
}

function DeleteDomainConfirmDialog({
	domain,
	onConfirm,
	onCancel,
}: {
	domain: string | null;
	onConfirm: () => void;
	onCancel: () => void;
}) {
	return (
		<Dialog.Root
			open={domain !== null}
			onOpenChange={(open) => !open && onCancel()}
		>
			<Dialog size="sm" className="p-6">
				<Dialog.Title className="text-base font-semibold mb-1">
					Remove domain
				</Dialog.Title>
				<Dialog.Description className="text-ink-3 text-sm mb-5">
					Remove <strong className="text-ink">{domain}</strong> from the
					available domain list? Existing mailboxes on this domain are not
					affected — only the domain will no longer appear in the{" "}
					<strong className="text-ink">New Mailbox</strong> dropdown.
				</Dialog.Description>
				<div className="flex justify-end gap-2">
					<Button variant="secondary" size="sm" onClick={onCancel}>
						Cancel
					</Button>
					<Button variant="destructive" size="sm" onClick={onConfirm}>
						Remove
					</Button>
				</div>
			</Dialog>
		</Dialog.Root>
	);
}
