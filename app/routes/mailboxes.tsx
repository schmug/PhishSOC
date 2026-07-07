// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import {
	Button,
	Dialog,
	Input,
	Loader,
	Select,
	Text,
} from "@cloudflare/kumo";
import { EnvelopeIcon, PlusIcon, TrashIcon } from "@phosphor-icons/react";
import { useQuery } from "@tanstack/react-query";
import { type FormEvent, type MouseEvent, useEffect, useState } from "react";
import { Link as RouterLink } from "react-router";
import Shell from "~/components/phishsoc/Shell";
import { useAutoProvisionMailboxes } from "~/hooks/useAutoProvisionMailboxes";
import { useFeedback } from "~/lib/feedback";
import api from "~/services/api";
import {
	useCreateMailbox,
	useDeleteMailbox,
	useLockDownAllMailboxes,
	useLockDownMailbox,
	useMailboxes,
} from "~/queries/mailboxes";
import { queryKeys } from "~/queries/keys";

export function meta() {
	return [{ title: "Mailboxes · PhishSOC" }];
}

export default function MailboxesRoute() {
	const feedback = useFeedback();
	const { data: mailboxes = [] } = useMailboxes();
	const createMailbox = useCreateMailbox();
	const deleteMailbox = useDeleteMailbox();
	const lockDownMailbox = useLockDownMailbox();
	const lockDownAllMailboxes = useLockDownAllMailboxes();

	useAutoProvisionMailboxes();

	const { data: configData } = useQuery({
		queryKey: queryKeys.config,
		queryFn: () => api.getConfig(),
		staleTime: Infinity,
	});

	const domains = configData?.domains ?? [];
	const emailAddresses = configData?.emailAddresses ?? [];

	const [isCreateOpen, setIsCreateOpen] = useState(false);
	const [newPrefix, setNewPrefix] = useState("");
	const [selectedDomain, setSelectedDomain] = useState("");
	const [newName, setNewName] = useState("");
	const [isCreating, setIsCreating] = useState(false);
	const [createError, setCreateError] = useState<string | null>(null);
	const [isDeleteOpen, setIsDeleteOpen] = useState(false);
	const [mailboxToDelete, setMailboxToDelete] = useState<{
		id: string;
		email: string;
	} | null>(null);
	const [isDeleting, setIsDeleting] = useState(false);
	const [isBulkLockDownOpen, setIsBulkLockDownOpen] = useState(false);

	useEffect(() => {
		if (domains.length > 0 && !selectedDomain) {
			setSelectedDomain(domains[0]);
		}
	}, [domains, selectedDomain]);

	const handleCreate = async (e: FormEvent) => {
		e.preventDefault();
		setCreateError(null);
		if (!newPrefix || !selectedDomain) {
			setCreateError("Please fill in all fields");
			return;
		}
		const email = `${newPrefix}@${selectedDomain}`;
		const name = newName || newPrefix;
		setIsCreating(true);
		try {
			await createMailbox.mutateAsync({ email, name });
			feedback.success("Mailbox created successfully!");
			setIsCreateOpen(false);
			setNewPrefix("");
			setNewName("");
		} catch (err: unknown) {
			const message = (err instanceof Error ? err.message : null) || "Failed to create mailbox";
			setCreateError(message);
		} finally {
			setIsCreating(false);
		}
	};

	const handleDelete = async () => {
		if (!mailboxToDelete) return;
		setIsDeleting(true);
		try {
			await deleteMailbox.mutateAsync(mailboxToDelete.id);
			feedback.info("Mailbox deleted");
			setIsDeleteOpen(false);
			setMailboxToDelete(null);
		} catch {
			feedback.error("Failed to delete mailbox");
		} finally {
			setIsDeleting(false);
		}
	};

	const isConfigured = emailAddresses.length > 0;
	const accounts = isConfigured
		? emailAddresses.map((addr) => ({
				id: addr,
				email: addr,
				name: addr.split("@")[0] || addr,
			}))
		: mailboxes;

	const mailboxAclStatusMap = new Map(mailboxes.map((m) => [m.id, m.acl_status]));

	// API-sidecar mailboxes (#31) — their authoritative store is the
	// operator's Google Workspace inbox, so they render in a separate group
	// linking to settings (not the inbox view) rather than mixed into the
	// normal list. `isConfigured` accounts come from `emailAddresses`, which
	// carries no sidecar flag, so the split only applies to the `mailboxes`
	// list itself.
	const sidecarStatusMap = new Map(mailboxes.map((m) => [m.id, m]));
	const plainAccounts = accounts.filter((a) => !sidecarStatusMap.get(a.id)?.sidecar);
	const sidecarAccounts = accounts.filter((a) => sidecarStatusMap.get(a.id)?.sidecar);

	const handleLockDown = async (mailboxId: string, e: MouseEvent) => {
		e.preventDefault();
		e.stopPropagation();
		try {
			await lockDownMailbox.mutateAsync(mailboxId);
			feedback.success("Mailbox locked down successfully");
		} catch {
			feedback.error("Failed to lock down mailbox");
		}
	};

	const unscopedCount = mailboxes.filter((m) => m.acl_status === "unscoped").length;

	const handleBulkLockDown = async () => {
		try {
			const result = await lockDownAllMailboxes.mutateAsync();
			const parts: string[] = [];
			if (result.locked > 0) parts.push(`${result.locked} locked`);
			if (result.skipped > 0) parts.push(`${result.skipped} skipped`);
			if (result.errors.length > 0) {
				feedback.error(`Bulk lock-down finished with errors: ${result.errors.join("; ")}`);
			} else {
				feedback.success(`Bulk lock-down complete — ${parts.join(", ")}`);
			}
		} catch {
			feedback.error("Bulk lock-down failed");
		} finally {
			setIsBulkLockDownOpen(false);
		}
	};

	const isLoading = !configData;

	return (
		<Shell>
			<div className="mx-auto max-w-2xl px-4 py-8 md:px-6 md:py-16">
				<div className="mb-8">
					<div className="flex items-center justify-between">
						<h1 className="pp-serif text-[40px] leading-none text-ink">Mailboxes</h1>
						<div className="flex items-center gap-2">
							{unscopedCount > 0 && (
								<Button
									variant="secondary"
									size="sm"
									onClick={() => setIsBulkLockDownOpen(true)}
								>
									Lock down all unscoped
								</Button>
							)}
							{!isConfigured && (
								<Button
									variant="primary"
									icon={<PlusIcon size={16} />}
									onClick={() => setIsCreateOpen(true)}
								>
									New Mailbox
								</Button>
							)}
						</div>
					</div>
					{domains.length > 0 && (
						<p className="text-sm text-ink-3 mt-1">
							{domains.join(", ")}
						</p>
					)}
				</div>

				{isLoading ? (
					<div className="flex justify-center py-20">
						<Loader size="lg" />
					</div>
				) : accounts.length > 0 ? (
					<>
						{plainAccounts.length > 0 && (
							<div className="pp-card overflow-hidden">
								{plainAccounts.map((account, idx) => (
									<RouterLink
										key={account.id}
										to={`/mailbox/${account.id}`}
										className={`group flex items-center gap-4 px-5 py-4 no-underline transition-colors hover:bg-paper-2 ${
											idx > 0 ? "border-t border-line" : ""
										}`}
									>
										<div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-paper-3 text-sm font-bold text-ink">
											{account.name.charAt(0).toUpperCase()}
										</div>
										<div className="min-w-0 flex-1">
											<div className="text-sm font-medium text-ink truncate">
												{account.name}
											</div>
											<div className="text-sm text-ink-3">
												{account.email}
											</div>
										</div>
										{mailboxAclStatusMap.get(account.id) === "unscoped" && (
											<>
												<span className="shrink-0 inline-flex items-center rounded px-1.5 py-0.5 text-[10.5px] font-medium bg-amber-50 text-amber-700 border border-amber-200">
													Unscoped
												</span>
												<Button
													variant="ghost"
													size="sm"
													loading={
														lockDownMailbox.isPending &&
														lockDownMailbox.variables === account.id
													}
													onClick={(e) => handleLockDown(account.id, e)}
												>
													Lock down
												</Button>
											</>
										)}
										{!isConfigured && (
											<Button
												variant="ghost"
												size="sm"
												shape="square"
												icon={<TrashIcon size={16} />}
												aria-label={`Delete mailbox ${account.email}`}
												onClick={(e) => {
													e.preventDefault();
													e.stopPropagation();
													setMailboxToDelete({
														id: account.id,
														email: account.email,
													});
													setIsDeleteOpen(true);
												}}
											/>
										)}
									</RouterLink>
								))}
							</div>
						)}

						{sidecarAccounts.length > 0 && (
							<div className={plainAccounts.length > 0 ? "mt-6" : undefined}>
								<div className="text-xs font-medium uppercase tracking-[0.06em] text-ink-3 mb-2 px-1">
									Sidecar mailboxes
								</div>
								<div className="pp-card overflow-hidden">
									{sidecarAccounts.map((account, idx) => {
										const health = sidecarStatusMap.get(account.id)?.sidecar_health;
										const unhealthy = !!health && !health.healthy;
										return (
											<RouterLink
												key={account.id}
												to={`/mailbox/${account.id}/settings`}
												className={`group flex items-center gap-4 px-5 py-4 no-underline transition-colors hover:bg-paper-2 ${
													idx > 0 ? "border-t border-line" : ""
												}`}
											>
												<div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-paper-3 text-sm font-bold text-ink">
													{account.name.charAt(0).toUpperCase()}
												</div>
												<div className="min-w-0 flex-1">
													<div className="text-sm font-medium text-ink truncate">
														{account.name}
													</div>
													<div className="text-sm text-ink-3">
														{account.email}
													</div>
												</div>
												{unhealthy && (
													<span
														className="shrink-0 text-amber-600 dark:text-amber-400 text-sm"
														title={health?.last_error ?? "Sidecar needs attention"}
														aria-label={`Sidecar unhealthy: ${health?.last_error ?? "needs attention"}`}
													>
														▲
													</span>
												)}
												<span className="shrink-0 inline-flex items-center rounded px-1.5 py-0.5 text-[10.5px] font-medium bg-paper-2 text-ink-3 border border-line">
													Sidecar
												</span>
											</RouterLink>
										);
									})}
								</div>
							</div>
						)}
					</>
				) : (
					<div className="pp-card py-16 px-6">
						<div className="flex flex-col items-center text-center">
							<div className="mb-4">
								<EnvelopeIcon
									size={48}
									weight="thin"
									className="text-ink-3"
								/>
							</div>
							<h3 className="text-base font-semibold text-ink mb-1.5">
								No mailboxes yet
							</h3>
							<p className="text-sm text-ink-3 max-w-sm mb-5">
								{isConfigured
									? "Your email routing is configured but no mailboxes have been created yet. They will appear here automatically."
									: "Create a mailbox to start sending and receiving emails with your domain."}
							</p>
							{!isConfigured && (
								<Button
									variant="primary"
									icon={<PlusIcon size={16} />}
									onClick={() => setIsCreateOpen(true)}
								>
									Create Mailbox
								</Button>
							)}
						</div>
					</div>
				)}
			</div>

			{/* Create Dialog */}
			<Dialog.Root open={isCreateOpen} onOpenChange={setIsCreateOpen}>
				<Dialog size="sm" className="p-6">
					<Dialog.Title className="text-base font-semibold mb-5">
						Create New Mailbox
					</Dialog.Title>
					<form onSubmit={handleCreate} className="space-y-4">
						{createError && (
							<Text variant="error" size="sm">
								{createError}
							</Text>
						)}
						<div>
							<span className="text-sm font-medium text-ink mb-1.5 block">
								Email Address
							</span>
							<div className="flex items-center gap-2">
								<div className="flex-1">
									<Input
										aria-label="Address prefix"
										placeholder="info"
										size="sm"
										value={newPrefix}
										onChange={(e) => setNewPrefix(e.target.value)}
										required
									/>
								</div>
								<span className="text-sm text-ink-3">@</span>
								{domains.length > 1 ? (
									<div className="flex-1">
							<Select
								aria-label="Domain"
								value={selectedDomain}
								onValueChange={(value) => {
									if (value) setSelectedDomain(value);
								}}
							>
											{domains.map((d) => (
												<Select.Option key={d} value={d}>
													{d}
												</Select.Option>
											))}
										</Select>
									</div>
								) : (
									<span className="text-sm text-ink-3">
										{selectedDomain || "no domain"}
									</span>
								)}
							</div>
						</div>
						<Input
							label="Display Name (optional)"
							placeholder="Info"
							size="sm"
							value={newName}
							onChange={(e) => setNewName(e.target.value)}
						/>
						<div className="flex justify-end gap-2 pt-2">
							<Dialog.Close
								render={(props) => (
									<Button {...props} variant="secondary" size="sm">
										Cancel
									</Button>
								)}
							/>
							<Button
								type="submit"
								variant="primary"
								size="sm"
								loading={isCreating}
								disabled={!selectedDomain}
							>
								Create
							</Button>
						</div>
					</form>
				</Dialog>
			</Dialog.Root>

			{/* Bulk Lock-down Confirm Dialog */}
			<Dialog.Root open={isBulkLockDownOpen} onOpenChange={setIsBulkLockDownOpen}>
				<Dialog size="sm" className="p-6">
					<Dialog.Title className="text-base font-semibold mb-2">
						Lock down all unscoped mailboxes?
					</Dialog.Title>
					<Dialog.Description className="text-ink-3 text-sm mb-5">
						Lock down{" "}
						<strong className="text-ink">{unscopedCount}</strong>{" "}
						unscoped{" "}
						{unscopedCount === 1 ? "mailbox" : "mailboxes"}? You will become owner of each.
					</Dialog.Description>
					<div className="flex justify-end gap-2">
						<Dialog.Close
							render={(props) => (
								<Button {...props} variant="secondary" size="sm">
									Cancel
								</Button>
							)}
						/>
						<Button
							variant="primary"
							size="sm"
							loading={lockDownAllMailboxes.isPending}
							onClick={handleBulkLockDown}
						>
							Lock down all
						</Button>
					</div>
				</Dialog>
			</Dialog.Root>

			{/* Delete Dialog */}
			<Dialog.Root
				open={isDeleteOpen}
				onOpenChange={(open) => {
					setIsDeleteOpen(open);
					if (!open) setMailboxToDelete(null);
				}}
			>
				<Dialog size="sm" className="p-6">
					<Dialog.Title className="text-base font-semibold mb-2">
						Delete Mailbox
					</Dialog.Title>
					<Dialog.Description className="text-ink-3 text-sm mb-5">
						Are you sure you want to delete{" "}
						<strong className="text-ink">
							{mailboxToDelete?.email}
						</strong>
						? This action cannot be undone.
					</Dialog.Description>
					<div className="flex justify-end gap-2">
						<Dialog.Close
							render={(props) => (
								<Button {...props} variant="secondary" size="sm">
									Cancel
								</Button>
							)}
						/>
						<Button
							variant="destructive"
							size="sm"
							loading={isDeleting}
							onClick={handleDelete}
						>
							Delete
						</Button>
					</div>
				</Dialog>
			</Dialog.Root>
		</Shell>
	);
}
