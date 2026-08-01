// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Button, Input, Loader } from "@cloudflare/kumo";
import { LockIcon, UserIcon, XIcon } from "@phosphor-icons/react";
import { useState } from "react";
import {
	useAddAclGroup,
	useAddAclMember,
	useLockDownMailbox,
	useMailboxAcl,
	useRemoveAclGroup,
	useRemoveAclMember,
	useTransferAclOwnership,
} from "~/queries/mailboxes";
import { ApiError } from "~/services/api";

interface AclMembersPanelProps {
	mailboxId: string;
}

export function AclMembersPanel({ mailboxId }: AclMembersPanelProps) {
	const { data: acl, isLoading } = useMailboxAcl(mailboxId);
	const lockDown = useLockDownMailbox();
	const addMember = useAddAclMember(mailboxId);
	const removeMember = useRemoveAclMember(mailboxId);
	const transferOwnership = useTransferAclOwnership(mailboxId);
	const addGroup = useAddAclGroup(mailboxId);
	const removeGroup = useRemoveAclGroup(mailboxId);

	const [newEmail, setNewEmail] = useState("");
	const [addError, setAddError] = useState<string | null>(null);
	const [removeError, setRemoveError] = useState<string | null>(null);
	const [transferError, setTransferError] = useState<string | null>(null);
	const [newGroup, setNewGroup] = useState("");
	const [addGroupError, setAddGroupError] = useState<string | null>(null);
	const [removeGroupError, setRemoveGroupError] = useState<string | null>(null);

	if (isLoading || acl === undefined) {
		return (
			<div className="flex justify-center py-6">
				<Loader size="sm" />
			</div>
		);
	}

	if (acl === null) {
		return (
			<div className="rounded-md border border-line bg-paper-2 px-4 py-3 text-sm text-ink-3">
				<div className="flex items-center gap-2 mb-2">
					<LockIcon size={14} weight="duotone" />
					<span className="font-medium text-ink">Mailbox is unscoped</span>
				</div>
				<p className="mb-3">
					This mailbox is accessible to anyone admitted by CF Access. Lock it
					down first to manage individual members.
				</p>
				<Button
					variant="secondary"
					size="sm"
					loading={lockDown.isPending}
					onClick={() => {
						if (
							window.confirm("Are you sure you want to lock down this mailbox?")
						) {
							lockDown.mutate(mailboxId);
						}
					}}
					data-testid="acl-lockdown-btn"
				>
					Lock down
				</Button>
				{lockDown.isError && (
					<p className="mt-2 text-xs text-red-600">
						{lockDown.error instanceof ApiError
							? lockDown.error.message
							: "Lock down failed"}
					</p>
				)}
			</div>
		);
	}

	const handleAdd = async () => {
		setAddError(null);
		const email = newEmail.trim().toLowerCase();
		if (!email) return;
		try {
			await addMember.mutateAsync(email);
			setNewEmail("");
		} catch (err) {
			setAddError(
				err instanceof ApiError ? err.message : "Failed to add member",
			);
		}
	};

	const handleRemove = async (email: string) => {
		if (!window.confirm(`Are you sure you want to remove ${email}?`)) return;
		setRemoveError(null);
		try {
			await removeMember.mutateAsync(email);
		} catch (err) {
			setRemoveError(
				err instanceof ApiError ? err.message : "Failed to remove member",
			);
		}
	};

	const handleTransfer = async (email: string) => {
		if (
			!window.confirm(
				`Are you sure you want to transfer ownership to ${email}?`,
			)
		)
			return;
		setTransferError(null);
		try {
			await transferOwnership.mutateAsync(email);
		} catch (err) {
			setTransferError(
				err instanceof ApiError ? err.message : "Failed to transfer ownership",
			);
		}
	};

	const handleAddGroup = async () => {
		setAddGroupError(null);
		const group = newGroup.trim();
		if (!group) return;
		try {
			await addGroup.mutateAsync(group);
			setNewGroup("");
		} catch (err) {
			setAddGroupError(
				err instanceof ApiError ? err.message : "Failed to add group",
			);
		}
	};

	const handleRemoveGroup = async (group: string) => {
		if (!window.confirm(`Are you sure you want to remove group ${group}?`))
			return;
		setRemoveGroupError(null);
		try {
			await removeGroup.mutateAsync(group);
		} catch (err) {
			setRemoveGroupError(
				err instanceof ApiError ? err.message : "Failed to remove group",
			);
		}
	};

	return (
		<div className="space-y-4">
			<div>
				<div className="text-xs text-ink-3 mb-1">Owner</div>
				<div className="flex items-center gap-2 text-sm text-ink">
					<UserIcon
						size={14}
						weight="duotone"
						className="text-ink-3 shrink-0"
					/>
					<span data-testid="acl-owner">{acl.owner}</span>
				</div>
			</div>

			<div>
				<div className="text-xs text-ink-3 mb-2">Members</div>
				<ul className="space-y-1" data-testid="acl-members-list">
					{acl.members.map((member) => (
						<li
							key={member}
							className="flex items-center justify-between gap-2"
						>
							<span className="text-sm text-ink truncate">{member}</span>
							{member !== acl.owner && (
								<div className="flex items-center gap-1 shrink-0">
									<button
										type="button"
										aria-label={`Make ${member} owner`}
										data-testid={`transfer-to-${member}`}
										className="text-xs text-ink-3 hover:text-amber-600 px-1"
										disabled={transferOwnership.isPending}
										onClick={() => handleTransfer(member)}
									>
										Make owner
									</button>
									<button
										type="button"
										aria-label={`Remove ${member}`}
										data-testid={`remove-member-${member}`}
										className="text-ink-3 hover:text-red-600"
										disabled={removeMember.isPending}
										onClick={() => handleRemove(member)}
									>
										<XIcon size={14} />
									</button>
								</div>
							)}
						</li>
					))}
				</ul>
				{removeError && (
					<p className="mt-1 text-xs text-red-600" data-testid="remove-error">
						{removeError}
					</p>
				)}
				{transferError && (
					<p className="mt-1 text-xs text-red-600" data-testid="transfer-error">
						{transferError}
					</p>
				)}
			</div>

			<div>
				<div className="text-xs text-ink-3 mb-2">Add member</div>
				<div className="flex gap-2">
					<Input
						type="email"
						placeholder="teammate@example.com"
						value={newEmail}
						onChange={(e) => setNewEmail(e.target.value)}
						onKeyDown={(e) => {
							if (e.key === "Enter") handleAdd();
						}}
						data-testid="add-member-input"
						aria-label="New member email"
					/>
					<Button
						variant="secondary"
						size="sm"
						loading={addMember.isPending}
						onClick={handleAdd}
						data-testid="add-member-btn"
					>
						Add
					</Button>
				</div>
				{addError && (
					<p className="mt-1 text-xs text-red-600" data-testid="add-error">
						{addError}
					</p>
				)}
			</div>

			<div>
				<div className="text-xs text-ink-3 mb-2">Groups</div>
				<ul className="space-y-1" data-testid="acl-groups-list">
					{acl.groups.map((group) => (
						<li key={group} className="flex items-center justify-between gap-2">
							<span className="text-sm text-ink truncate">{group}</span>
							<button
								type="button"
								aria-label={`Remove group ${group}`}
								data-testid={`remove-group-${group}`}
								className="text-ink-3 hover:text-red-600 shrink-0"
								disabled={removeGroup.isPending}
								onClick={() => handleRemoveGroup(group)}
							>
								<XIcon size={14} />
							</button>
						</li>
					))}
				</ul>
				{removeGroupError && (
					<p
						className="mt-1 text-xs text-red-600"
						data-testid="remove-group-error"
					>
						{removeGroupError}
					</p>
				)}
				<div className="flex gap-2 mt-2">
					<Input
						type="text"
						placeholder="soc-analysts"
						value={newGroup}
						onChange={(e) => setNewGroup(e.target.value)}
						onKeyDown={(e) => {
							if (e.key === "Enter") handleAddGroup();
						}}
						data-testid="add-group-input"
						aria-label="New group name"
					/>
					<Button
						variant="secondary"
						size="sm"
						loading={addGroup.isPending}
						onClick={handleAddGroup}
						data-testid="add-group-btn"
					>
						Add
					</Button>
				</div>
				{addGroupError && (
					<p
						className="mt-1 text-xs text-red-600"
						data-testid="add-group-error"
					>
						{addGroupError}
					</p>
				)}
				<p className="mt-1 text-xs text-ink-3" data-testid="acl-groups-note">
					Group names must match names defined in your Cloudflare Access
					dashboard
				</p>
			</div>
		</div>
	);
}
