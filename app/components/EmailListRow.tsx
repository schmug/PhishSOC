// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * One conversation row in a mail list. Shared by the per-mailbox folder list
 * (app/routes/email-list.tsx) and the unified /inbox (app/routes/unified-inbox.tsx).
 * Callers own the mutations; this component only renders and forwards clicks.
 */

import { Button, Tooltip } from "@cloudflare/kumo";
import {
	ArrowBendUpLeftIcon,
	EnvelopeOpenIcon,
	EnvelopeSimpleIcon,
	ShieldIcon,
	ShieldWarningIcon,
	StarIcon,
	TrashIcon,
} from "@phosphor-icons/react";
import { formatListDate } from "shared/dates";
import VerdictPill from "~/components/phishsoc/VerdictPill";
import { verdictActionToPill } from "~/components/phishsoc/verdict";
import { formatParticipants, getSnippetText } from "~/lib/utils";
import { parseVerdict, type Email } from "~/types";

function EmailVerdictPill({ email }: { email: Pick<Email, "security_verdict"> }) {
	const verdict = parseVerdict(email.security_verdict);
	const pill = verdictActionToPill(verdict?.action);
	if (!pill || !verdict) return null;
	const icon =
		pill.tone === "danger" ? (
			<ShieldWarningIcon size={12} weight="fill" />
		) : (
			<ShieldIcon size={12} weight="bold" />
		);
	return (
		<VerdictPill tone={pill.tone} icon={icon} title={verdict.explanation}>
			{pill.label}
		</VerdictPill>
	);
}

/** Thread-aware unread check: threaded rows carry thread_unread_count. */
export function hasUnread(email: Email): boolean {
	if (email.thread_unread_count !== undefined) {
		return email.thread_unread_count > 0;
	}
	return !email.read;
}

export interface EmailListRowProps {
	email: Email;
	isSelected: boolean;
	/** Tighter padding while the reading pane is open (md+). */
	compact: boolean;
	/** Unified inbox only: owning mailbox address rendered as a chip. */
	mailboxLabel?: string;
	onOpen: () => void;
	onToggleStar: () => void;
	onToggleRead: () => void;
	onDelete: () => void;
}

export default function EmailListRow({
	email,
	isSelected,
	compact,
	mailboxLabel,
	onOpen,
	onToggleStar,
	onToggleRead,
	onDelete,
}: EmailListRowProps) {
	const snippet = getSnippetText(email.snippet);
	const unread = hasUnread(email);
	return (
		<div
			role="button"
			tabIndex={0}
			onClick={onOpen}
			onKeyDown={(e) => {
				if (e.key === "Enter" || e.key === " ") {
					e.preventDefault();
					onOpen();
				}
			}}
			className={`group flex items-center gap-3 w-full text-left cursor-pointer transition-colors border-b border-line px-4 py-2.5 md:px-6 md:py-3 ${
				compact ? "md:px-4 md:py-2.5" : ""
			} ${isSelected ? "bg-paper-3" : "hover:bg-paper-2"}`}
		>
			{/* Unread dot */}
			<div className="w-2.5 shrink-0 flex justify-center">
				{unread && <div className="h-2 w-2 rounded-full bg-accent" />}
			</div>

			{/* Star */}
			<button
				type="button"
				className="shrink-0 p-0.5 bg-transparent border-0 cursor-pointer"
				aria-label={email.starred ? "Unstar message" : "Star message"}
				onClick={(e) => {
					e.preventDefault();
					e.stopPropagation();
					onToggleStar();
				}}
			>
				<StarIcon
					size={16}
					weight={email.starred ? "fill" : "regular"}
					className={email.starred ? "text-suspect" : "text-ink-3 hover:text-suspect"}
				/>
			</button>

			{/* Content */}
			<div className="min-w-0 flex-1">
				<div className="flex items-center gap-2">
					<span className={`truncate text-sm ${unread ? "font-semibold text-ink" : "text-ink"}`}>
						{formatParticipants(email)}
					</span>
					{(email.thread_count ?? 1) > 1 && (
						<span className="shrink-0 text-xs text-ink-3 bg-paper-3 rounded-full px-1.5 py-0.5 font-medium">
							{email.thread_count}
						</span>
					)}
					{mailboxLabel && (
						<span
							data-testid="row-mailbox"
							title={mailboxLabel}
							className="shrink min-w-0 max-w-[40%] truncate text-xs text-ink-3 border border-line rounded-full px-1.5 py-0.5"
						>
							{mailboxLabel}
						</span>
					)}
					{email.has_draft && <span className="shrink-0 text-xs text-danger font-medium">Draft</span>}
					{email.needs_reply && !email.has_draft && (
						<Tooltip content="Needs reply" asChild>
							<span className="shrink-0 text-suspect">
								<ArrowBendUpLeftIcon size={14} weight="bold" />
							</span>
						</Tooltip>
					)}
					<EmailVerdictPill email={email} />
					<span className="text-sm text-ink-3 shrink-0 ml-auto">{formatListDate(email.date)}</span>
				</div>
				<div className="truncate text-sm mt-0.5">
					<span className={unread ? "font-medium text-ink" : "text-ink-3"}>{email.subject}</span>
					{snippet && <span className="text-ink-3 font-normal"> &mdash; {snippet}</span>}
				</div>
			</div>

			{/* Hover actions */}
			<div className="hidden group-hover:flex items-center shrink-0">
				<Tooltip content={email.read ? "Mark unread" : "Mark read"} asChild>
					<Button
						variant="ghost"
						shape="square"
						size="sm"
						icon={email.read ? <EnvelopeSimpleIcon size={14} /> : <EnvelopeOpenIcon size={14} />}
						onClick={(e) => {
							e.stopPropagation();
							onToggleRead();
						}}
						aria-label={email.read ? "Mark unread" : "Mark read"}
					/>
				</Tooltip>
				<Tooltip content="Delete" asChild>
					<Button
						variant="ghost"
						shape="square"
						size="sm"
						icon={<TrashIcon size={14} />}
						onClick={(e) => {
							e.preventDefault();
							e.stopPropagation();
							onDelete();
						}}
						aria-label="Delete"
					/>
				</Tooltip>
			</div>
		</div>
	);
}
