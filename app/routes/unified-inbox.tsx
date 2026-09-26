// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * All inboxes (/inbox): merged Inbox conversations across every mailbox the
 * caller can see, minus honeypot, sidecar and hideFromAllInboxes mailboxes
 * (filtering is server-side, GET /api/v1/inbox).
 * Spec: docs/superpowers/specs/2026-09-26-unified-inbox-design.md
 *
 * There is no :mailboxId route param here, so the selected row's mailbox is
 * held in local state and passed to MailboxSplitView explicitly. Every row
 * action goes to the row's own mailbox through the existing per-mailbox
 * mutations.
 */

import { Banner, Button, Tooltip } from "@cloudflare/kumo";
import { ArrowsClockwiseIcon, PencilSimpleIcon } from "@phosphor-icons/react";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { Folders } from "shared/folders";
import EmailListRow, { hasUnread } from "~/components/EmailListRow";
import MailboxSplitView from "~/components/MailboxSplitView";
import Shell from "~/components/phishsoc/Shell";
import { useUIStore } from "~/hooks/useUIStore";
import { readLastFrom } from "~/lib/compose-from";
import { useFeedback } from "~/lib/feedback";
import { useDeleteEmail, useMarkThreadRead, useUpdateEmail } from "~/queries/emails";
import { useUnifiedInbox } from "~/queries/inbox";
import { queryKeys } from "~/queries/keys";
import { useMailboxes } from "~/queries/mailboxes";
import type { UnifiedInboxRow } from "~/types";

export default function UnifiedInboxRoute() {
	const { selectedEmailId, isComposing, selectEmail, closePanel, startCompose } = useUIStore();
	const [selectedMailboxId, setSelectedMailboxId] = useState<string | null>(null);
	// Stack of cursors for pages older than the head. [] = head page.
	const [cursorStack, setCursorStack] = useState<string[]>([]);
	const before = cursorStack.length > 0 ? cursorStack[cursorStack.length - 1] : null;
	const [searchParams, setSearchParams] = useSearchParams();

	const queryClient = useQueryClient();
	const { data, isFetching } = useUnifiedInbox(before);
	const { data: mailboxes } = useMailboxes();
	const updateEmail = useUpdateEmail();
	const markThreadRead = useMarkThreadRead();
	const deleteEmail = useDeleteEmail();
	const feedback = useFeedback();

	const emails = data?.emails ?? [];
	const failed = data?.failed ?? [];
	const isPanelOpen = selectedEmailId !== null || isComposing;

	// A selection made on a per-mailbox page belongs to that mailbox; drop it so
	// it can't open here against the wrong one. Must run before the deep-link effect.
	useEffect(() => {
		closePanel();
	}, [closePanel]);

	// Deep link: /inbox?mailbox=<id>&email=<id> opens that message, then drops the params.
	useEffect(() => {
		const mb = searchParams.get("mailbox");
		const em = searchParams.get("email");
		if (!mb || !em) return;
		setSelectedMailboxId(mb);
		selectEmail(em);
		setSearchParams(
			(prev) => {
				const next = new URLSearchParams(prev);
				next.delete("mailbox");
				next.delete("email");
				return next;
			},
			{ replace: true },
		);
	}, [searchParams, selectEmail, setSearchParams]);

	const fromOptions = useMemo(
		() => (mailboxes ?? []).filter((m) => !m.sidecar).map((m) => ({ id: m.id, email: m.email })),
		[mailboxes],
	);
	const lastFrom = readLastFrom();
	const defaultFrom =
		selectedMailboxId ?? (lastFrom && fromOptions.some((o) => o.id === lastFrom) ? lastFrom : null);

	const handleRowClick = (email: UnifiedInboxRow) => {
		setSelectedMailboxId(email.mailbox_id);
		selectEmail(email.id);
		if (!hasUnread(email)) return;
		if (email.thread_id && email.thread_count && email.thread_count > 1) {
			markThreadRead.mutate(
				{ mailboxId: email.mailbox_id, threadId: email.thread_id },
				{ onError: () => feedback.error("Couldn't mark thread read.") },
			);
		} else {
			updateEmail.mutate(
				{ mailboxId: email.mailbox_id, id: email.id, data: { read: true } },
				{ onError: () => feedback.error("Couldn't update email.") },
			);
		}
	};

	const toggleStar = (email: UnifiedInboxRow) =>
		updateEmail.mutate(
			{ mailboxId: email.mailbox_id, id: email.id, data: { starred: !email.starred } },
			{ onError: () => feedback.error("Couldn't update email.") },
		);

	const toggleRead = (email: UnifiedInboxRow) =>
		updateEmail.mutate(
			{ mailboxId: email.mailbox_id, id: email.id, data: { read: !email.read } },
			{ onError: () => feedback.error("Couldn't update email.") },
		);

	const handleDelete = (email: UnifiedInboxRow) => {
		if (!window.confirm("Are you sure you want to delete this email?")) return;
		deleteEmail.mutate(
			{ mailboxId: email.mailbox_id, id: email.id },
			{ onError: () => feedback.error("Couldn't delete email.") },
		);
		if (selectedEmailId === email.id && selectedMailboxId === email.mailbox_id) closePanel();
	};

	return (
		<Shell>
			<MailboxSplitView
				selectedEmailId={selectedEmailId}
				isComposing={isComposing}
				mailboxId={selectedMailboxId ?? undefined}
				folder={Folders.INBOX}
				fromPicker={{ options: fromOptions, defaultId: defaultFrom }}
			>
				<div className="flex items-center justify-between px-4 py-3.5 border-b border-line shrink-0 md:px-5">
					<h1 className="pp-serif text-ink">All inboxes</h1>
					<div className="flex items-center gap-1">
						<Tooltip content="Compose" side="bottom" asChild>
							<Button
								variant="ghost"
								shape="square"
								size="sm"
								icon={<PencilSimpleIcon size={18} />}
								onClick={() => startCompose()}
								aria-label="Compose"
							/>
						</Tooltip>
						<Tooltip content={isFetching ? "Refreshing..." : "Refresh"} side="bottom" asChild>
							<Button
								variant="ghost"
								shape="square"
								size="sm"
								icon={<ArrowsClockwiseIcon size={18} className={isFetching ? "animate-spin" : ""} />}
								onClick={() => queryClient.invalidateQueries({ queryKey: queryKeys.unifiedInbox.all })}
								disabled={isFetching}
								aria-label="Refresh"
							/>
						</Tooltip>
					</div>
				</div>

				{failed.length > 0 && (
					<div className="px-4 pt-3 md:px-5">
						<Banner
							variant="error"
							text={`${failed.length} mailbox${failed.length === 1 ? "" : "es"} didn't load: ${failed.join(", ")}`}
						/>
					</div>
				)}

				<div className="flex-1 overflow-y-auto">
					{emails.length > 0 ? (
						emails.map((email) => (
							<EmailListRow
								key={`${email.mailbox_id}:${email.id}`}
								email={email}
								mailboxLabel={email.mailbox_email}
								isSelected={selectedEmailId === email.id && selectedMailboxId === email.mailbox_id}
								compact={isPanelOpen}
								onOpen={() => handleRowClick(email)}
								onToggleStar={() => toggleStar(email)}
								onToggleRead={() => toggleRead(email)}
								onDelete={() => handleDelete(email)}
							/>
						))
					) : data && data.mailboxCount === 0 ? (
						<div className="px-6 py-12 text-center text-sm text-ink-3">
							<div className="text-ink font-medium">No mailboxes in All inboxes</div>
							<div className="mt-1">
								Every mailbox is hidden or none exist yet.{" "}
								<Link to="/mailboxes" className="text-accent hover:underline">
									Manage mailboxes
								</Link>
							</div>
						</div>
					) : data ? (
						<div className="px-6 py-12 text-center text-sm text-ink-3">No mail in any inbox.</div>
					) : null}
				</div>

				<div className="flex justify-center gap-2 py-3 border-t border-line shrink-0">
					<Button
						variant="ghost"
						size="sm"
						onClick={() => setCursorStack((s) => s.slice(0, -1))}
						disabled={cursorStack.length === 0}
					>
						Newer
					</Button>
					<Button
						variant="ghost"
						size="sm"
						onClick={() => data?.nextCursor && setCursorStack((s) => [...s, data.nextCursor as string])}
						disabled={!data?.nextCursor}
					>
						Older
					</Button>
				</div>
			</MailboxSplitView>
		</Shell>
	);
}
