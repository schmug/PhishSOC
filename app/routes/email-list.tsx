// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Button, Pagination, Tooltip } from "@cloudflare/kumo";
import {
	ArchiveIcon,
	ArrowsClockwiseIcon,
	EnvelopeSimpleIcon,
	FileIcon,
	PaperPlaneTiltIcon,
	PencilSimpleIcon,
	ShieldWarningIcon,
	TrashIcon,
	TrayIcon,
} from "@phosphor-icons/react";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { useParams, useSearchParams } from "react-router";
import { Folders } from "shared/folders";
import EmailListRow, { hasUnread } from "~/components/EmailListRow";
import MailboxSplitView from "~/components/MailboxSplitView";
import { useFeedback } from "~/lib/feedback";
import {
	useDeleteEmail,
	useEmails,
	useMarkThreadRead,
	useUpdateEmail,
} from "~/queries/emails";
import { useFolders } from "~/queries/folders";
import { queryKeys } from "~/queries/keys";
import { useUIStore } from "~/hooks/useUIStore";
import type { Email } from "~/types";

const PAGE_SIZE = 25;

const FOLDER_EMPTY_STATES: Record<
	string,
	{
		icon: React.ReactNode;
		title: string;
		description: string;
		showCompose?: boolean;
	}
> = {
	[Folders.INBOX]: {
		icon: <TrayIcon size={48} weight="thin" className="text-ink-3" />,
		title: "Your inbox is empty",
		description:
			"New emails will appear here when they arrive. Send an email to get the conversation started.",
		showCompose: true,
	},
	[Folders.SENT]: {
		icon: (
			<PaperPlaneTiltIcon size={48} weight="thin" className="text-ink-3" />
		),
		title: "No sent emails",
		description: "Emails you send will show up here.",
		showCompose: true,
	},
	[Folders.DRAFT]: {
		icon: <FileIcon size={48} weight="thin" className="text-ink-3" />,
		title: "No drafts",
		description: "Emails you're still working on will be saved here.",
		showCompose: true,
	},
	[Folders.ARCHIVE]: {
		icon: <ArchiveIcon size={48} weight="thin" className="text-ink-3" />,
		title: "Archive is empty",
		description:
			"Move emails here to keep your inbox clean without deleting them.",
	},
	[Folders.TRASH]: {
		icon: <TrashIcon size={48} weight="thin" className="text-ink-3" />,
		title: "Trash is empty",
		description:
			"Deleted emails will appear here. You can restore them or permanently delete them.",
	},
	[Folders.QUARANTINE]: {
		icon: <ShieldWarningIcon size={48} weight="thin" className="text-ink-3" />,
		title: "No quarantined emails",
		description:
			"Emails the security pipeline classifies as high-risk appear here. Review and release to inbox if safe.",
	},
};

function EmailListSkeleton() {
	return (
		<div className="animate-pulse space-y-1 p-2">
			{Array.from({ length: 8 }).map((_, i) => (
				<div key={i} className="flex items-center gap-3 px-3 py-3">
					<div className="w-4 h-4 rounded bg-paper-3" />
					<div className="w-5 h-5 rounded bg-paper-3" />
					<div className="flex-1 space-y-2">
						<div className="flex items-center gap-2">
							<div className="h-3 w-24 rounded bg-paper-3" />
							<div className="h-3 w-4 rounded bg-paper-3" />
							<div className="h-3 flex-1 rounded bg-paper-3" />
							<div className="h-3 w-12 rounded bg-paper-3" />
						</div>
						<div className="h-2.5 w-3/4 rounded bg-paper-3" />
					</div>
				</div>
			))}
		</div>
	);
}

function FolderEmptyState({
	folder,
	onCompose,
}: {
	folder?: string;
	onCompose: () => void;
}) {
	const config = (folder && FOLDER_EMPTY_STATES[folder]) || {
		icon: (
			<EnvelopeSimpleIcon size={48} weight="thin" className="text-ink-3" />
		),
		title: "No emails",
		description: "This folder is empty.",
	};

	return (
		<div className="flex flex-col items-center justify-center py-24 px-6 text-center">
			<div className="mb-4">{config.icon}</div>
			<h3 className="text-base font-semibold text-ink mb-1.5">
				{config.title}
			</h3>
			<p className="text-sm text-ink-3 max-w-xs mb-5">
				{config.description}
			</p>
			{"showCompose" in config && config.showCompose && (
				<Button
					variant="primary"
					size="sm"
					icon={<PencilSimpleIcon size={16} />}
					onClick={onCompose}
				>
					Compose
				</Button>
			)}
		</div>
	);
}

export default function EmailListRoute() {
	const { mailboxId, folder } = useParams<{
		mailboxId: string;
		folder: string;
	}>();
	const {
		selectedEmailId,
		isComposing,
		selectEmail,
		closePanel,
		startCompose,
	} = useUIStore();
	const [page, setPage] = useState(1);
	const [searchParams, setSearchParams] = useSearchParams();

	const queryClient = useQueryClient();
	const updateEmail = useUpdateEmail();
	const markThreadRead = useMarkThreadRead();
	const deleteEmail = useDeleteEmail();
	const feedback = useFeedback();

	const params = useMemo(
		() => ({
			folder: folder || "",
			page: String(page),
			limit: String(PAGE_SIZE),
		}),
		[folder, page],
	);

	// Live updates arrive via the per-mailbox WebSocket subscription mounted
	// in `app/routes/mailbox.tsx`, which invalidates this query on each new
	// email. The manual refresh button below remains as an explicit fallback.
	const {
		data: emailData,
		isFetching: isRefreshing,
	} = useEmails(mailboxId, params);

	const emails = emailData?.emails ?? [];
	const totalCount = emailData?.totalCount ?? 0;

	const { data: folders = [] } = useFolders(mailboxId);

	const folderName = useMemo(() => {
		const found = folders.find((f) => f.id === folder);
		if (found) return found.name;
		return folder ? folder.charAt(0).toUpperCase() + folder.slice(1) : "Inbox";
	}, [folders, folder]);

	const isPanelOpen = selectedEmailId !== null || isComposing;
	const showCompose = !!(folder && FOLDER_EMPTY_STATES[folder]?.showCompose);

	// Track folder identity to detect folder changes vs page changes
	const prevFolderRef = useRef<string | undefined>(undefined);

	useEffect(() => {
		const folderChanged = prevFolderRef.current !== `${mailboxId}/${folder}`;
		prevFolderRef.current = `${mailboxId}/${folder}`;

		if (folderChanged) {
			closePanel();
			setPage(1);
		}
	}, [mailboxId, folder, closePanel]);

	// Deep-link support (issue #563): opening `?email=<id>` (e.g. from an
	// operator notification webhook) auto-selects that message's reading
	// panel, then drops the param so it doesn't re-trigger on refetch/refresh.
	useEffect(() => {
		const emailId = searchParams.get("email");
		if (!emailId) return;
		selectEmail(emailId);
		setSearchParams(
			(prev) => {
				const next = new URLSearchParams(prev);
				next.delete("email");
				return next;
			},
			{ replace: true },
		);
	}, [searchParams, selectEmail, setSearchParams]);

	const toggleStar = (email: Email) => {
		if (mailboxId)
			updateEmail.mutate(
				{ mailboxId, id: email.id, data: { starred: !email.starred } },
				{ onError: () => feedback.error("Couldn't update email.") },
			);
	};

	const toggleRead = (email: Email) => {
		if (mailboxId)
			updateEmail.mutate(
				{ mailboxId, id: email.id, data: { read: !email.read } },
				{ onError: () => feedback.error("Couldn't update email.") },
			);
	};

	const handleDelete = (emailId: string) => {
		if (mailboxId) {
			const confirmed = window.confirm("Are you sure you want to delete this email?");
			if (!confirmed) return;
			deleteEmail.mutate(
				{ mailboxId, id: emailId },
				{ onError: () => feedback.error("Couldn't delete email.") },
			);
			if (selectedEmailId === emailId) closePanel();
		}
	};

	const handleRefresh = () => {
		if (mailboxId) {
			queryClient.invalidateQueries({ queryKey: ["emails", mailboxId] });
			queryClient.invalidateQueries({
				queryKey: queryKeys.folders.list(mailboxId),
			});
		}
	};

	const handleRowClick = (email: Email) => {
		selectEmail(email.id);
		if (mailboxId && hasUnread(email)) {
			if (email.thread_id && email.thread_count && email.thread_count > 1) {
				markThreadRead.mutate(
					{
						mailboxId,
						threadId: email.thread_id,
					},
					{ onError: () => feedback.error("Couldn't mark thread read.") },
				);
			} else {
				updateEmail.mutate(
					{
						mailboxId,
						id: email.id,
						data: { read: true },
					},
					{ onError: () => feedback.error("Couldn't update email.") },
				);
			}
		}
	};

	return (
		<MailboxSplitView
			selectedEmailId={selectedEmailId}
			isComposing={isComposing}
		>
				{/* Folder header */}
				<div className="flex items-center justify-between px-4 py-3.5 border-b border-line shrink-0 md:px-5">
					<h1 className="pp-serif text-ink">
						{folderName}
					</h1>
					<div className="flex items-center gap-1">
						{totalCount > 0 && (
							<span className="text-sm text-ink-3 mr-2 hidden sm:inline">
								{totalCount} conversation{totalCount !== 1 ? "s" : ""}
							</span>
						)}
						{showCompose && (
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
						)}
						<Tooltip
							content={isRefreshing ? "Refreshing..." : "Refresh"}
							side="bottom"
							asChild
						>
							<Button
								variant="ghost"
								shape="square"
								size="sm"
								icon={
									<ArrowsClockwiseIcon
										size={18}
										className={isRefreshing ? "animate-spin" : ""}
									/>
								}
								onClick={handleRefresh}
								disabled={isRefreshing}
								aria-label="Refresh"
							/>
						</Tooltip>
					</div>
				</div>

				{/* Email rows */}
				<div className="flex-1 overflow-y-auto">
				{isRefreshing && emails.length === 0 ? (
					<EmailListSkeleton />
				) : emails.length > 0 ? (
						<div>
							{emails.map((email) => (
								<EmailListRow
									key={email.id}
									email={email}
									isSelected={selectedEmailId === email.id}
									compact={isPanelOpen}
									onOpen={() => handleRowClick(email)}
									onToggleStar={() => toggleStar(email)}
									onToggleRead={() => toggleRead(email)}
									onDelete={() => handleDelete(email.id)}
								/>
							))}
						</div>
					) : (
						<FolderEmptyState
							folder={folder}
							onCompose={() => startCompose()}
						/>
					)}
				</div>

				{/* Pagination */}
				{totalCount > PAGE_SIZE && (
					<div className="flex justify-center py-3 border-t border-line shrink-0">
						<Pagination
							page={page}
							setPage={setPage}
							perPage={PAGE_SIZE}
							totalCount={totalCount}
						/>
					</div>
				)}
		</MailboxSplitView>
	);
}
