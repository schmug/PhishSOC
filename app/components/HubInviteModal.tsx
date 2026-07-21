// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Two-state modal for issuing a one-time hub invite token (#74).
 *
 *   form    → user enters optional note and TTL (default 72h), clicks Issue.
 *   success → modal swaps to a read-only token field with a Copy button,
 *             a one-time warning, and the absolute expiry timestamp.
 *
 * The token never persists outside the lifetime of this open modal. Closing
 * the dialog (X button, ESC, backdrop click, or Cancel/Done) drops it from
 * React state via the `onOpenChange={false}` reset path; remounting the
 * modal from the same parent button does not surface a stale token because
 * we also clear the mutation result so a fresh open shows the form again.
 */

import { Button, Dialog, Input, Text } from "@cloudflare/kumo";
import { CopyIcon, WarningIcon } from "@phosphor-icons/react";
import {
	type FormEvent,
	useCallback,
	useEffect,
	useRef,
	useState,
} from "react";
import { formatStandardDate } from "shared/dates";
import { useCreateHubInvite } from "~/queries/hub";

export interface HubInviteModalProps {
	open: boolean;
	mailboxId: string | undefined;
	sharingGroup: { uuid: string; name: string } | null;
	onOpenChange: (open: boolean) => void;
}

export default function HubInviteModal({
	open,
	mailboxId,
	sharingGroup,
	onOpenChange,
}: HubInviteModalProps) {
	const mutation = useCreateHubInvite();
	const [note, setNote] = useState("");
	const [ttlHours, setTtlHours] = useState<number>(72);
	const [errorMessage, setErrorMessage] = useState<string | null>(null);
	// Token lives in local state during the open modal. We deliberately do
	// NOT pull it from `mutation.data` for rendering — clearing local state
	// on close is the source of truth that the token is gone from the DOM.
	const [token, setToken] = useState<string | null>(null);
	const [expiresAt, setExpiresAt] = useState<string | null>(null);
	const [copyState, setCopyState] = useState<"idle" | "copied" | "fallback">(
		"idle",
	);
	const tokenInputRef = useRef<HTMLInputElement | null>(null);

	const reset = useCallback(() => {
		setNote("");
		setTtlHours(72);
		setErrorMessage(null);
		setToken(null);
		setExpiresAt(null);
		setCopyState("idle");
		mutation.reset();
	}, [mutation]);

	const handleOpenChange = useCallback(
		(next: boolean) => {
			if (!next) {
				// Drop the token from React state immediately on any close
				// reason (X, ESC, backdrop click, Cancel, Done).
				reset();
			}
			onOpenChange(next);
		},
		[onOpenChange, reset],
	);

	// If the parent flips `open` to false externally, still clear state.
	useEffect(() => {
		if (!open) reset();
		// `reset` identity changes when mutation changes; we only want this
		// to fire on `open` transitions, so deliberately omit `reset`.
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [open]);

	// When the success state lands, focus + select the token field so the
	// clipboard fallback (Cmd/Ctrl-C) just works without an extra click.
	useEffect(() => {
		if (token && tokenInputRef.current) {
			tokenInputRef.current.focus();
			tokenInputRef.current.select();
		}
	}, [token]);

	const handleSubmit = async (e: FormEvent) => {
		e.preventDefault();
		if (!mailboxId) return;
		setErrorMessage(null);
		try {
			const res = await mutation.mutateAsync({
				mailboxId,
				body: {
					sharing_group_uuid: sharingGroup?.uuid,
					note: note.trim() || undefined,
					ttl_hours: ttlHours,
				},
			});
			setToken(res.token);
			setExpiresAt(res.expires_at);
		} catch (err: unknown) {
			const msg =
				err instanceof Error && err.message
					? err.message
					: "Failed to create invite";
			setErrorMessage(msg);
		}
	};

	const handleCopy = async () => {
		if (!token) return;
		const clipboard =
			typeof navigator !== "undefined" ? navigator.clipboard : undefined;
		if (clipboard?.writeText) {
			try {
				await clipboard.writeText(token);
				setCopyState("copied");
				return;
			} catch {
				// fall through to manual fallback
			}
		}
		// Clipboard unavailable or denied — keep input focused and selected
		// so the user can Cmd-C/Ctrl-C from the keyboard.
		setCopyState("fallback");
		if (tokenInputRef.current) {
			tokenInputRef.current.focus();
			tokenInputRef.current.select();
		}
	};

	return (
		<Dialog.Root open={open} onOpenChange={handleOpenChange}>
			<Dialog size="sm" className="p-6">
				<Dialog.Title className="text-base font-semibold mb-1">
					Invite peer
				</Dialog.Title>
				{sharingGroup ? (
					<Dialog.Description className="text-ink-3 text-sm mb-5">
						Issue a one-time invite to{" "}
						<strong className="text-ink">{sharingGroup.name}</strong>.
					</Dialog.Description>
				) : null}

				{!token ? (
					<form onSubmit={handleSubmit} className="space-y-4">
						{errorMessage ? (
							<Text variant="error" size="sm">
								{errorMessage}
							</Text>
						) : null}
						<Input
							label="Note (optional)"
							placeholder="What's this invite for?"
							size="sm"
							value={note}
							onChange={(e) => setNote(e.target.value)}
							maxLength={500}
						/>
						<Input
							label="TTL (hours)"
							type="number"
							size="sm"
							min={1}
							max={24 * 30}
							value={String(ttlHours)}
							onChange={(e) => {
								const n = Number(e.target.value);
								if (Number.isFinite(n)) setTtlHours(n);
							}}
						/>
						<div className="flex justify-end gap-2 pt-2">
							<Dialog.Close
								render={(props) => (
									<Button
										{...props}
										variant="secondary"
										size="sm"
										type="button"
									>
										Cancel
									</Button>
								)}
							/>
							<Button
								type="submit"
								variant="primary"
								size="sm"
								loading={mutation.isPending}
							>
								Issue invite
							</Button>
						</div>
					</form>
				) : (
					<div className="space-y-4">
						<div className="flex items-start gap-2 rounded-md bg-paper-2 border border-line p-3 text-[12.5px] text-ink">
							<WarningIcon size={16} className="mt-[1px] shrink-0" />
							<div>
								<div className="font-medium">
									Copy this token now — it won't be shown again.
								</div>
								<div className="text-ink-3 mt-0.5">
									Share it with the peer through a trusted channel. They redeem
									it via <span className="pp-mono">/orgs/accept</span>.
								</div>
							</div>
						</div>
						<div>
							<span className="text-sm font-medium text-ink mb-1.5 block">
								Invite token
							</span>
							<div className="flex items-center gap-2">
								<div className="flex-1">
									<Input
										ref={tokenInputRef}
										aria-label="Invite token"
										readOnly
										size="sm"
										value={token}
										className="pp-mono"
										onFocus={(e) => e.currentTarget.select()}
									/>
								</div>
								<Button
									type="button"
									variant="secondary"
									size="sm"
									icon={<CopyIcon size={14} />}
									onClick={handleCopy}
								>
									{copyState === "copied"
										? "Copied"
										: copyState === "fallback"
											? "Press Cmd-C"
											: "Copy"}
								</Button>
							</div>
							{copyState === "fallback" ? (
								<p className="text-[11.5px] text-ink-3 mt-1">
									Clipboard access denied. The token is selected — press Cmd-C
									(macOS) or Ctrl-C (Windows/Linux) to copy.
								</p>
							) : null}
						</div>
						{expiresAt ? (
							<div className="text-[12px] text-ink-3">
								Expires {formatStandardDate(expiresAt)}
							</div>
						) : null}
						<div className="flex justify-end pt-2">
							<Button
								type="button"
								variant="primary"
								size="sm"
								onClick={() => handleOpenChange(false)}
							>
								Done
							</Button>
						</div>
					</div>
				)}
			</Dialog>
		</Dialog.Root>
	);
}
