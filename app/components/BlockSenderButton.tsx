// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Banner, Button, Dialog, Tooltip } from "@cloudflare/kumo";
import { ProhibitIcon } from "@phosphor-icons/react";
import { useState } from "react";
import {
	DEFAULT_REJECT_REASON,
	SHARED_SENDER_DOMAINS,
	registrableDomain,
	type BlockAction,
} from "shared/blocklist";
import { useFeedback } from "~/lib/feedback";
import api, { ApiError } from "~/services/api";
import type { Email } from "~/types";

/**
 * "Block sender" toolbar action (spec 2026-09-27-sender-blocklist). Writes a
 * mailbox-tier rule via POST /api/v1/mailboxes/:id/blocklist. Default match
 * is the full address, default action is Spam. The server re-validates
 * everything; the shared-domain confirm here only mirrors its 400.
 */
export default function BlockSenderButton({
	mailboxId,
	email,
	isSidecar = false,
}: {
	mailboxId?: string;
	email: Email;
	isSidecar?: boolean;
}) {
	const feedback = useFeedback();
	const [open, setOpen] = useState(false);
	const sender = (email.sender || "").trim().toLowerCase();
	const senderDomain = sender.slice(sender.lastIndexOf("@") + 1);
	const regDomain = senderDomain ? registrableDomain(senderDomain) : "";
	const matchOptions = [sender, regDomain, senderDomain].filter(
		(v, i, all) => v && all.indexOf(v) === i,
	);

	const [match, setMatch] = useState(sender);
	const [action, setAction] = useState<BlockAction>("spam");
	const [reason, setReason] = useState(DEFAULT_REJECT_REASON);
	const [moveExisting, setMoveExisting] = useState(true);
	const [confirmed, setConfirmed] = useState(false);
	const [serverWantsConfirm, setServerWantsConfirm] = useState<string | null>(null);
	const [pending, setPending] = useState(false);

	const isDomain = !match.includes("@");
	const needsConfirm =
		isDomain && (SHARED_SENDER_DOMAINS.has(match) || serverWantsConfirm === match);
	const auth = parseAuth(email.security_verdict);
	const unauthenticated = !(auth?.dmarc === "pass" && auth?.trusted === true);

	const submit = async () => {
		if (!mailboxId) return;
		setPending(true);
		try {
			const body: Record<string, unknown> = { match, action, move_existing: moveExisting };
			if (action === "reject") body.reason = reason;
			if (needsConfirm && confirmed) body.confirm_shared_domain = true;
			const data = await api.addBlockRule({ tier: "mailbox", mailboxId }, body);
			feedback.success(`Blocked ${match}. Moved ${data.moved ?? 0} existing message(s) to Spam.`);
			setOpen(false);
		} catch (e) {
			if (e instanceof ApiError && e.status === 400 && e.body.code === "shared_domain_unconfirmed") {
				setServerWantsConfirm(match);
				setConfirmed(false);
				return;
			}
			feedback.error(`Block failed: ${(e as Error).message}`);
		} finally {
			setPending(false);
		}
	};

	const actionOptions: Array<{ value: BlockAction; label: string }> = [
		{ value: "spam", label: "Move to Spam" },
		{ value: "drop", label: "Drop silently" },
		{
			value: "reject",
			label: isSidecar
				? "Bounce (unavailable for Google Workspace — will drop)"
				: "Bounce with message",
		},
	];

	return (
		<Dialog.Root open={open} onOpenChange={setOpen}>
			<Tooltip content="Block sender" side="bottom" asChild>
				<Button
					variant="ghost"
					shape="square"
					size="sm"
					icon={<ProhibitIcon size={18} />}
					onClick={() => setOpen(true)}
					disabled={!mailboxId || !sender.includes("@")}
					aria-label="Block sender"
				/>
			</Tooltip>
			<Dialog size="sm" className="p-6">
				<Dialog.Title className="text-base font-semibold mb-1">Block sender</Dialog.Title>
				<Dialog.Description className="text-ink-3 text-sm mb-4">
					Future mail matching this rule is handled automatically for this mailbox.
				</Dialog.Description>
				<div className="space-y-4">
					{unauthenticated ? (
						<Banner
							variant="error"
							text="This message's sender is not authenticated — the From address may be forged. Blocking it may block the real sender."
						/>
					) : null}
					<fieldset className="space-y-1.5">
						<legend className="text-sm font-medium text-ink mb-1">Block</legend>
						<div role="radiogroup" aria-label="Block" className="space-y-1">
							{matchOptions.map((opt) => (
								<label key={opt} className="flex items-center gap-2 text-[13px] text-ink-2">
									<input
										type="radio"
										name="block-match"
										value={opt}
										checked={match === opt}
										onChange={() => {
											setMatch(opt);
											setConfirmed(false);
										}}
										className="h-3.5 w-3.5 accent-accent"
									/>
									<span>{opt.includes("@") ? opt : `${opt} (and subdomains)`}</span>
								</label>
							))}
						</div>
					</fieldset>
					<fieldset className="space-y-1.5">
						<legend className="text-sm font-medium text-ink mb-1">Action</legend>
						<div role="radiogroup" aria-label="Action" className="space-y-1">
							{actionOptions.map((opt) => (
								<label key={opt.value} className="flex items-center gap-2 text-[13px] text-ink-2">
									<input
										type="radio"
										name="block-action"
										value={opt.value}
										checked={action === opt.value}
										onChange={() => setAction(opt.value)}
										className="h-3.5 w-3.5 accent-accent"
									/>
									<span>{opt.label}</span>
								</label>
							))}
						</div>
					</fieldset>
					{action === "reject" ? (
						<textarea
							aria-label="Bounce message"
							maxLength={200}
							rows={2}
							value={reason}
							onChange={(e) => setReason(e.target.value)}
							className="w-full rounded-md border border-line bg-paper px-3 py-2 text-[13px] text-ink focus:outline-none focus:border-line-strong"
						/>
					) : null}
					<label className="flex items-center gap-2 text-[13px] text-ink-2">
						<input
							type="checkbox"
							checked={moveExisting}
							onChange={(e) => setMoveExisting(e.target.checked)}
							className="h-3.5 w-3.5 accent-accent"
						/>
						<span>Also move existing mail from this sender to Spam</span>
					</label>
					{needsConfirm ? (
						<label className="flex items-center gap-2 text-[13px] text-ink-2">
							<input
								type="checkbox"
								checked={confirmed}
								onChange={(e) => setConfirmed(e.target.checked)}
								className="h-3.5 w-3.5 accent-accent"
							/>
							<span>I understand this blocks every sender at {match}</span>
						</label>
					) : null}
					<div className="flex justify-end gap-2 pt-2">
						<Dialog.Close
							render={(props) => (
								<Button {...props} variant="secondary" size="sm" type="button">
									Cancel
								</Button>
							)}
						/>
						<Button
							variant="primary"
							size="sm"
							onClick={submit}
							loading={pending}
							disabled={pending || (needsConfirm && !confirmed)}
						>
							Block
						</Button>
					</div>
				</div>
			</Dialog>
		</Dialog.Root>
	);
}

function parseAuth(raw: string | null | undefined): { dmarc?: string; trusted?: boolean } | null {
	if (!raw) return null;
	try {
		return (JSON.parse(raw) as { auth?: { dmarc?: string; trusted?: boolean } }).auth ?? null;
	} catch {
		return null;
	}
}
