// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Banner, Button, Dialog, Input, Text } from "@cloudflare/kumo";
import { FloppyDiskIcon, PaperPlaneTiltIcon } from "@phosphor-icons/react";
import { useParams } from "react-router";
import { useComposeForm } from "~/hooks/useComposeForm";
import RichTextEditor from "./RichTextEditor";
import SendRiskReasons from "./SendRiskReasons";
import { useUIStore } from "~/hooks/useUIStore";

export default function ComposeEmail() {
	const { mailboxId, folder } = useParams<{
		mailboxId: string;
		folder: string;
	}>();
	
	const { isComposeModalOpen, closeComposeModal } = useUIStore();

	const {
		to,
		setTo,
		cc,
		setCc,
		bcc,
		setBcc,
		showCcBcc,
		setShowCcBcc,
		subject,
		setSubject,
		body,
		setBody,
		error,
		isSavingDraft,
		isSending,
		preflight,
		confirmPhrase,
		setConfirmPhrase,
		formTitle,
		handleSaveDraft,
		handleSend,
	} = useComposeForm(mailboxId, folder);

	const sendTier = preflight?.tier ?? 0;
	const sendLabel = sendTier === 2 ? "Send (verify)" : sendTier === 1 ? "Send (re-auth)" : "Send";
	const sendTestId = sendTier === 2 ? "send-button-tier2" : sendTier === 1 ? "send-button-tier1" : "send-button-tier0";
	const primaryRecipient = to.split(/[,;]/)[0].trim();

	return (
		<Dialog.Root
			open={isComposeModalOpen}
			onOpenChange={(open) => !open && !isSending && closeComposeModal()}
		>
			<Dialog size="lg" className="p-6 max-h-[85vh] overflow-y-auto">
				<Dialog.Title className="text-lg font-semibold mb-5">
					{formTitle}
				</Dialog.Title>
				<form onSubmit={(e) => handleSend(e, closeComposeModal)} className="space-y-4">
					{error && <Banner variant="error" text={error} />}
					<div className="flex items-center gap-2">
						<div className="flex-1">
							<Input
								label="To"
								type="text"
								placeholder="recipient@example.com, another@example.com"
								size="sm"
								value={to}
								onChange={(e) => setTo(e.target.value)}
								required
							/>
						</div>
						{!showCcBcc && (
							<button
								type="button"
								onClick={() => setShowCcBcc(true)}
								className="shrink-0 text-xs text-accent hover:text-accent-2 font-medium mt-5"
							>
								CC / BCC
							</button>
						)}
					</div>
					{showCcBcc && (
						<Input
							label="CC"
							type="text"
							size="sm"
							value={cc}
							onChange={(e) => setCc(e.target.value)}
							placeholder="Separate multiple addresses with commas"
						/>
					)}
					{showCcBcc && (
						<Input
							label="BCC"
							type="text"
							size="sm"
							value={bcc}
							onChange={(e) => setBcc(e.target.value)}
							placeholder="Separate multiple addresses with commas"
						/>
					)}
					<Input
						label="Subject"
						type="text"
						placeholder="Email subject"
						size="sm"
						value={subject}
						onChange={(e) => setSubject(e.target.value)}
						required
					/>
					<div>
						<Text size="sm" DANGEROUS_className="font-medium mb-1.5 block">
							Message
						</Text>
						<RichTextEditor value={body} onChange={setBody} />
					</div>
					<SendRiskReasons reasons={preflight?.reasons} />
					{sendTier >= 2 && (
						<div className="mt-2">
							<Input
								label={`Type "${primaryRecipient}" to confirm`}
								type="text"
								size="sm"
								value={confirmPhrase}
								onChange={(e) => setConfirmPhrase(e.target.value)}
								data-testid="confirm-phrase-input"
							/>
						</div>
					)}
					<div className="flex justify-between items-center pt-2">
						<Button
							type="button"
							variant="ghost"
							size="sm"
							onClick={closeComposeModal}
							disabled={isSending}
						>
							Discard
						</Button>
						<div className="flex items-center gap-2">
							<Button
								type="button"
								variant="secondary"
								size="sm"
								loading={isSavingDraft}
								disabled={isSending}
								icon={<FloppyDiskIcon size={14} />}
								onClick={handleSaveDraft}
							>
								{isSavingDraft ? "Saving..." : "Save as Draft"}
							</Button>
							<Button
								type="submit"
								variant="primary"
								size="sm"
								loading={isSending}
								disabled={isSavingDraft || isSending}
								icon={<PaperPlaneTiltIcon size={14} />}
								data-testid={sendTestId}
							>
								{isSending ? "Sending..." : sendLabel}
							</Button>
						</div>
					</div>
				</form>
			</Dialog>
		</Dialog.Root>
	);
}
