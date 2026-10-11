// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Button, Tooltip } from "@cloudflare/kumo";
import { ShieldCheckIcon } from "@phosphor-icons/react";
import { useState } from "react";
import { useFeedback } from "~/lib/feedback";

/**
 * Record that a flagged email is legitimate (false positive). Counterpart of
 * ReportPhishButton. The server stores one label per email, so repeat clicks
 * are harmless. The label is stored for eval/export only — it does not change
 * the verdict, score or any blocklist.
 */
export default function NotPhishButton({
	mailboxId,
	emailId,
}: {
	mailboxId?: string;
	emailId: string;
}) {
	const feedback = useFeedback();
	const [pending, setPending] = useState(false);

	const handle = async () => {
		if (!mailboxId) return;
		setPending(true);
		try {
			const res = await fetch(
				`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/emails/${encodeURIComponent(emailId)}/not-phish`,
				{ method: "POST" },
			);
			if (!res.ok) throw new Error(await res.text());
			feedback.success("Marked as not phish.");
		} catch (e) {
			feedback.error(`Could not record label: ${(e as Error).message}`);
		} finally {
			setPending(false);
		}
	};

	return (
		<Tooltip content="Not phish" side="bottom" asChild>
			<Button
				variant="ghost"
				shape="square"
				size="sm"
				icon={<ShieldCheckIcon size={18} />}
				onClick={handle}
				loading={pending}
				aria-label="Not phish"
			/>
		</Tooltip>
	);
}
