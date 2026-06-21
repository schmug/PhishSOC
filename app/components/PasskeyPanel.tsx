// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Button } from "@cloudflare/kumo";
import { KeyIcon } from "@phosphor-icons/react";
import { useState } from "react";
import { useFeedback } from "~/lib/feedback";
import { enrollPasskey } from "~/lib/webauthn-enroll";

/**
 * Passkey enrollment surface (issue #376). A passkey is the second factor for
 * risky (Tier ≥1) sends: the server demands a fresh, payload-bound WebAuthn
 * assertion before it will mint a send-confirm token. Enrollment is per-user
 * (bound to the Access identity) and only available in an interactive browser
 * session — there is no agent or service-token path to it.
 *
 * The first key is a single ceremony; adding another key first re-verifies an
 * existing one (handled inside enrollPasskey). Lost-key recovery is admin-
 * mediated only — there is intentionally no self-serve reset here.
 */
export function PasskeyPanel() {
	const feedback = useFeedback();
	const [enrolling, setEnrolling] = useState(false);

	const onEnroll = async () => {
		setEnrolling(true);
		try {
			const { firstKey } = await enrollPasskey();
			feedback.success(
				firstKey
					? "Passkey enrolled. Risky sends now require this passkey."
					: "Additional passkey enrolled.",
			);
		} catch (err) {
			feedback.error(err instanceof Error ? err.message : "Passkey enrollment failed.");
		} finally {
			setEnrolling(false);
		}
	};

	return (
		<div className="pp-card p-5">
			<div className="flex items-center gap-2 mb-2">
				<KeyIcon size={16} weight="duotone" className="text-ink-3" />
				<span className="text-sm font-medium text-ink">Passkeys</span>
			</div>
			<p className="text-xs text-ink-3 mb-4 max-w-md">
				Risky sends (external recipients, payment/credential keywords) require a
				passkey confirmation at send time. Enroll a platform passkey (Touch ID,
				Windows Hello) or a security key. Adding another key re-verifies an
				existing one first; a lost key is recovered by an administrator only.
			</p>
			<Button onClick={onEnroll} disabled={enrolling} data-testid="enroll-passkey-button">
				{enrolling ? "Waiting for passkey…" : "Add a passkey"}
			</Button>
		</div>
	);
}
