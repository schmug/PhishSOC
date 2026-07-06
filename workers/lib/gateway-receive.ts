// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Gateway passthrough for unregistered recipients (issue #32).
 *
 * A gateway fronting a whole domain receives mail for backend users with
 * no PhishSOC mailbox. Score with domain-tier settings (stateless — no
 * MailboxDO is created), cap quarantine/block at `tag` (nothing to hold
 * into; mirrors learning_mode's cap), and relay. Nothing is stored.
 *
 * Failure semantics differ from the registered path: there is no mirror
 * copy, so PERMANENT relay failures also throw — bouncing at the origin
 * is the only honest outcome (see relayAfterVerdict's passthrough flag).
 */

import type { Env } from "../types";
import type { GatewayInbound } from "../providers/types";
import type { FinalVerdict } from "../security/verdict";
import { runSecurityPipeline } from "../security";
import { getDomainSettings } from "./domain-settings";
import { resolveRelayPolicy } from "./relay-policy";
import { relayAfterVerdict } from "./gateway-relay";
import { Folders } from "../../shared/folders";

export async function receiveGatewayPassthrough(
	normalized: GatewayInbound,
	env: Env,
	ctx: ExecutionContext,
): Promise<void> {
	const { parsedEmail, recipient, domain, envelopeFrom } = normalized;
	const policy = resolveRelayPolicy(await getDomainSettings(env, domain));
	if (!policy) {
		// Policy changed between normalizeInbound and here — nothing to do.
		console.log("gateway passthrough: no relay policy for", domain, "- dropping");
		return;
	}

	let verdict: FinalVerdict | null = null;
	try {
		const result = await runSecurityPipeline({
			env,
			// Settings resolution only: an unregistered id falls through
			// mailbox(absent) → domain → org tiers. stateless=true means no
			// MailboxDO is created or written for this address.
			mailboxId: recipient,
			messageId: crypto.randomUUID(),
			targetFolder: Folders.INBOX,
			stateless: true,
			parsedEmail: {
				subject: parsedEmail.subject,
				from: parsedEmail.from,
				html: parsedEmail.html,
				text: parsedEmail.text,
				headers: parsedEmail.headers,
				attachments: parsedEmail.attachments?.map((a) => ({
					filename: a.filename ?? null,
					mimeType: a.mimeType ?? null,
				})),
			},
		});
		verdict = result.verdict;
	} catch (e) {
		// Fail open: a gateway must never eat mail because scanning broke.
		console.error("gateway passthrough: pipeline failed; relaying unscanned:", (e as Error).message);
	}

	// Tag-cap: no mailbox to quarantine into. Same cap learning_mode applies.
	if (verdict && (verdict.action === "quarantine" || verdict.action === "block")) {
		verdict = { ...verdict, action: "tag" };
	}

	await relayAfterVerdict({
		env,
		ctx,
		raw: new Uint8Array(normalized.rawEmail),
		verdict,
		policy,
		envelopeFrom,
		rcptTo: recipient,
		passthrough: true,
	});
}
