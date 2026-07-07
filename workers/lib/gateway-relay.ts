// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Verdict → relay orchestration for inline-gateway mode (issue #32).
 *
 * Called from `receiveEmail` (registered mailboxes; mirror copy already
 * stored) and `receiveGatewayPassthrough` (unregistered recipients; no
 * local copy). Maps the verdict through the domain's action table, then
 * for relaying behaviors: prepend X-PhishPilot verdict headers, ARC-seal
 * (best-effort), and submit to the policy target.
 *
 * Error policy:
 * - transient SMTP failure  → rethrow (CF defers; origin MTA retries)
 * - permanent SMTP failure  → registered: alert + "failed_permanent";
 *                             passthrough: rethrow (bounce — no local copy)
 * - seal failure            → alert + relay unsealed (deliverability
 *                             degrades; delivery never blocked on crypto)
 * - null verdict            → relay untouched (fail-open: a gateway must
 *                             never eat mail because scanning broke)
 */

import type { Env } from "../types";
import type { FinalVerdict } from "../security/verdict";
import { behaviorFor, type ResolvedRelayPolicy } from "./relay-policy";
import { latin1Encode, sealMessage } from "./arc-seal";
import { getOrgSettings } from "./org-settings";
import { dispatchSecurityAlert, type AlertExecutionContext } from "./security-alert";
import { SmtpPermanentError } from "./smtp-client";
import { smtpRelayProvider, type RelayEnvelope } from "../providers/smtp-relay";

export type RelayOutcome = "relayed" | "held" | "dropped" | "failed_permanent";

/** Prepend header lines (no CRLF of their own) to raw message bytes. */
export function prependHeaders(raw: Uint8Array, lines: string[]): Uint8Array {
	if (lines.length === 0) return raw;
	const block = latin1Encode(lines.map((l) => l + "\r\n").join(""));
	const out = new Uint8Array(block.length + raw.length);
	out.set(block, 0);
	out.set(raw, block.length);
	return out;
}

/** Prepend a pre-terminated (CRLF-ended) raw header block. */
function prependRawBlock(raw: Uint8Array, block: string): Uint8Array {
	const bytes = latin1Encode(block);
	const out = new Uint8Array(bytes.length + raw.length);
	out.set(bytes, 0);
	out.set(raw, bytes.length);
	return out;
}

export interface RelayAfterVerdictOptions {
	env: Env;
	ctx: AlertExecutionContext | undefined;
	raw: Uint8Array;
	verdict: FinalVerdict | null;
	policy: ResolvedRelayPolicy;
	envelopeFrom: string;
	rcptTo: string;
	passthrough?: boolean;
	relayFn?: (
		env: Env,
		raw: Uint8Array,
		envelope: RelayEnvelope,
		policy: ResolvedRelayPolicy,
	) => Promise<void>;
}

export async function relayAfterVerdict(opts: RelayAfterVerdictOptions): Promise<RelayOutcome> {
	const action = opts.verdict?.action ?? null;
	const behavior = behaviorFor(action, opts.policy, { passthrough: opts.passthrough });
	if (behavior === "hold") return "held";
	if (behavior === "drop") return "dropped";

	let outgoing = opts.raw;
	if (opts.verdict) {
		outgoing = prependHeaders(outgoing, [
			`X-PhishPilot-Verdict: ${opts.verdict.action}`,
			`X-PhishPilot-Score: ${opts.verdict.score}`,
		]);

		// ARC seal — best-effort. Sealing covers the verdict headers above.
		try {
			const gw = (await getOrgSettings(opts.env)).gateway;
			const pem = opts.env.ARC_SEAL_PRIVATE_KEY;
			if (gw?.arcSealerDomain && gw.arcSelector && pem) {
				const block = await sealMessage(outgoing, {
					auth: {
						spf: opts.verdict.auth.spf,
						dkim: opts.verdict.auth.dkim,
						dmarc: opts.verdict.auth.dmarc,
					},
					sealerDomain: gw.arcSealerDomain,
					selector: gw.arcSelector,
					privateKeyPem: pem,
				});
				if (block) outgoing = prependRawBlock(outgoing, block);
			}
		} catch (e) {
			console.error("gateway: ARC seal failed; relaying unsealed:", (e as Error).message);
			dispatchSecurityAlert(opts.env, opts.ctx, {
				type: "gateway_seal_failed",
				rcptTo: opts.rcptTo,
				error: (e as Error).message,
			});
		}
	}

	const relayFn = opts.relayFn ?? smtpRelayProvider.relayRaw.bind(smtpRelayProvider);
	try {
		await relayFn(opts.env, outgoing, { mailFrom: opts.envelopeFrom, rcptTo: opts.rcptTo }, opts.policy);
		return "relayed";
	} catch (e) {
		if (e instanceof SmtpPermanentError && !opts.passthrough) {
			console.error("gateway: permanent relay failure (mirror copy retained):", e.message);
			dispatchSecurityAlert(opts.env, opts.ctx, {
				type: "gateway_relay_failed",
				rcptTo: opts.rcptTo,
				target: opts.policy.target.host,
				error: e.message,
			});
			return "failed_permanent";
		}
		throw e;
	}
}
