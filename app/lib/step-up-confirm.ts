// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Client step-up relay for Tier ≥1 sends (issue #285, reworked for #376).
 *
 * Replaces the Cloudflare Access popup + postMessage relay — which looped
 * forever because a second Access app on the same hostname emitted a colliding
 * CF_Authorization cookie — with an in-page WebAuthn assertion:
 *
 *   1. POST authenticate/options {mailboxId, tier, payload} → a fresh,
 *      payload-bound challenge.
 *   2. navigator.credentials.get() via startAuthentication() — no popup, no
 *      cross-site redirect.
 *   3. POST authenticate/verify {…, assertion} → the one-shot confirm token.
 *
 * The token is bound server-side to a SHA-256 hash of
 * {to, cc, bcc, subject, body, attachmentIds}. Callers MUST pass the exact
 * values the email send will use — do not re-normalize between preflight,
 * confirm, and send or the server payloadHash check rejects the token.
 *
 * The signature and Promise<string> return type are UNCHANGED from the popup
 * version, so useComposeForm / EmailPanel callers need no edits.
 */

import { startAuthentication } from "@simplewebauthn/browser";
import api from "~/services/api";

export interface StepUpPayload {
	tier: 0 | 1 | 2;
	mailboxId: string;
	to: string | string[];
	cc?: string | string[];
	bcc?: string | string[];
	subject: string;
	/** Exactly `html || text || ""` of the outgoing message. */
	body: string;
	attachmentIds: string[];
}

/**
 * Thrown when the account has no enrolled passkey, so the caller can route the
 * user to enrollment ("enroll a passkey") instead of showing a raw error
 * (issue #376 enrollment-first rollout).
 */
export class StepUpNoPasskeyError extends Error {
	constructor(message = "No passkey is enrolled for this account.") {
		super(message);
		this.name = "StepUpNoPasskeyError";
	}
}

/** Map a WebAuthn ceremony failure to a user-presentable message. */
function humanizeAssertionError(err: unknown): string {
	const name = err instanceof Error ? err.name : "";
	if (name === "NotAllowedError") {
		return "Step-up was cancelled or timed out. Please try again.";
	}
	if (name === "SecurityError") {
		return "Step-up could not run on this origin. Contact your administrator.";
	}
	const message = err instanceof Error ? err.message : "";
	return message || "Step-up confirmation failed.";
}

/**
 * Run the WebAuthn step-up and resolve with a one-shot confirmation token, or
 * reject with a user-presentable Error (no passkey, cancelled, or relay error).
 */
export async function requestStepUpConfirmation(
	payload: StepUpPayload,
	_opts: { timeoutMs?: number } = {},
): Promise<string> {
	const request = {
		mailboxId: payload.mailboxId,
		tier: payload.tier,
		payload: {
			to: payload.to,
			cc: payload.cc,
			bcc: payload.bcc,
			subject: payload.subject,
			body: payload.body,
			attachmentIds: payload.attachmentIds,
		},
	};

	const options = await api.webauthnAuthenticateOptions(request);
	if (!options.allowCredentials || options.allowCredentials.length === 0) {
		throw new StepUpNoPasskeyError();
	}

	let assertion;
	try {
		assertion = await startAuthentication({ optionsJSON: options });
	} catch (err) {
		throw new Error(humanizeAssertionError(err));
	}

	const { token } = await api.webauthnAuthenticateVerify({ ...request, assertion });
	return token;
}
