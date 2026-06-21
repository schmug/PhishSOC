// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Out-of-band operator security alerts.
 *
 * A surreptitious first-passkey (TOFU) enrollment is the highest-risk window in
 * the WebAuthn step-up (#376): whoever lands the first credential for a `sub`
 * can mint confirm tokens for that identity's risky sends. The structured
 * `webauthn.first_key_registered` audit line is a forensic record, not an alert
 * — nobody is paged by a `console.log`. This module fans security events out to
 * an operator-configured webhook so they are *actively* detectable.
 *
 * Fire-and-forget by contract: a webhook that is slow, down, or misconfigured
 * MUST NOT block or fail the action it is reporting on. Every failure (a
 * synchronous throw constructing the request, an async network rejection, or a
 * non-2xx response) is caught and logged here — it never surfaces to the caller.
 * When an execution context is reachable the request is scheduled with
 * `waitUntil` so it outlives the handler's response; otherwise it is still
 * issued, pre-`catch`ed so it cannot become an unhandled rejection.
 */

import type { Env } from "../types";

/** Minimal execution-context shape — only `waitUntil` is needed here. */
export interface AlertExecutionContext {
	waitUntil(promise: Promise<unknown>): void;
}

/** Webhook request timeout — bounded so a hung endpoint can't pin a request. */
const ALERT_WEBHOOK_TIMEOUT_MS = 10_000;

/**
 * POST `payload` (JSON) to the configured `SECURITY_ALERT_WEBHOOK_URL`, if any.
 *
 * No-ops silently when the webhook is unconfigured. Never throws and never
 * rejects into the caller. When `ctx` is supplied the request is scheduled with
 * `waitUntil`; otherwise the request is still issued fire-and-forget.
 *
 * @param env      Worker env — read for the optional `SECURITY_ALERT_WEBHOOK_URL`.
 * @param ctx      Execution context (for `waitUntil`); `undefined` is tolerated.
 * @param payload  Any JSON-serialisable alert body.
 */
export function dispatchSecurityAlert(
	env: Pick<Env, "SECURITY_ALERT_WEBHOOK_URL">,
	ctx: AlertExecutionContext | undefined,
	payload: unknown,
): void {
	const url = env.SECURITY_ALERT_WEBHOOK_URL;
	if (!url) return;

	try {
		const request = fetch(url, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(payload),
			signal: AbortSignal.timeout(ALERT_WEBHOOK_TIMEOUT_MS),
		})
			.then((res) => {
				if (!res.ok) {
					console.error(`security alert webhook returned ${res.status}`);
				}
			})
			.catch((err: unknown) => {
				console.error(
					"security alert webhook failed:",
					err instanceof Error ? err.message : String(err),
				);
			});
		ctx?.waitUntil(request);
	} catch (err: unknown) {
		// A synchronous failure (e.g. fetch/AbortSignal construction) must not
		// propagate into the handler that is reporting the event.
		console.error(
			"security alert webhook dispatch error:",
			err instanceof Error ? err.message : String(err),
		);
	}
}
