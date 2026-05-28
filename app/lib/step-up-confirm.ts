// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Client relay for the Tier ≥1 step-up confirm flow (issue #285).
 *
 * Cloudflare Access step-up requires a top-level navigation to a
 * step-up-protected path. The only such path is `/api/v1/confirm`, so we
 * open it in a popup: the GET handler (workers/routes/confirm.ts) serves a
 * tiny relay page that — once Access has set the step-up cookie — POSTs the
 * preflighted payload back to the same path (Access injects the step-up
 * JWT), then `postMessage`s the one-shot confirmation token to this opener.
 *
 * The token is bound server-side to a SHA-256 hash of
 * {to, cc, bcc, subject, body, attachmentIds}. Callers MUST pass the exact
 * values the email send will use — do not re-normalize between preflight,
 * confirm, and send or the server payloadHash check rejects the token.
 */

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

const RELAY_PATH = "/api/v1/confirm";
const MSG_SOURCE = "phishsoc-confirm";
const DEFAULT_TIMEOUT_MS = 120_000;
const POLL_MS = 400;

interface RelayMessage {
	source?: unknown;
	type?: unknown;
	nonce?: unknown;
	token?: unknown;
	error?: unknown;
}

/**
 * Opens the step-up popup and resolves with a one-shot confirmation token,
 * or rejects with a user-presentable Error (popup blocked, popup closed,
 * relay error, or timeout). Always cleans up the listener, poll, and popup.
 */
export function requestStepUpConfirmation(
	payload: StepUpPayload,
	opts: { timeoutMs?: number } = {},
): Promise<string> {
	return new Promise<string>((resolve, reject) => {
		const popup = window.open(
			RELAY_PATH,
			"phishsoc-stepup",
			"popup,width=480,height=680",
		);
		if (!popup) {
			reject(
				new Error(
					"Step-up popup was blocked. Allow popups for this site and try sending again.",
				),
			);
			return;
		}

		const nonce =
			typeof crypto !== "undefined" && "randomUUID" in crypto
				? crypto.randomUUID()
				: String(Math.random()).slice(2);
		const origin = window.location.origin;
		let settled = false;
		let poll: ReturnType<typeof setInterval>;
		let timer: ReturnType<typeof setTimeout>;

		const cleanup = () => {
			window.removeEventListener("message", onMessage);
			clearInterval(poll);
			clearTimeout(timer);
			try {
				if (!popup.closed) popup.close();
			} catch {
				/* cross-origin during Access leg — ignore */
			}
		};
		const finish = (fn: () => void) => {
			if (settled) return;
			settled = true;
			cleanup();
			fn();
		};

		const onMessage = (event: MessageEvent) => {
			if (event.origin !== origin) return;
			const data = event.data as RelayMessage | null;
			if (!data || data.source !== MSG_SOURCE) return;

			if (data.type === "ready") {
				// Relay page loaded post-auth; hand it the payload to POST.
				popup.postMessage(
					{ source: MSG_SOURCE, type: "payload", nonce, payload },
					origin,
				);
				return;
			}

			// token / error must echo our nonce to be accepted.
			if (data.nonce !== nonce) return;
			if (data.type === "token" && typeof data.token === "string") {
				finish(() => resolve(data.token as string));
			} else if (data.type === "error") {
				const message =
					typeof data.error === "string" && data.error
						? data.error
						: "Step-up confirmation failed.";
				finish(() => reject(new Error(message)));
			}
		};

		window.addEventListener("message", onMessage);

		poll = setInterval(() => {
			if (popup.closed) {
				finish(() =>
					reject(
						new Error(
							"Step-up window was closed before confirmation completed.",
						),
					),
				);
			}
		}, POLL_MS);

		timer = setTimeout(() => {
			finish(() =>
				reject(new Error("Step-up confirmation timed out. Please try again.")),
			);
		}, opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
	});
}
