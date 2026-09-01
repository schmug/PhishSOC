// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Ops-visibility "new mail" notifications (issue #563).
 *
 * The only "new mail" signal today is the foreground WebSocket fanout
 * (`MailboxDO.notifyNewEmail`), which requires the app to be open. This
 * module fans inbound-email events out to an operator-configured chat
 * webhook so an operator watching the deployment doesn't need a browser tab
 * open. It is a separate, higher-volume channel from
 * `workers/lib/security-alert.ts`'s `SECURITY_ALERT_WEBHOOK_URL` (a
 * low-volume security pager — see issue #511's alert-fatigue note) and its
 * raw-JSON payloads, which chat apps don't render.
 *
 * Fire-and-forget by the same contract as `dispatchSecurityAlert`: a webhook
 * that is slow, down, or misconfigured MUST NOT block or fail email receipt.
 * Every failure (a synchronous throw, an async network rejection, or a
 * non-2xx response) is caught and logged here. When an execution context is
 * reachable the request is scheduled with `waitUntil`; otherwise it is still
 * issued, pre-`catch`ed so it cannot become an unhandled rejection.
 */

import type { Env } from "../types";
import type { AlertExecutionContext } from "./security-alert";
import {
	NEW_EMAIL_WEBHOOK_SECRET_PREFIX,
	type ResolvedNewEmailWebhook,
} from "./new-email-webhook-policy";

/** Webhook request timeout — bounded so a hung endpoint can't pin a request. */
const NEW_EMAIL_WEBHOOK_TIMEOUT_MS = 10_000;

/** Cap on the subject text included in the outbound message. */
const MAX_SUBJECT_LENGTH = 120;

export interface NewEmailNotification {
	mailboxId: string;
	messageId: string;
	/** Landing folder (e.g. "inbox" or "quarantine"). */
	folder: string;
	sender: string;
	subject: string;
	verdictAction?: string | null;
	verdictScore?: number | null;
}

/**
 * Strip characters that could be used to inject a fake `<url|text>` chat
 * link (or otherwise break the single-line message) via attacker-controlled
 * email fields. No email body content is ever included here — sender and
 * subject only.
 */
function sanitizeField(value: string): string {
	return value.replace(/[<>|]/g, "");
}

function truncateSubject(subject: string): string {
	const clean = sanitizeField(subject);
	return clean.length > MAX_SUBJECT_LENGTH
		? `${clean.slice(0, MAX_SUBJECT_LENGTH)}…`
		: clean;
}

/** Google Chat / Slack incoming-webhook-compatible `{"text": "..."}` body. */
function buildMessageText(
	env: Pick<Env, "RP_ORIGIN">,
	notification: NewEmailNotification,
): string {
	const { mailboxId, messageId, folder, verdictAction, verdictScore } = notification;
	const sender = sanitizeField(notification.sender || "unknown");
	const subject = truncateSubject(notification.subject || "(no subject)");

	const parts = [
		`New email → ${sanitizeField(mailboxId)} [${folder}]`,
		`from: ${sender}`,
		`"${subject}"`,
	];
	if (verdictAction) {
		parts.push(
			verdictScore != null
				? `verdict: ${verdictAction} (${verdictScore})`
				: `verdict: ${verdictAction}`,
		);
	}

	let text = parts.join(" | ");
	if (env.RP_ORIGIN) {
		const link = `${env.RP_ORIGIN}/mailbox/${encodeURIComponent(mailboxId)}/emails/${encodeURIComponent(folder)}?email=${encodeURIComponent(messageId)}`;
		text += ` | <${link}|open>`;
	}
	return text;
}

/**
 * POST a chat-message payload to the configured `NEW_EMAIL_WEBHOOK_URL`, if
 * any.
 *
 * No-ops silently when the webhook is unconfigured. Never throws and never
 * rejects into the caller. When `ctx` is supplied the request is scheduled
 * with `waitUntil`; otherwise the request is still issued fire-and-forget.
 */
export function dispatchNewEmailNotification(
	env: Pick<Env, "NEW_EMAIL_WEBHOOK_URL" | "RP_ORIGIN">,
	ctx: AlertExecutionContext | undefined,
	notification: NewEmailNotification,
	webhook: ResolvedNewEmailWebhook = { configured: false, secretName: null },
): void {
	const target = resolveWebhookTarget(env, webhook);
	if (!target) return;

	try {
		const text = buildMessageText(env, notification);
		const request = fetch(target.url, {
			method: "POST",
			// Envelope headers spread last so an operator can override
			// content-type for a destination that demands something else.
			headers: { "content-type": "application/json", ...target.headers },
			body: JSON.stringify({ text }),
			signal: AbortSignal.timeout(NEW_EMAIL_WEBHOOK_TIMEOUT_MS),
		})
			.then((res) => {
				if (!res.ok) {
					console.error(`new-email webhook returned ${res.status}`);
				}
			})
			.catch((err: unknown) => {
				console.error(
					"new-email webhook failed:",
					err instanceof Error ? err.message : String(err),
				);
			});
		ctx?.waitUntil(request);
	} catch (err: unknown) {
		// A synchronous failure (e.g. fetch/AbortSignal construction) must not
		// propagate into email receipt.
		console.error(
			"new-email webhook dispatch error:",
			err instanceof Error ? err.message : String(err),
		);
	}
}

/**
 * Pick the destination URL for this email.
 *
 * No tier configured falls back to the legacy global `NEW_EMAIL_WEBHOOK_URL`,
 * so a deployment that never touches settings keeps working unchanged.
 *
 * Once a tier IS configured there is deliberately NO fallback: a muted,
 * half-written, or invalid tier sends nothing. Falling back would leak the
 * mail to the wider channel the operator configured that tier to replace.
 *
 * The prefix is re-checked here even though the Zod schema enforces it on
 * write — a hand-edited R2 blob never passes through Zod, and without this
 * check a settings write could name any secret in `env` (a signing key, an
 * API token) and have its value POSTed to an operator-chosen endpoint. Same
 * defense-in-depth as `SmtpRelayProvider` re-checking `RELAY_CREDS_`.
 */
interface WebhookTarget {
	url: string;
	/** Extra request headers, empty for the bare-URL form. */
	headers: Record<string, string>;
}

/**
 * Interpret a webhook secret's value.
 *
 * Two accepted forms. A bare URL string is the original shape and still the
 * default — it suits chat incoming webhooks (Slack, Google Chat, Discord),
 * which carry their credential in the query string. A JSON envelope
 * `{"url": "...", "headers": {...}}` covers destinations that authenticate
 * with a header instead; Cursor's automations endpoint requires
 * `Authorization: Bearer`.
 *
 * Keeping both halves inside ONE operator-set secret is the security point.
 * Settings name the secret and nothing else, so a settings write can never
 * pair someone else's credential with a destination of its choosing — the
 * confused-deputy hole that forced the `FEED_ALLOWED_HOSTS` allowlist in
 * `workers/intel/feeds.ts` cannot open here, and no allowlist is needed.
 *
 * Mirrors `RELAY_CREDS_*`, which holds `{"user","pass"}` JSON parsed at use
 * time in `workers/providers/smtp-relay.ts`.
 *
 * `label` is the secret NAME and is safe to log; the value never is.
 */
function parseWebhookSecret(value: string, label: string): WebhookTarget | undefined {
	let parsed: unknown;
	try {
		parsed = JSON.parse(value);
	} catch {
		// Not JSON — the bare-URL form. A URL never parses as JSON.
		return { url: value, headers: {} };
	}

	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		console.error(
			`new-email webhook secret ${label} is neither a URL nor a {url, headers} envelope; sending nothing`,
		);
		return undefined;
	}

	const { url, headers } = parsed as { url?: unknown; headers?: unknown };
	if (typeof url !== "string" || url.length === 0) {
		// Fail closed. Falling back to the raw string would POST the literal
		// JSON text as a URL, and there is no safe destination to guess.
		console.error(`new-email webhook secret ${label} envelope has no usable url; sending nothing`);
		return undefined;
	}

	const out: Record<string, string> = {};
	if (headers && typeof headers === "object" && !Array.isArray(headers)) {
		for (const [key, headerValue] of Object.entries(headers as Record<string, unknown>)) {
			// Drop a non-string value rather than coercing it — a malformed
			// header is a misconfiguration, not something to guess at.
			if (typeof headerValue === "string") out[key] = headerValue;
		}
	}
	return { url, headers: out };
}

/**
 * Pick the destination for this email.
 *
 * No tier configured falls back to the legacy global `NEW_EMAIL_WEBHOOK_URL`,
 * so a deployment that never touches settings keeps working unchanged.
 *
 * Once a tier IS configured there is deliberately NO fallback: a muted,
 * half-written, or invalid tier sends nothing. Falling back would leak the
 * mail to the wider channel the operator configured that tier to replace.
 *
 * The prefix is re-checked here even though the Zod schema enforces it on
 * write — a hand-edited R2 blob never passes through Zod, and without this
 * check a settings write could name any secret in `env` (a signing key, an
 * API token) and have its value POSTed to an operator-chosen endpoint. Same
 * defense-in-depth as `SmtpRelayProvider` re-checking `RELAY_CREDS_`.
 */
function resolveWebhookTarget(
	env: Pick<Env, "NEW_EMAIL_WEBHOOK_URL" | "RP_ORIGIN">,
	webhook: ResolvedNewEmailWebhook,
): WebhookTarget | undefined {
	if (!webhook.configured) {
		const globalUrl = env.NEW_EMAIL_WEBHOOK_URL;
		if (!globalUrl) return undefined;
		return parseWebhookSecret(globalUrl, "NEW_EMAIL_WEBHOOK_URL");
	}

	const name = webhook.secretName;
	if (!name) return undefined;

	if (!name.startsWith(NEW_EMAIL_WEBHOOK_SECRET_PREFIX)) {
		console.error(
			`new-email webhook secret ${name} must start with ${NEW_EMAIL_WEBHOOK_SECRET_PREFIX}; sending nothing`,
		);
		return undefined;
	}

	const value = (env as unknown as Record<string, unknown>)[name];
	if (typeof value !== "string" || value.length === 0) {
		console.error(`new-email webhook secret ${name} is not configured; sending nothing`);
		return undefined;
	}
	return parseWebhookSecret(value, name);
}
