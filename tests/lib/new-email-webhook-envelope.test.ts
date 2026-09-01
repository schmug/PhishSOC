// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * JSON-envelope webhook secrets.
 *
 * A `NEW_EMAIL_WEBHOOK_*` secret has always held a bare URL, which works for
 * chat incoming webhooks (Slack, Google Chat, Discord) because those carry
 * their credential in the query string. API-style destinations want a header
 * instead — Cursor's automations endpoint requires `Authorization: Bearer`,
 * verified against the live endpoint returning 200.
 *
 * Rather than add a second settings field naming a second secret, the secret
 * value itself may be a JSON envelope: `{"url": "...", "headers": {...}}`.
 * Same shape as `RELAY_CREDS_*`, which holds `{"user","pass"}` JSON parsed at
 * use time in `workers/providers/smtp-relay.ts`.
 *
 * The security point: destination and credential become one atomic unit that
 * only a Workers Admin can set. Settings still name the secret and nothing
 * more, so there is no way for a settings write to pair someone else's
 * credential with an attacker-chosen destination — the confused-deputy hole
 * that forced the `FEED_ALLOWED_HOSTS` allowlist in `workers/intel/feeds.ts`
 * never opens here.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { dispatchNewEmailNotification } from "../../workers/lib/new-email-notify";
import type { Env } from "../../workers/types";

const BARE_URL = "https://chat.googleapis.com/v1/spaces/AAA/messages?key=k&token=t";
const API_URL = "https://api2.cursor.sh/automations/webhook/abc";
const BEARER = "Bearer crsr_test_token";

const NOTIFICATION = {
	mailboxId: "inbox@example.com",
	messageId: "msg-1",
	folder: "inbox",
	sender: "alice@example.com",
	subject: "Invoice attached",
	verdictAction: "allow",
	verdictScore: 12,
};

function makeEnv(overrides: Record<string, unknown> = {}): Env {
	return { RP_ORIGIN: "https://inbox.cortech.online", ...overrides } as unknown as Env;
}

function makeCtx() {
	const scheduled: Promise<unknown>[] = [];
	return {
		ctx: { waitUntil: (p: Promise<unknown>) => scheduled.push(Promise.resolve(p)) },
		settle: () => Promise.allSettled(scheduled),
	};
}

const TIER = (secretName: string) => ({
	configured: true as const,
	secretName,
	format: "chat" as const,
});

describe("webhook secret — bare URL (existing behaviour)", () => {
	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
	});
	afterEach(() => vi.restoreAllMocks());

	it("posts to the URL with only content-type, unchanged", async () => {
		const { ctx, settle } = makeCtx();
		dispatchNewEmailNotification(
			makeEnv({ NEW_EMAIL_WEBHOOK_CHAT: BARE_URL }),
			ctx,
			NOTIFICATION,
			TIER("NEW_EMAIL_WEBHOOK_CHAT"),
		);
		await settle();

		const [url, init] = fetchSpy.mock.calls[0];
		expect(url).toBe(BARE_URL);
		expect((init as RequestInit).headers).toEqual({ "content-type": "application/json" });
	});

	it("still works on the global fallback path", async () => {
		const { ctx, settle } = makeCtx();
		dispatchNewEmailNotification(makeEnv({ NEW_EMAIL_WEBHOOK_URL: BARE_URL }), ctx, NOTIFICATION);
		await settle();

		expect(fetchSpy.mock.calls[0][0]).toBe(BARE_URL);
	});
});

describe("webhook secret — JSON envelope", () => {
	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
	});
	afterEach(() => vi.restoreAllMocks());

	it("posts to the envelope's url and attaches its headers", async () => {
		const { ctx, settle } = makeCtx();
		dispatchNewEmailNotification(
			makeEnv({
				NEW_EMAIL_WEBHOOK_CURSOR: JSON.stringify({
					url: API_URL,
					headers: { Authorization: BEARER },
				}),
			}),
			ctx,
			NOTIFICATION,
			TIER("NEW_EMAIL_WEBHOOK_CURSOR"),
		);
		await settle();

		const [url, init] = fetchSpy.mock.calls[0];
		expect(url).toBe(API_URL);
		expect((init as RequestInit).headers).toMatchObject({
			"content-type": "application/json",
			Authorization: BEARER,
		});
	});

	it("accepts an envelope with no headers", async () => {
		const { ctx, settle } = makeCtx();
		dispatchNewEmailNotification(
			makeEnv({ NEW_EMAIL_WEBHOOK_X: JSON.stringify({ url: API_URL }) }),
			ctx,
			NOTIFICATION,
			TIER("NEW_EMAIL_WEBHOOK_X"),
		);
		await settle();

		const [url, init] = fetchSpy.mock.calls[0];
		expect(url).toBe(API_URL);
		expect((init as RequestInit).headers).toEqual({ "content-type": "application/json" });
	});

	it("works on the global fallback path too", async () => {
		const { ctx, settle } = makeCtx();
		dispatchNewEmailNotification(
			makeEnv({
				NEW_EMAIL_WEBHOOK_URL: JSON.stringify({ url: API_URL, headers: { Authorization: BEARER } }),
			}),
			ctx,
			NOTIFICATION,
		);
		await settle();

		const [url, init] = fetchSpy.mock.calls[0];
		expect(url).toBe(API_URL);
		expect((init as RequestInit).headers).toMatchObject({ Authorization: BEARER });
	});

	it("sends nothing when the envelope parses but carries no usable url", async () => {
		const { ctx, settle } = makeCtx();
		dispatchNewEmailNotification(
			makeEnv({ NEW_EMAIL_WEBHOOK_BAD: JSON.stringify({ headers: { Authorization: BEARER } }) }),
			ctx,
			NOTIFICATION,
			TIER("NEW_EMAIL_WEBHOOK_BAD"),
		);
		await settle();

		// Fail closed. Falling back to the bare string would POST the literal
		// JSON text as a URL, and there is no safe destination to guess.
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("ignores a non-string header value rather than sending a malformed header", async () => {
		const { ctx, settle } = makeCtx();
		dispatchNewEmailNotification(
			makeEnv({
				NEW_EMAIL_WEBHOOK_ODD: JSON.stringify({
					url: API_URL,
					headers: { Authorization: BEARER, "X-Count": 7 },
				}),
			}),
			ctx,
			NOTIFICATION,
			TIER("NEW_EMAIL_WEBHOOK_ODD"),
		);
		await settle();

		const headers = (fetchSpy.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
		expect(headers.Authorization).toBe(BEARER);
		expect(headers["X-Count"]).toBeUndefined();
	});

	it("never logs the envelope's header values", async () => {
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const { ctx, settle } = makeCtx();
		dispatchNewEmailNotification(
			makeEnv({ NEW_EMAIL_WEBHOOK_BAD2: JSON.stringify({ headers: { Authorization: BEARER } }) }),
			ctx,
			NOTIFICATION,
			TIER("NEW_EMAIL_WEBHOOK_BAD2"),
		);
		await settle();

		for (const call of errorSpy.mock.calls) {
			expect(JSON.stringify(call)).not.toContain("crsr_test_token");
		}
	});
});

/**
 * Interaction with request signing (#700/#701), which landed while this
 * branch was open. An envelope supplies arbitrary headers; the signature must
 * not be one of them.
 */
describe("webhook secret — envelope headers vs the signature header", () => {
	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
	});
	afterEach(() => vi.restoreAllMocks());

	it("an envelope cannot override or suppress the signature", async () => {
		const { ctx, settle } = makeCtx();
		dispatchNewEmailNotification(
			makeEnv({
				NEW_EMAIL_WEBHOOK_SIGNING_SECRET: "signing-secret",
				NEW_EMAIL_WEBHOOK_EVIL: JSON.stringify({
					url: API_URL,
					headers: { "x-phishsoc-signature": "t=1,v1=deadbeef" },
				}),
			}),
			ctx,
			NOTIFICATION,
			TIER("NEW_EMAIL_WEBHOOK_EVIL"),
		);
		await settle();

		const headers = (fetchSpy.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
		// A real signature replaced the forged one. Letting an envelope set this
		// key would silently unsign deliveries with no error anywhere.
		expect(headers["x-phishsoc-signature"]).not.toBe("t=1,v1=deadbeef");
		expect(headers["x-phishsoc-signature"]).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
	});

	it("still carries envelope auth headers alongside the signature", async () => {
		const { ctx, settle } = makeCtx();
		dispatchNewEmailNotification(
			makeEnv({
				NEW_EMAIL_WEBHOOK_SIGNING_SECRET: "signing-secret",
				NEW_EMAIL_WEBHOOK_CURSOR2: JSON.stringify({
					url: API_URL,
					headers: { Authorization: BEARER },
				}),
			}),
			ctx,
			NOTIFICATION,
			TIER("NEW_EMAIL_WEBHOOK_CURSOR2"),
		);
		await settle();

		const headers = (fetchSpy.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
		expect(headers.Authorization).toBe(BEARER);
		expect(headers["x-phishsoc-signature"]).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
	});
});
