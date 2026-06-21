// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// M4 (#376): enrollment endpoints. Enrollment is the highest-risk window, so:
//   - only an INTERACTIVE Access identity (email claim) may enroll — service
//     tokens / MCP get 403 (zero agent tool-path to register);
//   - the FIRST key (TOFU) emits an audit event;
//   - adding a 2nd+ key requires a fresh assertion from an existing key.
import { env as testEnv } from "cloudflare:test";
import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createCredential, listBySub } from "../../workers/lib/webauthn-store";
import { webauthnRoute } from "../../workers/routes/webauthn";
import { createTestAuthenticator } from "./webauthn-test-authenticator";
import type { AccessIdentity } from "../../workers/lib/access-identity";

const RP_ID = "localhost";
const RP_ORIGIN = "http://localhost:5173";
const SECRET = "test-secret-at-least-32-chars-long-for-hs256!!";

function makeKv() {
	const store: Record<string, string> = {};
	return {
		async get(k: string) {
			return store[k] ?? null;
		},
		async put(k: string, v: string) {
			store[k] = v;
		},
		async delete(k: string) {
			delete store[k];
		},
	};
}

function makeApp(identity: AccessIdentity | null, opts: { alertWebhookUrl?: string } = {}) {
	const app = new Hono();
	app.use("*", async (c, next) => {
		if (identity) c.set("accessIdentity", identity);
		await next();
	});
	app.route("/api/v1/webauthn", webauthnRoute);
	const env = {
		WEBAUTHN_DB: testEnv.WEBAUTHN_DB,
		RP_ID,
		RP_ORIGIN,
		CONFIRMATION_TOKEN_SECRET: SECRET,
		BLOOM_KV: makeKv(),
		// Only present when a test opts in; absent → the first-key alert dispatch
		// no-ops (no webhook configured) exactly as it does on an unconfigured deploy.
		...(opts.alertWebhookUrl ? { SECURITY_ALERT_WEBHOOK_URL: opts.alertWebhookUrl } : {}),
	};
	// Provide a real ExecutionContext so the handler's fire-and-forget
	// `ctx.waitUntil(...)` dispatch exercises the production path. Scheduled
	// promises are collected so a test can await them before asserting.
	const scheduled: Promise<unknown>[] = [];
	const executionCtx = {
		waitUntil: (p: Promise<unknown>) => {
			scheduled.push(Promise.resolve(p));
		},
		passThroughOnException: () => {},
	} as unknown as ExecutionContext;
	const call = (path: string, body: unknown) =>
		app.request(
			path,
			{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) },
			env,
			executionCtx,
		);
	return {
		regOptions: (body: unknown = {}) => call("/api/v1/webauthn/register/options", body),
		regVerify: (body: unknown) => call("/api/v1/webauthn/register/verify", body),
		/** Await every promise the handler scheduled via `ctx.waitUntil(...)`. */
		settleAlerts: () => Promise.allSettled(scheduled),
	};
}

beforeEach(() => {
	vi.restoreAllMocks();
});

describe("register — interactive gating", () => {
	it("rejects a service-token identity (no email) with 403 on options and verify", async () => {
		const app = makeApp({ sub: "svc-1" }); // no email → not interactive
		expect((await app.regOptions()).status).toBe(403);
		expect((await app.regVerify({ attestation: {} })).status).toBe(403);
	});

	it("rejects an absent identity with 403", async () => {
		const app = makeApp(null);
		expect((await app.regOptions()).status).toBe(403);
	});
});

describe("register — first key (TOFU)", () => {
	it("enrolls the first key behind an interactive session and emits an audit event", async () => {
		const sub = "user-first";
		const auth = await createTestAuthenticator();
		const app = makeApp({ sub, email: "op@example.com" });
		const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

		const optRes = await app.regOptions();
		expect(optRes.status).toBe(200);
		const opt = (await optRes.json()) as {
			requiresStepUp?: boolean;
			registration?: { challenge: string };
		};
		expect(opt.requiresStepUp).toBeFalsy();
		expect(opt.registration?.challenge).toBeTypeOf("string");

		const attestation = await auth.register({
			challenge: opt.registration!.challenge,
			rpId: RP_ID,
			origin: RP_ORIGIN,
		});
		const verRes = await app.regVerify({ attestation });
		expect(verRes.status).toBe(200);
		const ver = (await verRes.json()) as { verified: boolean; firstKey?: boolean };
		expect(ver.verified).toBe(true);
		expect(ver.firstKey).toBe(true);

		const creds = await listBySub(testEnv.WEBAUTHN_DB, sub);
		expect(creds).toHaveLength(1);
		expect(creds[0].credentialId).toBe(auth.credentialId);

		// Audit event on first-key registration.
		const audited = logSpy.mock.calls.some((args) =>
			args.some((a) => typeof a === "string" && a.includes("webauthn.first_key_registered")),
		);
		expect(audited).toBe(true);
	});
});

describe("register — adding a 2nd key requires an existing-key assertion", () => {
	it("returns requiresStepUp (no registration options) when a key already exists", async () => {
		const sub = "user-2nd-a";
		const existing = await createTestAuthenticator();
		await createCredential(testEnv.WEBAUTHN_DB, {
			credentialId: existing.credentialId,
			userSub: sub,
			publicKey: existing.cosePublicKey,
			counter: 0,
			transports: ["internal"],
			aaguid: null,
			createdAt: 1_700_000_000_000,
		});
		const app = makeApp({ sub, email: "op@example.com" });

		const res = await app.regOptions(); // no stepUpAssertion
		expect(res.status).toBe(200);
		const body = (await res.json()) as {
			requiresStepUp?: boolean;
			authentication?: { challenge: string };
			registration?: unknown;
		};
		expect(body.requiresStepUp).toBe(true);
		expect(body.authentication?.challenge).toBeTypeOf("string");
		expect(body.registration).toBeUndefined();
	});

	it("rejects a bogus existing-key assertion with 403", async () => {
		const sub = "user-2nd-bogus";
		const existing = await createTestAuthenticator();
		await createCredential(testEnv.WEBAUTHN_DB, {
			credentialId: existing.credentialId,
			userSub: sub,
			publicKey: existing.cosePublicKey,
			counter: 0,
			transports: ["internal"],
			aaguid: null,
			createdAt: 1_700_000_000_000,
		});
		const app = makeApp({ sub, email: "op@example.com" });
		// Get a real challenge but never sign it — submit a malformed assertion.
		await app.regOptions();
		const res = await app.regOptions({ stepUpAssertion: { id: "x", response: {} } });
		expect(res.status).toBe(403);
	});

	it("issues registration options after a valid existing-key assertion, then stores the 2nd key", async () => {
		const sub = "user-2nd-ok";
		const existing = await createTestAuthenticator();
		await createCredential(testEnv.WEBAUTHN_DB, {
			credentialId: existing.credentialId,
			userSub: sub,
			publicKey: existing.cosePublicKey,
			counter: 0,
			transports: ["internal"],
			aaguid: null,
			createdAt: 1_700_000_000_000,
		});
		const app = makeApp({ sub, email: "op@example.com" });

		// Phase 1: get the step-up authentication challenge.
		const phase1 = (await (await app.regOptions()).json()) as {
			requiresStepUp: boolean;
			authentication: { challenge: string };
		};
		const stepUpAssertion = await existing.assert({
			challenge: phase1.authentication.challenge,
			rpId: RP_ID,
			origin: RP_ORIGIN,
			counter: 1,
		});

		// Phase 2: present the assertion → registration options unlocked.
		const phase2 = await app.regOptions({ stepUpAssertion });
		expect(phase2.status).toBe(200);
		const reg = (await phase2.json()) as { registration: { challenge: string } };
		expect(reg.registration?.challenge).toBeTypeOf("string");

		// Phase 3: create + verify the new key.
		const newKey = await createTestAuthenticator();
		const attestation = await newKey.register({
			challenge: reg.registration.challenge,
			rpId: RP_ID,
			origin: RP_ORIGIN,
		});
		const verRes = await app.regVerify({ attestation });
		expect(verRes.status).toBe(200);
		const ver = (await verRes.json()) as { verified: boolean; firstKey?: boolean };
		expect(ver.verified).toBe(true);
		expect(ver.firstKey).toBe(false);

		const creds = await listBySub(testEnv.WEBAUTHN_DB, sub);
		expect(creds.map((c) => c.credentialId).sort()).toEqual(
			[existing.credentialId, newKey.credentialId].sort(),
		);
	});
});

describe("register — first-key operator notification (TOFU alert)", () => {
	// A surreptitious first-key registration is the highest-risk window: the
	// console.log audit line is forensic, not an alert. register/verify dispatches
	// the same audit payload to SECURITY_ALERT_WEBHOOK_URL — fire-and-forget, so a
	// down/slow/throwing webhook can never block or fail the enrollment.
	const WEBHOOK_URL = "https://soc-alerts.example.test/first-key";
	const WEBHOOK_HOST = "soc-alerts.example.test";

	// Hostname is PARSED (never substring-matched) per the CodeQL gate — both in
	// the mock dispatcher and in the assertions below.
	function hostOf(input: unknown): string | null {
		const url = input instanceof Request ? input.url : typeof input === "string" ? input : String(input);
		try {
			return new URL(url).hostname;
		} catch {
			return null;
		}
	}

	/** Spy on fetch; route only the webhook host to `handler`, pass everything
	 *  else through (the register flow itself makes no outbound requests). */
	function spyWebhookFetch(handler: (init?: RequestInit) => Response) {
		const realFetch = globalThis.fetch;
		return vi
			.spyOn(globalThis, "fetch")
			.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
				if (hostOf(input) === WEBHOOK_HOST) return handler(init);
				return realFetch(input as RequestInfo | URL, init);
			});
	}

	function webhookCalls(spy: ReturnType<typeof spyWebhookFetch>) {
		return spy.mock.calls.filter((c) => hostOf(c[0]) === WEBHOOK_HOST);
	}

	async function enrollFirstKey(app: ReturnType<typeof makeApp>) {
		const auth = await createTestAuthenticator();
		const opt = (await (await app.regOptions()).json()) as {
			registration: { challenge: string };
		};
		const attestation = await auth.register({
			challenge: opt.registration.challenge,
			rpId: RP_ID,
			origin: RP_ORIGIN,
		});
		return app.regVerify({ attestation });
	}

	it("dispatches the notification with the audit payload on first-key registration", async () => {
		const app = makeApp({ sub: "notify-first", email: "op@example.com" }, { alertWebhookUrl: WEBHOOK_URL });
		const fetchSpy = spyWebhookFetch(() => new Response(null, { status: 200 }));

		const verRes = await enrollFirstKey(app);
		await app.settleAlerts();

		expect(verRes.status).toBe(200);
		const ver = (await verRes.json()) as { verified: boolean; firstKey: boolean };
		expect(ver.verified).toBe(true);
		expect(ver.firstKey).toBe(true);

		const calls = webhookCalls(fetchSpy);
		expect(calls).toHaveLength(1);
		// The notification carries the same structured audit payload as the log line.
		const body = JSON.parse(String((calls[0][1] as RequestInit).body)) as {
			event: string;
			sub: string;
			email: string;
		};
		expect(body.event).toBe("webauthn.first_key_registered");
		expect(body.sub).toBe("notify-first");
		expect(body.email).toBe("op@example.com");
	});

	it("does NOT dispatch the notification when adding a 2nd key", async () => {
		const sub = "notify-2nd";
		const existing = await createTestAuthenticator();
		await createCredential(testEnv.WEBAUTHN_DB, {
			credentialId: existing.credentialId,
			userSub: sub,
			publicKey: existing.cosePublicKey,
			counter: 0,
			transports: ["internal"],
			aaguid: null,
			createdAt: 1_700_000_000_000,
		});
		const app = makeApp({ sub, email: "op@example.com" }, { alertWebhookUrl: WEBHOOK_URL });
		const fetchSpy = spyWebhookFetch(() => new Response(null, { status: 200 }));

		// Full add-2nd-key handshake: step-up assertion → registration options → store.
		const phase1 = (await (await app.regOptions()).json()) as {
			authentication: { challenge: string };
		};
		const stepUpAssertion = await existing.assert({
			challenge: phase1.authentication.challenge,
			rpId: RP_ID,
			origin: RP_ORIGIN,
			counter: 1,
		});
		const phase2 = (await (await app.regOptions({ stepUpAssertion })).json()) as {
			registration: { challenge: string };
		};
		const newKey = await createTestAuthenticator();
		const attestation = await newKey.register({
			challenge: phase2.registration.challenge,
			rpId: RP_ID,
			origin: RP_ORIGIN,
		});
		const verRes = await app.regVerify({ attestation });
		await app.settleAlerts();

		expect(verRes.status).toBe(200);
		const ver = (await verRes.json()) as { firstKey: boolean };
		expect(ver.firstKey).toBe(false);
		expect(webhookCalls(fetchSpy)).toHaveLength(0);
	});

	it("still completes enrollment (200, credential stored) when the notifier rejects", async () => {
		const sub = "notify-throws";
		const app = makeApp({ sub, email: "op@example.com" }, { alertWebhookUrl: WEBHOOK_URL });
		const fetchSpy = spyWebhookFetch(() => {
			throw new Error("alert webhook unreachable");
		});

		const verRes = await enrollFirstKey(app);
		await app.settleAlerts();

		expect(verRes.status).toBe(200);
		const ver = (await verRes.json()) as { verified: boolean; firstKey: boolean };
		expect(ver.verified).toBe(true);
		expect(ver.firstKey).toBe(true);
		// The dispatch was attempted (and its rejection swallowed) — enrollment held.
		expect(webhookCalls(fetchSpy)).toHaveLength(1);

		const creds = await listBySub(testEnv.WEBAUTHN_DB, sub);
		expect(creds).toHaveLength(1);
	});
});
