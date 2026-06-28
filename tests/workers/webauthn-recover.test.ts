// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// #507: operator/admin-only out-of-band recovery for lost WebAuthn step-up
// credentials. Admin authority comes solely from the operator WEBAUTHN_ADMIN_EMAILS
// allowlist; a non-admin teammate or a service token (no email ⇒ not interactive)
// is rejected. After recovery the user re-enters the first-key (TOFU) enrollment
// flow. There is NO self-serve / emailed / TOTP path.
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
const ADMIN_EMAIL = "operator@example.com";

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

function makeApp(identity: AccessIdentity | null, opts: { adminEmails?: string } = {}) {
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
		...(opts.adminEmails !== undefined ? { WEBAUTHN_ADMIN_EMAILS: opts.adminEmails } : {}),
	};
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
		recover: (body: unknown) => call("/api/v1/webauthn/recover", body),
		regOptions: (body: unknown = {}) => call("/api/v1/webauthn/register/options", body),
		regVerify: (body: unknown) => call("/api/v1/webauthn/register/verify", body),
		settleAlerts: () => Promise.allSettled(scheduled),
	};
}

/** Enroll a single credential directly into the store for `sub`. */
async function seedCredential(sub: string) {
	const auth = await createTestAuthenticator();
	await createCredential(testEnv.WEBAUTHN_DB, {
		credentialId: auth.credentialId,
		userSub: sub,
		publicKey: auth.cosePublicKey,
		counter: 0,
		transports: ["internal"],
		aaguid: null,
		createdAt: 1_700_000_000_000,
	});
	return auth;
}

beforeEach(() => {
	vi.restoreAllMocks();
});

describe("recover — admin success", () => {
	it("clears all of the target user's credentials and emits an audit event", async () => {
		const sub = "recover-target";
		await seedCredential(sub);
		await seedCredential(sub);
		expect(await listBySub(testEnv.WEBAUTHN_DB, sub)).toHaveLength(2);

		const app = makeApp({ sub: "admin-1", email: ADMIN_EMAIL }, { adminEmails: ADMIN_EMAIL });
		const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

		const res = await app.recover({ userSub: sub });
		expect(res.status).toBe(200);
		const body = (await res.json()) as { recovered: boolean; removed: number; targetSub: string };
		expect(body.recovered).toBe(true);
		expect(body.removed).toBe(2);
		expect(body.targetSub).toBe(sub);

		expect(await listBySub(testEnv.WEBAUTHN_DB, sub)).toHaveLength(0);

		const audited = logSpy.mock.calls.some((args) =>
			args.some((a) => typeof a === "string" && a.includes("webauthn.credentials_recovered")),
		);
		expect(audited).toBe(true);
	});

	it("matches admin email case-insensitively and tolerates a multi-entry allowlist", async () => {
		const sub = "recover-target-ci";
		await seedCredential(sub);
		const app = makeApp(
			{ sub: "admin-2", email: "OPERATOR@example.com" },
			{ adminEmails: "someone@else.test, operator@example.com" },
		);
		const res = await app.recover({ userSub: sub });
		expect(res.status).toBe(200);
		expect(await listBySub(testEnv.WEBAUTHN_DB, sub)).toHaveLength(0);
	});
});

describe("recover — rejection", () => {
	it("rejects a non-admin interactive teammate with 403 (credentials untouched)", async () => {
		const sub = "keep-1";
		await seedCredential(sub);
		const app = makeApp({ sub: "teammate", email: "user@example.com" }, { adminEmails: ADMIN_EMAIL });

		const res = await app.recover({ userSub: sub });
		expect(res.status).toBe(403);
		expect(await listBySub(testEnv.WEBAUTHN_DB, sub)).toHaveLength(1);
	});

	it("rejects a service-token / agent caller (no email) with 403", async () => {
		const sub = "keep-2";
		await seedCredential(sub);
		const app = makeApp({ sub: "svc-token" }, { adminEmails: ADMIN_EMAIL });

		const res = await app.recover({ userSub: sub });
		expect(res.status).toBe(403);
		expect(await listBySub(testEnv.WEBAUTHN_DB, sub)).toHaveLength(1);
	});

	it("rejects everyone (403) when no admin allowlist is configured (fail closed)", async () => {
		const sub = "keep-3";
		await seedCredential(sub);
		// Admin-shaped identity, but WEBAUTHN_ADMIN_EMAILS unset → fail closed.
		const app = makeApp({ sub: "would-be-admin", email: ADMIN_EMAIL });

		const res = await app.recover({ userSub: sub });
		expect(res.status).toBe(403);
		expect(await listBySub(testEnv.WEBAUTHN_DB, sub)).toHaveLength(1);
	});
});

describe("recover — re-enrollment after recovery", () => {
	it("lets the recovered user enroll a fresh first authenticator (TOFU)", async () => {
		const sub = "recover-reenroll";
		await seedCredential(sub);

		// Admin recovers the lost credentials.
		const admin = makeApp({ sub: "admin-3", email: ADMIN_EMAIL }, { adminEmails: ADMIN_EMAIL });
		expect((await admin.recover({ userSub: sub })).status).toBe(200);
		expect(await listBySub(testEnv.WEBAUTHN_DB, sub)).toHaveLength(0);

		// The user now re-enters the FIRST-key enrollment flow (no requiresStepUp).
		const user = makeApp({ sub, email: "victim@example.com" });
		const optRes = await user.regOptions();
		expect(optRes.status).toBe(200);
		const opt = (await optRes.json()) as {
			requiresStepUp?: boolean;
			registration?: { challenge: string };
		};
		expect(opt.requiresStepUp).toBeFalsy();
		expect(opt.registration?.challenge).toBeTypeOf("string");

		const newKey = await createTestAuthenticator();
		const attestation = await newKey.register({
			challenge: opt.registration!.challenge,
			rpId: RP_ID,
			origin: RP_ORIGIN,
		});
		const verRes = await user.regVerify({ attestation });
		expect(verRes.status).toBe(200);
		const ver = (await verRes.json()) as { verified: boolean; firstKey: boolean };
		expect(ver.verified).toBe(true);
		expect(ver.firstKey).toBe(true);

		const creds = await listBySub(testEnv.WEBAUTHN_DB, sub);
		expect(creds).toHaveLength(1);
		expect(creds[0].credentialId).toBe(newKey.credentialId);
	});
});
