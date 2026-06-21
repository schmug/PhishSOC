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

function makeApp(identity: AccessIdentity | null) {
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
	};
	const call = (path: string, body: unknown) =>
		app.request(
			path,
			{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) },
			env,
		);
	return {
		regOptions: (body: unknown = {}) => call("/api/v1/webauthn/register/options", body),
		regVerify: (body: unknown) => call("/api/v1/webauthn/register/verify", body),
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
