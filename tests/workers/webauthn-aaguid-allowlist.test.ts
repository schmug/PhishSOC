// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// #506: optional AAGUID authenticator allowlist for WebAuthn step-up enrollment.
// With a non-empty WEBAUTHN_AAGUID_ALLOWLIST, register/verify rejects any
// authenticator whose AAGUID is not on the list, before the credential is
// stored. Empty/unset → allow all (no change from #376). Enforcement reuses the
// AAGUID @simplewebauthn already parses — no hand-rolled attestation parsing.
import { env as testEnv } from "cloudflare:test";
import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { listBySub } from "../../workers/lib/webauthn-store";
import { webauthnRoute } from "../../workers/routes/webauthn";
import { createTestAuthenticator } from "./webauthn-test-authenticator";
import type { AccessIdentity } from "../../workers/lib/access-identity";

const RP_ID = "localhost";
const RP_ORIGIN = "http://localhost:5173";
const SECRET = "test-secret-at-least-32-chars-long-for-hs256!!";

const ALLOWED_AAGUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const DISALLOWED_AAGUID = "11111111-2222-3333-4444-555555555555";

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

function makeApp(identity: AccessIdentity | null, opts: { aaguidAllowlist?: string } = {}) {
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
		...(opts.aaguidAllowlist !== undefined ? { WEBAUTHN_AAGUID_ALLOWLIST: opts.aaguidAllowlist } : {}),
	};
	const executionCtx = {
		waitUntil: () => {},
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
	};
}

/** Run the first-key enrollment to register/verify and return the response. */
async function enroll(app: ReturnType<typeof makeApp>, aaguid: string) {
	const auth = await createTestAuthenticator({ aaguid });
	const opt = (await (await app.regOptions()).json()) as { registration: { challenge: string } };
	const attestation = await auth.register({
		challenge: opt.registration.challenge,
		rpId: RP_ID,
		origin: RP_ORIGIN,
	});
	return app.regVerify({ attestation });
}

beforeEach(() => {
	vi.restoreAllMocks();
});

describe("AAGUID allowlist — enforcement (#506)", () => {
	it("allows enrollment when the authenticator AAGUID is on the allowlist", async () => {
		const sub = "aaguid-allowed";
		const app = makeApp({ sub, email: "op@example.com" }, { aaguidAllowlist: ALLOWED_AAGUID });

		const res = await enroll(app, ALLOWED_AAGUID);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { verified: boolean };
		expect(body.verified).toBe(true);
		expect(await listBySub(testEnv.WEBAUTHN_DB, sub)).toHaveLength(1);
	});

	it("rejects enrollment (4xx) when the AAGUID is not on the allowlist, storing nothing", async () => {
		const sub = "aaguid-blocked";
		const app = makeApp(
			{ sub, email: "op@example.com" },
			{ aaguidAllowlist: `${ALLOWED_AAGUID}, 99999999-0000-0000-0000-000000000000` },
		);

		const res = await enroll(app, DISALLOWED_AAGUID);
		expect(res.status).toBeGreaterThanOrEqual(400);
		expect(res.status).toBeLessThan(500);
		expect(await listBySub(testEnv.WEBAUTHN_DB, sub)).toHaveLength(0);
	});

	it("allows any authenticator when the allowlist is empty (no behavior change from #376)", async () => {
		const sub = "aaguid-empty";
		const app = makeApp({ sub, email: "op@example.com" }, { aaguidAllowlist: "" });

		const res = await enroll(app, DISALLOWED_AAGUID);
		expect(res.status).toBe(200);
		expect(await listBySub(testEnv.WEBAUTHN_DB, sub)).toHaveLength(1);
	});

	it("allows any authenticator when the allowlist is unset", async () => {
		const sub = "aaguid-unset";
		const app = makeApp({ sub, email: "op@example.com" });

		const res = await enroll(app, DISALLOWED_AAGUID);
		expect(res.status).toBe(200);
		expect(await listBySub(testEnv.WEBAUTHN_DB, sub)).toHaveLength(1);
	});

	it("matches the allowlist case-insensitively", async () => {
		const sub = "aaguid-ci";
		const app = makeApp(
			{ sub, email: "op@example.com" },
			{ aaguidAllowlist: ALLOWED_AAGUID.toUpperCase() },
		);

		const res = await enroll(app, ALLOWED_AAGUID);
		expect(res.status).toBe(200);
		expect(await listBySub(testEnv.WEBAUTHN_DB, sub)).toHaveLength(1);
	});
});
