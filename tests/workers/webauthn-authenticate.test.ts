// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// M3 (#376): the security core — authenticate/options + authenticate/verify.
// Runs in real workerd so @simplewebauthn/server's verify path (`crypto.subtle`
// ES256) and the D1 `DELETE … RETURNING` challenge consume behave as in prod.
//
// Six cases, all 401 except the happy path:
//   happy            — token mints AND passes the unchanged send gate
//   wrong-user       — credential owned by a different Access sub
//   replayed         — challenge already consumed
//   payload mismatch — verify payload ≠ the payload the challenge was bound to
//   UV-absent        — assertion without the userVerification flag
//   counter regress  — assertion signCount ≤ the stored counter
import { env as testEnv } from "cloudflare:test";
import { Hono } from "hono";
import { beforeEach, describe, expect, it } from "vitest";
import { createCredential } from "../../workers/lib/webauthn-store";
import { enforceSendRiskConfirmation } from "../../workers/lib/send-risk-gate";
import { webauthnRoute } from "../../workers/routes/webauthn";
import { createTestAuthenticator } from "./webauthn-test-authenticator";
import type { AccessIdentity } from "../../workers/lib/access-identity";

const RP_ID = "localhost";
const RP_ORIGIN = "http://localhost:5173";
const SECRET = "test-secret-at-least-32-chars-long-for-hs256!!";
const MAILBOX = "me@example.com";

// A Tier-2 send: external recipient + a BEC keyword in the body.
const PAYLOAD = {
	to: "victim@external.com",
	subject: "Q3 update",
	body: "Please wire funds to the new account today.",
	attachmentIds: [] as string[],
};

function makeKv(initial: Record<string, string> = {}) {
	const store: Record<string, string> = { ...initial };
	return {
		async get(key: string) {
			return store[key] ?? null;
		},
		async put(key: string, value: string) {
			store[key] = value;
		},
		async delete(key: string) {
			delete store[key];
		},
		_store: store,
	};
}

function makeApp(identity: AccessIdentity | null, kv: ReturnType<typeof makeKv>) {
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
		BLOOM_KV: kv,
	};
	const call = (path: string, body: unknown) =>
		app.request(
			path,
			{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) },
			env,
		);
	return {
		options: (body: unknown) => call("/api/v1/webauthn/authenticate/options", body),
		verify: (body: unknown) => call("/api/v1/webauthn/authenticate/verify", body),
	};
}

async function enroll(userSub: string, credentialId?: string, counter = 0) {
	const auth = await createTestAuthenticator(credentialId ? { credentialId } : {});
	await createCredential(testEnv.WEBAUTHN_DB, {
		credentialId: auth.credentialId,
		userSub,
		publicKey: auth.cosePublicKey,
		counter,
		transports: ["internal"],
		aaguid: null,
		createdAt: 1_700_000_000_000,
	});
	return auth;
}

let kv: ReturnType<typeof makeKv>;
beforeEach(() => {
	kv = makeKv();
});

describe("POST /authenticate — happy path", () => {
	it("mints a confirm token that passes the unchanged send gate", async () => {
		const sub = "user-happy";
		const auth = await enroll(sub);
		const app = makeApp({ sub, email: "op@example.com" }, kv);

		const optRes = await app.options({ mailboxId: MAILBOX, tier: 2, payload: PAYLOAD });
		expect(optRes.status).toBe(200);
		const options = (await optRes.json()) as { challenge: string };
		expect(typeof options.challenge).toBe("string");

		const assertion = await auth.assert({
			challenge: options.challenge,
			rpId: RP_ID,
			origin: RP_ORIGIN,
			counter: 1,
		});
		const verRes = await app.verify({ mailboxId: MAILBOX, tier: 2, payload: PAYLOAD, assertion });
		expect(verRes.status).toBe(200);
		const { token } = (await verRes.json()) as { token: string };
		expect(token.split(".")).toHaveLength(3);

		// The minted token must satisfy the UNCHANGED send-risk gate.
		const consumed = new Set<string>();
		const gate = await enforceSendRiskConfirmation(
			{ CONFIRMATION_TOKEN_SECRET: SECRET, BLOOM_KV: kv as unknown as KVNamespace },
			token,
			{ mailboxId: MAILBOX, to: PAYLOAD.to, subject: PAYLOAD.subject, body: PAYLOAD.body, attachments: [] },
			(jti) => Promise.resolve(consumed.has(jti) ? false : (consumed.add(jti), true)),
		);
		expect(gate.ok).toBe(true);
		expect(gate.ok ? gate.risk.tier : 0).toBe(2);
	});
});

describe("POST /authenticate/verify — rejections (all 401)", () => {
	it("rejects an assertion from another user's credential (identity binding)", async () => {
		const attacker = await enroll("attacker"); // credential owned by attacker
		const victim = "victim-sub";
		const app = makeApp({ sub: victim, email: "victim@example.com" }, kv);

		const optRes = await app.options({ mailboxId: MAILBOX, tier: 2, payload: PAYLOAD });
		const options = (await optRes.json()) as { challenge: string };
		// Victim's warm session, but the assertion is signed by attacker's key.
		const assertion = await attacker.assert({
			challenge: options.challenge,
			rpId: RP_ID,
			origin: RP_ORIGIN,
			counter: 1,
		});
		const verRes = await app.verify({ mailboxId: MAILBOX, tier: 2, payload: PAYLOAD, assertion });
		expect(verRes.status).toBe(401);
	});

	it("rejects a replayed challenge (consumed once)", async () => {
		const sub = "user-replay";
		const auth = await enroll(sub);
		const app = makeApp({ sub, email: "op@example.com" }, kv);

		const options = (await (await app.options({ mailboxId: MAILBOX, tier: 2, payload: PAYLOAD })).json()) as {
			challenge: string;
		};
		const assertion = await auth.assert({ challenge: options.challenge, rpId: RP_ID, origin: RP_ORIGIN, counter: 1 });

		const first = await app.verify({ mailboxId: MAILBOX, tier: 2, payload: PAYLOAD, assertion });
		expect(first.status).toBe(200);
		const replay = await app.verify({ mailboxId: MAILBOX, tier: 2, payload: PAYLOAD, assertion });
		expect(replay.status).toBe(401);
	});

	it("rejects a payload that does not match the challenge's bound payloadHash", async () => {
		const sub = "user-payload";
		const auth = await enroll(sub);
		const app = makeApp({ sub, email: "op@example.com" }, kv);

		const options = (await (await app.options({ mailboxId: MAILBOX, tier: 2, payload: PAYLOAD })).json()) as {
			challenge: string;
		};
		const assertion = await auth.assert({ challenge: options.challenge, rpId: RP_ID, origin: RP_ORIGIN, counter: 1 });

		const tamperedPayload = { ...PAYLOAD, to: "attacker@evil.com" };
		const verRes = await app.verify({ mailboxId: MAILBOX, tier: 2, payload: tamperedPayload, assertion });
		expect(verRes.status).toBe(401);
	});

	it("rejects an assertion missing the userVerification flag", async () => {
		const sub = "user-uv";
		const auth = await enroll(sub);
		const app = makeApp({ sub, email: "op@example.com" }, kv);

		const options = (await (await app.options({ mailboxId: MAILBOX, tier: 2, payload: PAYLOAD })).json()) as {
			challenge: string;
		};
		const assertion = await auth.assert({
			challenge: options.challenge,
			rpId: RP_ID,
			origin: RP_ORIGIN,
			counter: 1,
			userVerified: false,
		});
		const verRes = await app.verify({ mailboxId: MAILBOX, tier: 2, payload: PAYLOAD, assertion });
		expect(verRes.status).toBe(401);
	});

	it("rejects a sign-counter regression", async () => {
		const sub = "user-counter";
		const auth = await enroll(sub, undefined, 10); // stored counter = 10
		const app = makeApp({ sub, email: "op@example.com" }, kv);

		const options = (await (await app.options({ mailboxId: MAILBOX, tier: 2, payload: PAYLOAD })).json()) as {
			challenge: string;
		};
		const assertion = await auth.assert({ challenge: options.challenge, rpId: RP_ID, origin: RP_ORIGIN, counter: 5 });
		const verRes = await app.verify({ mailboxId: MAILBOX, tier: 2, payload: PAYLOAD, assertion });
		expect(verRes.status).toBe(401);
	});
});

describe("POST /authenticate — no Access identity", () => {
	it("returns 401 when no identity is present", async () => {
		const app = makeApp(null, kv);
		const res = await app.options({ mailboxId: MAILBOX, tier: 2, payload: PAYLOAD });
		expect(res.status).toBe(401);
	});
});
