// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Route-level tests for workers/routes/confirm.ts (#264 — slice 2 of #15).
 *
 * Strategy: mock `createRemoteJWKSet` to return a sentinel object and route
 * all `jwtVerify` calls that hit that sentinel through simulated success/failure.
 * `jwtVerify` calls with a real Uint8Array key (the HS256 confirm-token verify
 * inside verifyConfirmationToken) fall through to the real implementation.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { Hono } from "hono";

// Sentinel object returned by the mocked createRemoteJWKSet.
// Used to distinguish "CF Access JWKS call" from "HS256 symmetric key call".
const MOCK_CF_JWKS: unique symbol = Symbol("mock-cf-jwks");

vi.mock("jose", async (importOriginal) => {
	const actual = await importOriginal<typeof import("jose")>();
	return {
		...actual,
		createRemoteJWKSet: vi.fn(() => MOCK_CF_JWKS),
		jwtVerify: vi.fn(
			async (
				token: unknown,
				key: unknown,
				options?: unknown,
			): Promise<unknown> => {
				if (key === (MOCK_CF_JWKS as unknown)) {
					// Simulate CF Access step-up JWT validation.
					// "valid-step-up-token" succeeds; everything else throws.
					if (token === "valid-step-up-token") {
						return { payload: { email: "operator@example.com" } };
					}
					throw new Error("JWT verification failed");
				}
				// HS256 confirm-token path — use real implementation.
				return actual.jwtVerify(
					token as string,
					key as Parameters<typeof actual.jwtVerify>[1],
					options as Parameters<typeof actual.jwtVerify>[2],
				);
			},
		),
	};
});

import { confirmRoute } from "../../workers/routes/confirm";

const SECRET = "test-secret-at-least-32-chars-long-for-hs256!!";
const TEAM_DOMAIN = "https://example.cloudflareaccess.com";

function makeKv(initial: Record<string, string> = {}) {
	const store: Record<string, string> = { ...initial };
	return {
		async get(key: string) {
			return store[key] ?? null;
		},
		async put(key: string, value: string, _opts?: unknown) {
			store[key] = value;
		},
		async delete(key: string) {
			delete store[key];
		},
		_store: store,
	};
}

function makeApp(env: Record<string, unknown>) {
	const app = new Hono();
	app.route("/api/v1/confirm", confirmRoute);
	return {
		fetch(path: string, opts?: RequestInit) {
			return app.request(path, opts, env);
		},
	};
}

const FULL_ENV = {
	STEP_UP_AUD: "step-up-aud-tag",
	CONFIRMATION_TOKEN_SECRET: SECRET,
	TEAM_DOMAIN,
};

const VALID_BODY = {
	tier: 1,
	mailboxId: "me@example.com",
	to: "other@external.com",
	subject: "Hello",
	body: "Please wire funds",
	attachmentIds: [],
};

describe("POST /api/v1/confirm — configuration guard", () => {
	it("returns 503 when STEP_UP_AUD is not set", async () => {
		const kv = makeKv();
		const { fetch } = makeApp({ TEAM_DOMAIN, CONFIRMATION_TOKEN_SECRET: SECRET, BLOOM_KV: kv });
		const res = await fetch("/api/v1/confirm", { method: "POST" });
		expect(res.status).toBe(503);
		const body = await res.json() as { error: string };
		expect(body.error).toContain("not configured");
	});

	it("returns 503 when CONFIRMATION_TOKEN_SECRET is not set", async () => {
		const kv = makeKv();
		const { fetch } = makeApp({ STEP_UP_AUD: "aud", TEAM_DOMAIN, BLOOM_KV: kv });
		const res = await fetch("/api/v1/confirm", { method: "POST" });
		expect(res.status).toBe(503);
	});

	it("returns 503 when TEAM_DOMAIN is not set", async () => {
		const kv = makeKv();
		const { fetch } = makeApp({ STEP_UP_AUD: "aud", CONFIRMATION_TOKEN_SECRET: SECRET, BLOOM_KV: kv });
		const res = await fetch("/api/v1/confirm", { method: "POST" });
		expect(res.status).toBe(503);
	});

	it("returns a clean 503 (not a 500) when BLOOM_KV is not bound", async () => {
		// Without the guard, a valid step-up JWT would proceed to BLOOM_KV.put
		// on an undefined binding and throw an unhandled TypeError → 500.
		const { fetch } = makeApp(FULL_ENV);
		const res = await fetch("/api/v1/confirm", {
			method: "POST",
			headers: {
				"cf-access-jwt-assertion": "valid-step-up-token",
				"Content-Type": "application/json",
			},
			body: JSON.stringify(VALID_BODY),
		});
		expect(res.status).toBe(503);
		const body = await res.json() as { error: string };
		expect(body.error).toContain("not configured");
	});
});

describe("POST /api/v1/confirm — JWT validation", () => {
	let kv: ReturnType<typeof makeKv>;

	beforeEach(() => {
		kv = makeKv();
		vi.clearAllMocks();
	});

	it("returns 401 when no cf-access-jwt-assertion header is present", async () => {
		const { fetch } = makeApp({ ...FULL_ENV, BLOOM_KV: kv });
		const res = await fetch("/api/v1/confirm", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(VALID_BODY),
		});
		expect(res.status).toBe(401);
	});

	it("returns 401 when JWT has wrong audience (main-app POLICY_AUD token)", async () => {
		const { fetch } = makeApp({ ...FULL_ENV, BLOOM_KV: kv });
		const res = await fetch("/api/v1/confirm", {
			method: "POST",
			headers: {
				"cf-access-jwt-assertion": "bad-policy-aud-token",
				"Content-Type": "application/json",
			},
			body: JSON.stringify(VALID_BODY),
		});
		expect(res.status).toBe(401);
	});

	it("returns 200 with token when step-up JWT is valid", async () => {
		const { fetch } = makeApp({ ...FULL_ENV, BLOOM_KV: kv });
		const res = await fetch("/api/v1/confirm", {
			method: "POST",
			headers: {
				"cf-access-jwt-assertion": "valid-step-up-token",
				"Content-Type": "application/json",
			},
			body: JSON.stringify(VALID_BODY),
		});
		expect(res.status).toBe(200);
		const json = await res.json() as { token: string };
		expect(typeof json.token).toBe("string");
		expect(json.token.split(".").length).toBe(3);
	});
});

describe("POST /api/v1/confirm — minted token shape", () => {
	it("token carries tier, mailboxId, payloadHash (64-char hex), jti, exp (iat+60)", async () => {
		const kv = makeKv();
		const { fetch } = makeApp({ ...FULL_ENV, BLOOM_KV: kv });

		const res = await fetch("/api/v1/confirm", {
			method: "POST",
			headers: {
				"cf-access-jwt-assertion": "valid-step-up-token",
				"Content-Type": "application/json",
			},
			body: JSON.stringify(VALID_BODY),
		});

		const { token } = await res.json() as { token: string };
		const payload = JSON.parse(
			Buffer.from(token.split(".")[1], "base64url").toString(),
		);

		expect(payload.tier).toBe(1);
		expect(payload.mailboxId).toBe("me@example.com");
		expect(typeof payload.payloadHash).toBe("string");
		expect(payload.payloadHash).toHaveLength(64); // SHA-256 hex
		expect(/^[0-9a-f]{64}$/.test(payload.payloadHash)).toBe(true);
		expect(typeof payload.jti).toBe("string");
		expect(typeof payload.exp).toBe("number");
		expect(payload.exp - payload.iat).toBe(60);
	});

	it("stores jti in KV after minting", async () => {
		const kv = makeKv();
		const { fetch } = makeApp({ ...FULL_ENV, BLOOM_KV: kv });

		const res = await fetch("/api/v1/confirm", {
			method: "POST",
			headers: {
				"cf-access-jwt-assertion": "valid-step-up-token",
				"Content-Type": "application/json",
			},
			body: JSON.stringify(VALID_BODY),
		});

		const { token } = await res.json() as { token: string };
		const payload = JSON.parse(
			Buffer.from(token.split(".")[1], "base64url").toString(),
		);

		expect(kv._store[`confirm-jti:${payload.jti}`]).toBe("1");
	});

	it("payloadHash is deterministic for the same inputs regardless of array order", async () => {
		const kv1 = makeKv();
		const kv2 = makeKv();
		const { fetch: fetch1 } = makeApp({ ...FULL_ENV, BLOOM_KV: kv1 });
		const { fetch: fetch2 } = makeApp({ ...FULL_ENV, BLOOM_KV: kv2 });

		const body1 = { ...VALID_BODY, to: ["a@x.com", "b@x.com"] };
		const body2 = { ...VALID_BODY, to: ["b@x.com", "a@x.com"] };

		const [r1, r2] = await Promise.all([
			fetch1("/api/v1/confirm", {
				method: "POST",
				headers: { "cf-access-jwt-assertion": "valid-step-up-token", "Content-Type": "application/json" },
				body: JSON.stringify(body1),
			}),
			fetch2("/api/v1/confirm", {
				method: "POST",
				headers: { "cf-access-jwt-assertion": "valid-step-up-token", "Content-Type": "application/json" },
				body: JSON.stringify(body2),
			}),
		]);

		const t1 = ((await r1.json()) as { token: string }).token;
		const t2 = ((await r2.json()) as { token: string }).token;

		const h1 = JSON.parse(Buffer.from(t1.split(".")[1], "base64url").toString()).payloadHash;
		const h2 = JSON.parse(Buffer.from(t2.split(".")[1], "base64url").toString()).payloadHash;

		expect(h1).toBe(h2);
	});
});

describe("POST /api/v1/confirm — replay protection", () => {
	it("verifyConfirmationToken returns null on second use (jti consumed)", async () => {
		const { verifyConfirmationToken } = await import(
			"../../workers/lib/confirm-token"
		);
		const kv = makeKv();
		const { fetch } = makeApp({ ...FULL_ENV, BLOOM_KV: kv });

		const res = await fetch("/api/v1/confirm", {
			method: "POST",
			headers: {
				"cf-access-jwt-assertion": "valid-step-up-token",
				"Content-Type": "application/json",
			},
			body: JSON.stringify(VALID_BODY),
		});

		const { token } = await res.json() as { token: string };
		const payload = JSON.parse(
			Buffer.from(token.split(".")[1], "base64url").toString(),
		);

		// Shared atomic-consume callback (simulates DO INSERT OR IGNORE)
		const consumed = new Set<string>();
		const consumeJti = (jti: string): Promise<boolean> => {
			if (consumed.has(jti)) return Promise.resolve(false);
			consumed.add(jti);
			return Promise.resolve(true);
		};

		// First verify — should succeed
		const first = await verifyConfirmationToken(
			token,
			SECRET,
			payload.mailboxId,
			payload.payloadHash,
			kv as unknown as KVNamespace,
			consumeJti,
		);
		expect(first).not.toBeNull();

		// Second verify — jti already consumed, should fail
		const second = await verifyConfirmationToken(
			token,
			SECRET,
			payload.mailboxId,
			payload.payloadHash,
			kv as unknown as KVNamespace,
			consumeJti,
		);
		expect(second).toBeNull();
	});
});
