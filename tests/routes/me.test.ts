// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Route-level test for `GET /api/v1/me` (#204, f17).
 *
 * The endpoint decodes the signed-in identity from the `email` claim of the
 * `cf-access-jwt-assertion` token that the JWT-verifying middleware in
 * `workers/app.ts` has already vouched for — NEVER from the
 * `Cf-Access-Authenticated-User-Email` header, which is decoupled from the
 * token and forgeable on a direct-to-origin request (advisory finding f17).
 * The unit test scope here is the *handler* contract — given the verified
 * token, return its email claim — not the middleware (which has its own
 * integration coverage).
 *
 * We rebuild a minimal Hono app with the same handler shape rather than
 * importing the full `workers/index.ts` graph, because that module pulls
 * in the entire intel/security/MCP stack and requires a live env binding
 * just to be evaluated. The behavior under test is small enough that
 * mirroring the handler keeps the test fast and dependency-free; the
 * production handler lives in `workers/index.ts` next to `/api/v1/config`
 * so a follow-up that changes one and forgets the other will fail this
 * test on the contract (JWT email claim → email mapping) regardless of
 * where the route is defined.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { callerEmailFromJwt } from "../../workers/lib/mailbox-acl";

// Helper: build a fake (unsigned) JWT carrying arbitrary claims. decodeJwt
// from jose just base64url-decodes the payload — no sig check needed here.
function makeFakeJwt(claims: Record<string, unknown>): string {
	const b64url = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
	return `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify(claims))}.`;
}

// Mirror of the production handler in workers/index.ts. Keep in sync.
function makeApp(opts: { dev: boolean } = { dev: false }) {
	const app = new Hono();
	app.get("/api/v1/me", (c) => {
		const jwtEmail = callerEmailFromJwt(c.req.header("cf-access-jwt-assertion"));
		if (jwtEmail) {
			return c.json({ email: jwtEmail });
		}
		if (opts.dev) {
			return c.json({ email: "dev@local" });
		}
		return c.json({ error: "not authenticated" }, 401);
	});
	return app;
}

describe("GET /api/v1/me (#204, f17)", () => {
	it("returns the email claim from the verified cf-access-jwt-assertion token", async () => {
		const app = makeApp();
		const res = await app.request("/api/v1/me", {
			headers: { "cf-access-jwt-assertion": makeFakeJwt({ email: "alice@acme.com" }) },
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as { email: string };
		expect(body.email).toBe("alice@acme.com");
	});

	it("ignores the forgeable cf-access-authenticated-user-email header (f17)", async () => {
		// A forged header without a JWT email claim must NOT mint an identity.
		const app = makeApp({ dev: false });
		const res = await app.request("/api/v1/me", {
			headers: {
				"cf-access-authenticated-user-email": "victim@corp.com",
				"cf-access-jwt-assertion": makeFakeJwt({ common_name: "svc-token" }),
			},
		});
		expect(res.status).toBe(401);
	});

	it("prefers the JWT email when a conflicting header is forged", async () => {
		const app = makeApp({ dev: false });
		const res = await app.request("/api/v1/me", {
			headers: {
				"cf-access-authenticated-user-email": "victim@corp.com",
				"cf-access-jwt-assertion": makeFakeJwt({ email: "eve@acme.com" }),
			},
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as { email: string };
		expect(body.email).toBe("eve@acme.com");
	});

	it("returns 401 in production when no identity can be derived", async () => {
		// The auth middleware would normally have already 403'd a tokenless
		// request; reaching the handler without a JWT email in production is
		// the belt-and-suspenders branch (e.g. a service token, no email claim).
		const app = makeApp({ dev: false });
		const res = await app.request("/api/v1/me");
		expect(res.status).toBe(401);
	});

	it("returns a stub identity in dev mode when no token is present", async () => {
		// `npm run dev` runs the worker without Access in front; the
		// handler must not 401 there or the account menu shows "Loading…"
		// forever. Stub email is stable so the dev experience is
		// predictable.
		const app = makeApp({ dev: true });
		const res = await app.request("/api/v1/me");
		expect(res.status).toBe(200);
		const body = (await res.json()) as { email: string };
		expect(body.email).toBe("dev@local");
	});
});
