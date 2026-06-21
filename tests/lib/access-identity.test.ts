// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// M2 (#376): Access identity extraction + context helper. The identity carried
// by the verified POLICY_AUD JWT (`sub`, optional `email`) is the trust anchor
// for WebAuthn identity binding and interactive-only enrollment gating.
import { describe, expect, it } from "vitest";
import { Hono } from "hono";
import {
	getAccessIdentity,
	identityFromAccessPayload,
	isInteractive,
	type AccessVariables,
} from "../../workers/lib/access-identity";

describe("identityFromAccessPayload", () => {
	it("extracts sub and email from an interactive Access JWT", () => {
		const id = identityFromAccessPayload({ sub: "user-uuid", email: "op@example.com" });
		expect(id).toEqual({ sub: "user-uuid", email: "op@example.com" });
	});

	it("omits email for a service-token JWT (no email claim)", () => {
		const id = identityFromAccessPayload({ sub: "svc-uuid", common_name: "token.example" });
		expect(id).toEqual({ sub: "svc-uuid" });
		expect(id?.email).toBeUndefined();
	});

	it("returns null when there is no sub claim", () => {
		expect(identityFromAccessPayload({ email: "op@example.com" })).toBeNull();
		expect(identityFromAccessPayload({ sub: "" })).toBeNull();
	});
});

describe("isInteractive", () => {
	it("is true only when an email claim is present", () => {
		expect(isInteractive({ sub: "u", email: "op@example.com" })).toBe(true);
		expect(isInteractive({ sub: "u" })).toBe(false);
		expect(isInteractive(null)).toBe(false);
	});
});

describe("getAccessIdentity (Hono context)", () => {
	it("returns the identity set by upstream middleware", async () => {
		const app = new Hono<{ Variables: AccessVariables }>();
		app.use("*", async (c, next) => {
			c.set("accessIdentity", { sub: "s1", email: "op@example.com" });
			await next();
		});
		app.get("/", (c) => c.json(getAccessIdentity(c)));
		const res = await app.request("/");
		expect(await res.json()).toEqual({ sub: "s1", email: "op@example.com" });
	});

	it("returns null when no identity was set", async () => {
		const app = new Hono<{ Variables: AccessVariables }>();
		app.get("/", (c) => c.json({ id: getAccessIdentity(c) }));
		const res = await app.request("/");
		expect(await res.json()).toEqual({ id: null });
	});
});
