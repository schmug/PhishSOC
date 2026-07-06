// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	parseServiceAccountJson,
	mintAccessToken,
	GmailApiError,
} from "../../workers/providers/gmail-client";

function b64urlToBytes(s: string): Uint8Array {
	const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
	return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function makeTestServiceAccount(): Promise<{ sa: { client_email: string; private_key: string }; publicKey: CryptoKey }> {
	const kp = await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	);
	const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
	const b64 = btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
	const pem = `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
	return { sa: { client_email: "svc@proj.iam.gserviceaccount.com", private_key: pem }, publicKey: kp.publicKey };
}

describe("parseServiceAccountJson", () => {
	it("accepts a JSON string with client_email and private_key", () => {
		const sa = parseServiceAccountJson(JSON.stringify({ client_email: "a@b.iam", private_key: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----" }));
		expect(sa?.client_email).toBe("a@b.iam");
	});
	it("returns null on malformed JSON, missing fields, or non-string input", () => {
		expect(parseServiceAccountJson("{nope")).toBeNull();
		expect(parseServiceAccountJson(JSON.stringify({ client_email: "a@b" }))).toBeNull();
		expect(parseServiceAccountJson(42)).toBeNull();
	});
});

describe("mintAccessToken", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("POSTs a signed RS256 assertion to oauth2.googleapis.com and returns the token", async () => {
		const { sa, publicKey } = await makeTestServiceAccount();
		let capturedBody = "";
		vi.stubGlobal("fetch", vi.fn(async (url: string | URL, init?: RequestInit) => {
			const u = new URL(String(url));
			if (u.hostname === "oauth2.googleapis.com" && u.pathname === "/token") {
				capturedBody = String(init?.body);
				return new Response(JSON.stringify({ access_token: "tok-123", expires_in: 3600, token_type: "Bearer" }), { status: 200 });
			}
			throw new Error(`unexpected fetch: ${u.hostname}`);
		}));

		const before = Date.now();
		const { token, expiresAt } = await mintAccessToken(sa, "user@tenant.example");
		expect(token).toBe("tok-123");
		expect(expiresAt).toBeGreaterThan(before + 3000_000); // ~3600s minus safety margin

		// Decode + verify the assertion we sent.
		const params = new URLSearchParams(capturedBody);
		expect(params.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
		const assertion = params.get("assertion")!;
		const [h, c, sig] = assertion.split(".");
		const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h)));
		const claims = JSON.parse(new TextDecoder().decode(b64urlToBytes(c)));
		expect(header).toEqual({ alg: "RS256", typ: "JWT" });
		expect(claims.iss).toBe(sa.client_email);
		expect(claims.sub).toBe("user@tenant.example");
		expect(claims.aud).toBe("https://oauth2.googleapis.com/token");
		expect(claims.scope).toBe("https://www.googleapis.com/auth/gmail.modify");
		expect(claims.exp - claims.iat).toBeLessThanOrEqual(3600);
		const ok = await crypto.subtle.verify(
			"RSASSA-PKCS1-v1_5", publicKey,
			b64urlToBytes(sig).buffer as ArrayBuffer,
			new TextEncoder().encode(`${h}.${c}`),
		);
		expect(ok).toBe(true);
	});

	it("throws GmailApiError with the response status on a non-200 token response", async () => {
		const { sa } = await makeTestServiceAccount();
		vi.stubGlobal("fetch", vi.fn(async (url: string | URL) => {
			const u = new URL(String(url));
			if (u.hostname === "oauth2.googleapis.com") {
				return new Response(JSON.stringify({ error: "unauthorized_client" }), { status: 401 });
			}
			throw new Error("unexpected fetch");
		}));
		await expect(mintAccessToken(sa, "user@tenant.example")).rejects.toThrowError(GmailApiError);
		await expect(mintAccessToken(sa, "user@tenant.example")).rejects.toMatchObject({ status: 401 });
	});
});
