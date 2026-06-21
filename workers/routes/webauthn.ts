// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// App-layer WebAuthn step-up (issue #376). Replaces the Cloudflare Access-JWT
// step-up at /api/v1/confirm — which looped forever because two Access apps on
// one hostname emitted colliding CF_Authorization cookies — with a per-send,
// phishing-resistant, in-page assertion verified inside the Worker.
//
// This file changes ONLY how the one-shot confirm token is MINTED. The send
// gate (workers/lib/send-risk-gate.ts), the token contract
// (workers/lib/confirm-token.ts: payloadHash binding, HS256, one-shot jti in
// BLOOM_KV), and the send-risk tiers (workers/security/send-risk.ts) are all
// unchanged.
//
// Mounted BEHIND the main Access middleware, so c.var.accessIdentity carries the
// verified POLICY_AUD `sub`/`email`. The four threat-model invariants:
//   1. Fresh, payload-bound, one-shot challenge (D1 `DELETE … RETURNING`).
//   2. Identity binding — the asserted credential's user_sub MUST equal the
//      request's Access sub (load-bearing: kills warm-session confirm-as-other).
//   3. userVerification required (biometric/PIN, not bare presence).
//   4. Full server verify: RP id, origin, challenge, signature, counter regress.

import {
	generateAuthenticationOptions,
	verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type {
	AuthenticationResponseJSON,
	AuthenticatorTransportFuture,
} from "@simplewebauthn/server";
import { Hono } from "hono";
import { z } from "zod";
import {
	getAccessIdentity,
	type AccessVariables,
} from "../lib/access-identity";
import { computePayloadHash, signConfirmationToken } from "../lib/confirm-token";
import {
	consumeChallenge,
	getByCredentialId,
	listBySub,
	putChallenge,
	updateCounter,
} from "../lib/webauthn-store";
import type { Env } from "../types";

// Challenge lifetime: long enough for a human biometric/PIN ceremony, short
// enough to bound the replay window. The minted confirm token is still 60s.
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

const SendPayloadSchema = z.object({
	to: z.union([z.string(), z.array(z.string())]),
	cc: z.union([z.string(), z.array(z.string())]).optional(),
	bcc: z.union([z.string(), z.array(z.string())]).optional(),
	subject: z.string().optional().default(""),
	body: z.string().optional().default(""),
	attachmentIds: z.array(z.string()).optional().default([]),
});

const OptionsBodySchema = z.object({
	mailboxId: z.string().min(1),
	tier: z.number().int().min(0).max(2),
	payload: SendPayloadSchema,
});

const VerifyBodySchema = OptionsBodySchema.extend({
	// The AuthenticationResponseJSON from navigator.credentials.get(); its shape
	// is fully validated by @simplewebauthn/server during verify.
	assertion: z.record(z.string(), z.unknown()),
});

export const webauthnRoute = new Hono<{ Bindings: Env; Variables: AccessVariables }>();

function authConfigured(env: Env): boolean {
	return !!(env.WEBAUTHN_DB && env.RP_ID && env.RP_ORIGIN && env.CONFIRMATION_TOKEN_SECRET && env.BLOOM_KV);
}

function payloadHashFor(p: z.infer<typeof SendPayloadSchema>): Promise<string> {
	return computePayloadHash(p.to, p.subject, p.body, p.attachmentIds, p.cc, p.bcc);
}

function b64urlToBytes(s: string): Uint8Array {
	const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
	const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

/** The challenge the authenticator signed, read from the assertion's clientDataJSON. */
function challengeFromAssertion(assertion: Record<string, unknown>): string | null {
	try {
		const response = assertion.response as { clientDataJSON?: unknown } | undefined;
		const cdj = response?.clientDataJSON;
		if (typeof cdj !== "string") return null;
		const parsed = JSON.parse(new TextDecoder().decode(b64urlToBytes(cdj))) as {
			challenge?: unknown;
		};
		return typeof parsed.challenge === "string" ? parsed.challenge : null;
	} catch {
		return null;
	}
}

// ── POST /authenticate/options ────────────────────────────────────────────────
// Issue a fresh authentication challenge bound to (sub, payloadHash).
webauthnRoute.post("/authenticate/options", async (c) => {
	if (!authConfigured(c.env)) {
		return c.json({ error: "webauthn not configured" }, 503);
	}
	const identity = getAccessIdentity(c);
	if (!identity) return c.json({ error: "unauthenticated" }, 401);

	const parsed = OptionsBodySchema.safeParse(await c.req.json().catch(() => ({})));
	if (!parsed.success) return c.json({ error: "invalid request body" }, 400);

	const credentials = await listBySub(c.env.WEBAUTHN_DB, identity.sub);
	const options = await generateAuthenticationOptions({
		rpID: c.env.RP_ID,
		userVerification: "required",
		allowCredentials: credentials.map((cred) => ({
			id: cred.credentialId,
			transports: (cred.transports ?? undefined) as AuthenticatorTransportFuture[] | undefined,
		})),
	});

	const payloadHash = await payloadHashFor(parsed.data.payload);
	await putChallenge(c.env.WEBAUTHN_DB, {
		challenge: options.challenge,
		userSub: identity.sub,
		type: "authentication",
		payloadHash,
		expiresAt: Date.now() + CHALLENGE_TTL_MS,
	});

	return c.json(options);
});

// ── POST /authenticate/verify ─────────────────────────────────────────────────
// Verify the assertion, enforce the four invariants, and mint the confirm token.
webauthnRoute.post("/authenticate/verify", async (c) => {
	if (!authConfigured(c.env)) {
		return c.json({ error: "webauthn not configured" }, 503);
	}
	const identity = getAccessIdentity(c);
	if (!identity) return c.json({ error: "unauthenticated" }, 401);

	const parsed = VerifyBodySchema.safeParse(await c.req.json().catch(() => ({})));
	if (!parsed.success) return c.json({ error: "invalid request body" }, 400);
	const { mailboxId, tier, payload, assertion } = parsed.data;

	const challenge = challengeFromAssertion(assertion);
	if (!challenge) return c.json({ error: "step-up verification failed" }, 401);

	// (1) Consume the challenge atomically FIRST — burns it whether or not the
	// rest succeeds, so a failed attempt cannot be retried with the same one.
	const consumed = await consumeChallenge(c.env.WEBAUTHN_DB, challenge, Date.now());
	if (!consumed || consumed.type !== "authentication" || consumed.userSub !== identity.sub) {
		return c.json({ error: "step-up verification failed" }, 401);
	}

	// (1, cont.) Payload binding — the assertion must be for THIS exact send.
	const payloadHash = await payloadHashFor(payload);
	if (consumed.payloadHash !== payloadHash) {
		return c.json({ error: "step-up verification failed" }, 401);
	}

	// (2) Identity binding — the credential must be owned by the confirming sub.
	const credentialId = typeof assertion.id === "string" ? assertion.id : "";
	const credential = await getByCredentialId(c.env.WEBAUTHN_DB, credentialId);
	if (!credential || credential.userSub !== identity.sub) {
		return c.json({ error: "step-up verification failed" }, 401);
	}

	// (3)+(4) Full server-side verify: RP id, origin, challenge, signature,
	// required UV flag, and sign-counter regression (throws on any failure).
	let verification;
	try {
		verification = await verifyAuthenticationResponse({
			response: assertion as unknown as AuthenticationResponseJSON,
			expectedChallenge: consumed.challenge,
			expectedOrigin: c.env.RP_ORIGIN,
			expectedRPID: c.env.RP_ID,
			requireUserVerification: true,
			credential: {
				id: credential.credentialId,
				publicKey: credential.publicKey as Uint8Array<ArrayBuffer>,
				counter: credential.counter,
				transports: (credential.transports ?? undefined) as
					| AuthenticatorTransportFuture[]
					| undefined,
			},
		});
	} catch {
		return c.json({ error: "step-up verification failed" }, 401);
	}
	if (!verification.verified) {
		return c.json({ error: "step-up verification failed" }, 401);
	}

	await updateCounter(
		c.env.WEBAUTHN_DB,
		credential.credentialId,
		verification.authenticationInfo.newCounter,
		Date.now(),
	);

	// Mint the one-shot confirm token via the UNCHANGED token contract.
	const jti = crypto.randomUUID();
	const token = await signConfirmationToken(
		{ tier: tier as 0 | 1 | 2, mailboxId, payloadHash, jti },
		c.env.CONFIRMATION_TOKEN_SECRET as string,
	);
	await c.env.BLOOM_KV.put(`confirm-jti:${jti}`, "1", { expirationTtl: 120 });

	return c.json({ token });
});
