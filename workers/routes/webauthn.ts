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
// verified POLICY_AUD `sub`/`email`. The four authenticate invariants:
//   1. Fresh, payload-bound, one-shot challenge (D1 `DELETE … RETURNING`).
//   2. Identity binding — the asserted credential's user_sub MUST equal the
//      request's Access sub (load-bearing: kills warm-session confirm-as-other).
//   3. userVerification required (biometric/PIN, not bare presence).
//   4. Full server verify: RP id, origin, challenge, signature, counter regress.
//
// Enrollment (register/*) is interactive-only (email claim ⇒ a human SSO
// session, never a service token / MCP), emits an audit event on the first
// (TOFU) key, and requires a fresh existing-key assertion to add a 2nd+ key.

import {
	generateAuthenticationOptions,
	generateRegistrationOptions,
	verifyAuthenticationResponse,
	verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
	AuthenticationResponseJSON,
	AuthenticatorTransportFuture,
	RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { Hono } from "hono";
import { z } from "zod";
import {
	getAccessIdentity,
	isInteractive,
	type AccessIdentity,
	type AccessVariables,
} from "../lib/access-identity";
import { computePayloadHash, signConfirmationToken } from "../lib/confirm-token";
import { dispatchSecurityAlert, type AlertExecutionContext } from "../lib/security-alert";
import {
	consumeChallenge,
	createCredential,
	getByCredentialId,
	listBySub,
	putChallenge,
	updateCounter,
	type ChallengeType,
	type StoredChallenge,
} from "../lib/webauthn-store";
import type { Env } from "../types";

const RP_NAME = "PhishSOC";
// Challenge lifetime: long enough for a human biometric/PIN ceremony, short
// enough to bound the replay window. The minted confirm token is still 60s.
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const SUPPORTED_ALGS = [-7, -257];

const SendPayloadSchema = z.object({
	to: z.union([z.string(), z.array(z.string())]),
	cc: z.union([z.string(), z.array(z.string())]).optional(),
	bcc: z.union([z.string(), z.array(z.string())]).optional(),
	subject: z.string().optional().default(""),
	body: z.string().optional().default(""),
	attachmentIds: z.array(z.string()).optional().default([]),
});

const AuthOptionsBodySchema = z.object({
	mailboxId: z.string().min(1),
	tier: z.number().int().min(0).max(2),
	payload: SendPayloadSchema,
});

const AuthVerifyBodySchema = AuthOptionsBodySchema.extend({
	// AuthenticationResponseJSON from navigator.credentials.get(); fully
	// validated by @simplewebauthn/server during verify.
	assertion: z.record(z.string(), z.unknown()),
});

const RegisterOptionsBodySchema = z.object({
	// Present only when adding a 2nd+ key: a fresh existing-key assertion.
	stepUpAssertion: z.record(z.string(), z.unknown()).optional(),
});

const RegisterVerifyBodySchema = z.object({
	attestation: z.record(z.string(), z.unknown()),
});

export const webauthnRoute = new Hono<{ Bindings: Env; Variables: AccessVariables }>();

function authConfigured(env: Env): boolean {
	return !!(env.WEBAUTHN_DB && env.RP_ID && env.RP_ORIGIN && env.CONFIRMATION_TOKEN_SECRET && env.BLOOM_KV);
}

function payloadHashFor(p: z.infer<typeof SendPayloadSchema>): Promise<string> {
	return computePayloadHash(p.to, p.subject, p.body, p.attachmentIds, p.cc, p.bcc);
}

function transportsOf(transports: string[] | null): AuthenticatorTransportFuture[] | undefined {
	return (transports ?? undefined) as AuthenticatorTransportFuture[] | undefined;
}

function b64urlToBytes(s: string): Uint8Array {
	const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
	const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

/** The challenge the authenticator signed, read from the response's clientDataJSON. */
function challengeFromResponse(response: Record<string, unknown>): string | null {
	try {
		const inner = response.response as { clientDataJSON?: unknown } | undefined;
		const cdj = inner?.clientDataJSON;
		if (typeof cdj !== "string") return null;
		const parsed = JSON.parse(new TextDecoder().decode(b64urlToBytes(cdj))) as {
			challenge?: unknown;
		};
		return typeof parsed.challenge === "string" ? parsed.challenge : null;
	} catch {
		return null;
	}
}

/**
 * Consume the challenge bound to this assertion and fully verify it: the
 * challenge must be live, of the expected type, and issued to this identity;
 * the asserted credential must be OWNED by this identity (the load-bearing
 * identity binding); and @simplewebauthn must verify RP id/origin/challenge/
 * signature, the required UV flag, and reject any sign-counter regression. The
 * challenge is consumed first, so a failed attempt can't be retried with it.
 */
async function consumeAndVerifyAssertion(
	env: Env,
	assertion: Record<string, unknown>,
	identity: AccessIdentity,
	expectedType: ChallengeType,
): Promise<{ ok: boolean; consumed: StoredChallenge | null }> {
	const challenge = challengeFromResponse(assertion);
	if (!challenge) return { ok: false, consumed: null };

	const consumed = await consumeChallenge(env.WEBAUTHN_DB, challenge, Date.now());
	if (!consumed || consumed.type !== expectedType || consumed.userSub !== identity.sub) {
		return { ok: false, consumed };
	}

	const credentialId = typeof assertion.id === "string" ? assertion.id : "";
	const credential = await getByCredentialId(env.WEBAUTHN_DB, credentialId);
	if (!credential || credential.userSub !== identity.sub) {
		return { ok: false, consumed };
	}

	try {
		const verification = await verifyAuthenticationResponse({
			response: assertion as unknown as AuthenticationResponseJSON,
			expectedChallenge: consumed.challenge,
			expectedOrigin: env.RP_ORIGIN,
			expectedRPID: env.RP_ID,
			requireUserVerification: true,
			credential: {
				id: credential.credentialId,
				publicKey: credential.publicKey as Uint8Array<ArrayBuffer>,
				counter: credential.counter,
				transports: transportsOf(credential.transports),
			},
		});
		if (!verification.verified) return { ok: false, consumed };
		await updateCounter(
			env.WEBAUTHN_DB,
			credential.credentialId,
			verification.authenticationInfo.newCounter,
			Date.now(),
		);
	} catch {
		return { ok: false, consumed };
	}
	return { ok: true, consumed };
}

// ── POST /authenticate/options ────────────────────────────────────────────────
// Issue a fresh authentication challenge bound to (sub, payloadHash).
webauthnRoute.post("/authenticate/options", async (c) => {
	if (!authConfigured(c.env)) return c.json({ error: "webauthn not configured" }, 503);
	const identity = getAccessIdentity(c);
	if (!identity) return c.json({ error: "unauthenticated" }, 401);

	const parsed = AuthOptionsBodySchema.safeParse(await c.req.json().catch(() => ({})));
	if (!parsed.success) return c.json({ error: "invalid request body" }, 400);

	const credentials = await listBySub(c.env.WEBAUTHN_DB, identity.sub);
	const options = await generateAuthenticationOptions({
		rpID: c.env.RP_ID,
		userVerification: "required",
		allowCredentials: credentials.map((cred) => ({
			id: cred.credentialId,
			transports: transportsOf(cred.transports),
		})),
	});

	await putChallenge(c.env.WEBAUTHN_DB, {
		challenge: options.challenge,
		userSub: identity.sub,
		type: "authentication",
		payloadHash: await payloadHashFor(parsed.data.payload),
		expiresAt: Date.now() + CHALLENGE_TTL_MS,
	});

	return c.json(options);
});

// ── POST /authenticate/verify ─────────────────────────────────────────────────
// Verify the assertion, enforce the four invariants, and mint the confirm token.
webauthnRoute.post("/authenticate/verify", async (c) => {
	if (!authConfigured(c.env)) return c.json({ error: "webauthn not configured" }, 503);
	const identity = getAccessIdentity(c);
	if (!identity) return c.json({ error: "unauthenticated" }, 401);

	const parsed = AuthVerifyBodySchema.safeParse(await c.req.json().catch(() => ({})));
	if (!parsed.success) return c.json({ error: "invalid request body" }, 400);
	const { mailboxId, tier, payload, assertion } = parsed.data;

	const { ok, consumed } = await consumeAndVerifyAssertion(c.env, assertion, identity, "authentication");
	if (!ok || !consumed) return c.json({ error: "step-up verification failed" }, 401);

	// Payload binding — the verified assertion must be for THIS exact send.
	const payloadHash = await payloadHashFor(payload);
	if (consumed.payloadHash !== payloadHash) {
		return c.json({ error: "step-up verification failed" }, 401);
	}

	// Mint the one-shot confirm token via the UNCHANGED token contract.
	const jti = crypto.randomUUID();
	const token = await signConfirmationToken(
		{ tier: tier as 0 | 1 | 2, mailboxId, payloadHash, jti },
		c.env.CONFIRMATION_TOKEN_SECRET as string,
	);
	await c.env.BLOOM_KV.put(`confirm-jti:${jti}`, "1", { expirationTtl: 120 });

	return c.json({ token });
});

// ── POST /register/options ────────────────────────────────────────────────────
// Interactive-only. First key: returns registration options directly. Adding a
// 2nd+ key: a two-phase handshake — first returns an existing-key step-up
// challenge (requiresStepUp), then, given a valid assertion, the registration
// options. Zero agent tool-path exists to reach this.
webauthnRoute.post("/register/options", async (c) => {
	if (!authConfigured(c.env)) return c.json({ error: "webauthn not configured" }, 503);
	const identity = getAccessIdentity(c);
	if (!identity || !isInteractive(identity)) {
		return c.json({ error: "interactive session required" }, 403);
	}

	const parsed = RegisterOptionsBodySchema.safeParse(await c.req.json().catch(() => ({})));
	const stepUpAssertion = parsed.success ? parsed.data.stepUpAssertion : undefined;

	const existing = await listBySub(c.env.WEBAUTHN_DB, identity.sub);
	if (existing.length > 0) {
		if (!stepUpAssertion) {
			// Phase 1: issue an existing-key step-up challenge.
			const authOptions = await generateAuthenticationOptions({
				rpID: c.env.RP_ID,
				userVerification: "required",
				allowCredentials: existing.map((cred) => ({
					id: cred.credentialId,
					transports: transportsOf(cred.transports),
				})),
			});
			await putChallenge(c.env.WEBAUTHN_DB, {
				challenge: authOptions.challenge,
				userSub: identity.sub,
				type: "register-stepup",
				payloadHash: null,
				expiresAt: Date.now() + CHALLENGE_TTL_MS,
			});
			return c.json({ requiresStepUp: true, authentication: authOptions });
		}
		// Phase 2: require a valid existing-key assertion before unlocking.
		const { ok } = await consumeAndVerifyAssertion(c.env, stepUpAssertion, identity, "register-stepup");
		if (!ok) return c.json({ error: "step-up verification failed" }, 403);
	}

	const options = await generateRegistrationOptions({
		rpName: RP_NAME,
		rpID: c.env.RP_ID,
		userName: identity.email ?? identity.sub,
		userID: new TextEncoder().encode(identity.sub) as Uint8Array<ArrayBuffer>,
		attestationType: "none",
		excludeCredentials: existing.map((cred) => ({
			id: cred.credentialId,
			transports: transportsOf(cred.transports),
		})),
		authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
		supportedAlgorithmIDs: SUPPORTED_ALGS,
	});
	await putChallenge(c.env.WEBAUTHN_DB, {
		challenge: options.challenge,
		userSub: identity.sub,
		type: "registration",
		payloadHash: null,
		expiresAt: Date.now() + CHALLENGE_TTL_MS,
	});

	return c.json({ registration: options });
});

// ── POST /register/verify ─────────────────────────────────────────────────────
// Interactive-only. Verify the attestation, store the credential bound to the
// Access sub, and emit an audit event on the first key (the TOFU window).
webauthnRoute.post("/register/verify", async (c) => {
	if (!authConfigured(c.env)) return c.json({ error: "webauthn not configured" }, 503);
	const identity = getAccessIdentity(c);
	if (!identity || !isInteractive(identity)) {
		return c.json({ error: "interactive session required" }, 403);
	}

	const parsed = RegisterVerifyBodySchema.safeParse(await c.req.json().catch(() => ({})));
	if (!parsed.success) return c.json({ error: "invalid request body" }, 400);
	const attestation = parsed.data.attestation;

	const challenge = challengeFromResponse(attestation);
	if (!challenge) return c.json({ error: "registration verification failed" }, 401);

	const consumed = await consumeChallenge(c.env.WEBAUTHN_DB, challenge, Date.now());
	if (!consumed || consumed.type !== "registration" || consumed.userSub !== identity.sub) {
		return c.json({ error: "registration verification failed" }, 401);
	}

	let verification;
	try {
		verification = await verifyRegistrationResponse({
			response: attestation as unknown as RegistrationResponseJSON,
			expectedChallenge: consumed.challenge,
			expectedOrigin: c.env.RP_ORIGIN,
			expectedRPID: c.env.RP_ID,
			requireUserVerification: true,
			supportedAlgorithmIDs: SUPPORTED_ALGS,
		});
	} catch {
		return c.json({ error: "registration verification failed" }, 401);
	}
	if (!verification.verified || !verification.registrationInfo) {
		return c.json({ error: "registration verification failed" }, 401);
	}

	const info = verification.registrationInfo;
	const responseTransports = (attestation.response as { transports?: string[] } | undefined)?.transports;
	const existingBefore = await listBySub(c.env.WEBAUTHN_DB, identity.sub);
	const firstKey = existingBefore.length === 0;

	await createCredential(c.env.WEBAUTHN_DB, {
		credentialId: info.credential.id,
		userSub: identity.sub,
		publicKey: info.credential.publicKey,
		counter: info.credential.counter,
		transports: info.credential.transports ?? responseTransports ?? null,
		aaguid: info.aaguid ?? null,
		createdAt: Date.now(),
	});

	if (firstKey) {
		// The TOFU enrollment is the highest-risk window in the step-up, so it gets
		// BOTH a forensic audit line AND an active out-of-band notification.
		const auditEvent = {
			event: "webauthn.first_key_registered",
			sub: identity.sub,
			email: identity.email,
			credentialId: info.credential.id,
			aaguid: info.aaguid,
		};
		// Forensic audit line (kept as-is) for retrospective log search.
		console.log(JSON.stringify(auditEvent));
		// Active operator notification — a console line is not an alert. Dispatched
		// fire-and-forget via the execution context's waitUntil; a failed/slow/
		// missing webhook MUST NOT block or fail this enrollment, so the response
		// below still returns { verified: true } regardless. No-ops when the
		// SECURITY_ALERT_WEBHOOK_URL operator secret is unset.
		let alertCtx: AlertExecutionContext | undefined;
		try {
			alertCtx = c.executionCtx;
		} catch {
			alertCtx = undefined;
		}
		dispatchSecurityAlert(c.env, alertCtx, auditEvent);
	}

	return c.json({ verified: true, credentialId: info.credential.id, firstKey });
});
