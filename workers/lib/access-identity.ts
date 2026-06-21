// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// Cloudflare Access identity carried by the verified POLICY_AUD JWT (issue
// #376). `sub` is the per-user UUID and is the trust anchor for WebAuthn
// identity binding (a credential is owned by exactly one `sub`); `email` is
// present only for interactive browser sessions, so its presence is how we
// gate self-enrollment away from service tokens / the MCP server.

import type { Context } from "hono";
import type { JWTPayload } from "jose";

export type AccessIdentity = {
	sub: string;
	email?: string;
};

/** Hono context variables set by the main Access middleware in workers/app.ts. */
export type AccessVariables = {
	accessIdentity?: AccessIdentity;
};

/**
 * Build an AccessIdentity from an already-verified CF Access JWT payload.
 * Returns null when the token carries no usable `sub` — callers must treat a
 * null identity as unauthenticated for step-up purposes.
 */
export function identityFromAccessPayload(payload: JWTPayload): AccessIdentity | null {
	const sub = typeof payload.sub === "string" && payload.sub ? payload.sub : null;
	if (!sub) return null;
	const emailClaim = (payload as { email?: unknown }).email;
	const email = typeof emailClaim === "string" && emailClaim ? emailClaim : undefined;
	return email ? { sub, email } : { sub };
}

/**
 * Read the Access identity set by upstream middleware, or null if unset.
 * Generic over the full Hono env so any route whose Variables include
 * `accessIdentity` (regardless of its Bindings/path params) can call it.
 */
export function getAccessIdentity<E extends { Variables: AccessVariables }>(
	c: Context<E>,
): AccessIdentity | null {
	return c.get("accessIdentity") ?? null;
}

/**
 * An interactive identity is one with an email claim — i.e. a human browser
 * SSO session, not a service token / MCP caller. Enrollment is gated on this.
 */
export function isInteractive(identity: AccessIdentity | null): boolean {
	return !!identity?.email;
}
