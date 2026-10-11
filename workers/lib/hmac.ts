// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Shared HMAC-SHA256 helper (Workers runtime — `crypto.subtle` only, no
 * `node:crypto`).
 *
 * Lifted out of `workers/routes/yaramail-callback.ts` (issue #257, inbound
 * sidecar-callback verification) so the outbound new-email webhook signer
 * (issue #700) reuses the same primitive instead of a second implementation.
 */

/** Compute HMAC-SHA256 of `message` with `secret` and return hex string. */
export async function hmacSha256Hex(secret: string, message: string): Promise<string> {
	const enc = new TextEncoder();
	const key = await crypto.subtle.importKey(
		"raw",
		enc.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
	return Array.from(new Uint8Array(sig))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}
