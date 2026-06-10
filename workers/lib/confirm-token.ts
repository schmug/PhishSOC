// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { SignJWT, jwtVerify } from "jose";

export type ConfirmationTokenPayload = {
	tier: 0 | 1 | 2;
	mailboxId: string;
	payloadHash: string;
	jti: string;
};

const JTI_KV_PREFIX = "confirm-jti:";

/** Normalize RFC-5322 recipient field(s) to a sorted, deduped address list. */
function normalizeRecipients(field: string | string[] | null | undefined): string[] {
	if (!field) return [];
	const addresses = Array.isArray(field) ? field : [field];
	return addresses
		.flatMap((a) => a.split(",").map((s) => s.trim()))
		.filter(Boolean)
		.sort();
}

export async function computePayloadHash(
	to: string | string[],
	subject: string,
	body: string,
	attachmentIds: string[],
	cc?: string | string[] | null,
	bcc?: string | string[] | null,
): Promise<string> {
	const canonical = JSON.stringify({
		to: normalizeRecipients(to),
		cc: normalizeRecipients(cc),
		bcc: normalizeRecipients(bcc),
		subject,
		body,
		attachmentIds: [...attachmentIds].sort(),
	});
	const digest = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(canonical),
	);
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

function confirmKey(secret: string): Uint8Array {
	return new TextEncoder().encode(secret);
}

export async function signConfirmationToken(
	payload: ConfirmationTokenPayload,
	secret: string,
): Promise<string> {
	return new SignJWT({
		tier: payload.tier,
		mailboxId: payload.mailboxId,
		payloadHash: payload.payloadHash,
	})
		.setProtectedHeader({ alg: "HS256" })
		.setIssuedAt()
		.setJti(payload.jti)
		.setExpirationTime("60s")
		.sign(confirmKey(secret));
}

/**
 * Verifies a one-shot confirmation token. Returns the payload on success,
 * null if the token is invalid, expired, or has already been used.
 *
 * Replay protection is enforced by `consumeJti`: it must atomically record
 * the jti as consumed and return true only when this is the first consume
 * (e.g. INSERT OR IGNORE into the per-mailbox DO SQLite with rowsWritten check).
 * The `bloomKv` get-check verifies the token was legitimately issued.
 */
export async function verifyConfirmationToken(
	token: string,
	secret: string,
	mailboxId: string,
	payloadHash: string,
	bloomKv: KVNamespace,
	consumeJti: (jti: string) => Promise<boolean>,
): Promise<ConfirmationTokenPayload | null> {
	let raw: Record<string, unknown>;
	try {
		const { payload } = await jwtVerify(token, confirmKey(secret));
		raw = payload as Record<string, unknown>;
	} catch {
		return null;
	}

	if (raw.mailboxId !== mailboxId || raw.payloadHash !== payloadHash) return null;

	const jti = typeof raw.jti === "string" ? raw.jti : null;
	if (!jti) return null;

	const jtiKey = `${JTI_KV_PREFIX}${jti}`;
	const exists = await bloomKv.get(jtiKey);
	if (!exists) return null;

	if (!(await consumeJti(jti))) return null;

	return {
		tier: raw.tier as 0 | 1 | 2,
		mailboxId: raw.mailboxId as string,
		payloadHash: raw.payloadHash as string,
		jti,
	};
}
