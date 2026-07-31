// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * POST /api/v1/mailboxes/:mailboxId/yaramail-callback
 *
 * Inbound callback route for the yaramail sidecar (issue #257).
 *
 * Authentication: HMAC-SHA256 of the raw request body using the
 * `YARAMAIL_CALLBACK_SECRET` Worker secret, passed in the
 * `x-yaramail-signature` header as a hex string.
 *
 * This route is registered BEFORE the `requireMailbox` middleware so
 * machine-to-machine sidecar calls are not blocked by the CF Access
 * ACL check that guards user-facing endpoints.
 */

import { Hono } from "hono";
import { z } from "zod";
import type { Env } from "../types";
import {
	computeYaraScoreDelta,
	type YaraMatchResult,
} from "../security/yaramail-signal";

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

const YaramailCallbackBody = z.object({
	emailId: z.string().min(1),
	matches: z.array(
		z.object({
			rule_name: z.string(),
			category: z.string().optional(),
			score: z.number().optional(),
		}),
	),
});

export const yaramailCallbackRoute = new Hono<{ Bindings: Env }>();

yaramailCallbackRoute.post("/", async (c) => {
	const { YARAMAIL_CALLBACK_SECRET } = c.env;
	if (!YARAMAIL_CALLBACK_SECRET) {
		return c.json({ error: "yaramail callback not configured" }, 503);
	}

	// Read body as text so we can verify HMAC before parsing JSON.
	const rawBody = await c.req.text();

	const signature = c.req.header("x-yaramail-signature") ?? "";
	const expected = await hmacSha256Hex(YARAMAIL_CALLBACK_SECRET, rawBody);

	// Constant-time comparison: XOR all bytes so the result doesn't
	// short-circuit on the first mismatch (timing-safe comparison).
	const enc = new TextEncoder();
	const sigBytes = enc.encode(signature);
	const expBytes = enc.encode(expected);
	let mismatch = sigBytes.length !== expBytes.length ? 1 : 0;
	const maxLen = Math.max(sigBytes.length, expBytes.length);
	for (let i = 0; i < maxLen; i++) {
		mismatch |= (sigBytes[i] ?? 0) ^ (expBytes[i] ?? 0);
	}
	if (mismatch !== 0) {
		return c.json({ error: "invalid signature" }, 401);
	}

	const parseResult = YaramailCallbackBody.safeParse(
		JSON.parse(rawBody === "" ? "{}" : rawBody),
	);
	if (!parseResult.success) {
		return c.json({ error: "invalid request body" }, 400);
	}

	const mailboxId = decodeURIComponent(c.req.param("mailboxId") ?? "");
	if (!mailboxId) return c.json({ error: "Mailbox ID required" }, 400);

	const { emailId, matches } = parseResult.data;
	const scoreDelta = computeYaraScoreDelta(matches as YaraMatchResult[]);

	const stub = c.env.MAILBOX.get(c.env.MAILBOX.idFromName(mailboxId));
	const scannedAt = Math.floor(Date.now() / 1000);

	await stub.insertYaraScanResult(emailId, JSON.stringify(matches), scannedAt);
	await stub.applyYaraSignal(emailId, scoreDelta);

	return c.json({ ok: true, scoreDelta });
});
