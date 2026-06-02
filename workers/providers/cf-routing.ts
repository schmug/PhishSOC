// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Inbound normaliser for Cloudflare Email Routing.
 *
 * Cloudflare calls the Worker's `email()` handler with a raw RFC-5322
 * stream.  This module is the CF-specific boundary: it converts the
 * stream to an `ArrayBuffer`, parses it with PostalMime, and resolves
 * the target mailboxId.  The result is a `NormalizedInbound` that the
 * shared pipeline (`receiveEmail` in workers/index.ts) can process
 * without knowing anything about CF Email Routing.
 */

import PostalMime from "postal-mime";
import type { Env } from "../types";
import type { NormalizedInbound } from "./types";

const MAX_EMAIL_SIZE = 25 * 1024 * 1024;

async function streamToArrayBuffer(
	stream: ReadableStream,
	streamSize: number,
): Promise<Uint8Array> {
	if (streamSize > MAX_EMAIL_SIZE) {
		throw new Error(`Email too large: ${streamSize} bytes exceeds ${MAX_EMAIL_SIZE} byte limit`);
	}
	if (streamSize <= 0) throw new Error(`Invalid stream size: ${streamSize}`);
	const result = new Uint8Array(streamSize);
	let bytesRead = 0;
	const reader = stream.getReader();
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		if (bytesRead + value.length > streamSize) {
			reader.cancel();
			throw new Error("Stream exceeds declared size");
		}
		result.set(value, bytesRead);
		bytesRead += value.length;
	}
	return result;
}

/**
 * Normalise a CF Email Routing event into `NormalizedInbound`.
 *
 * Returns `null` when the email should be silently ignored (no matching
 * mailbox recipient or the mailbox does not exist); callers should return
 * without rethrowing in that case.  Any other failure is thrown so CF
 * Email Routing can retry or bounce the message.
 */
export async function normalizeInbound(
	event: { raw: ReadableStream; rawSize: number },
	env: Env,
): Promise<NormalizedInbound | null> {
	const rawEmail = await streamToArrayBuffer(event.raw, event.rawSize);
	const parsedEmail = await new PostalMime().parse(rawEmail);

	if (!parsedEmail.to?.length || !parsedEmail.to[0].address) {
		throw new Error("received email with empty to");
	}

	const allowedAddresses = ((env.EMAIL_ADDRESSES ?? []) as string[]).map((a) => a.toLowerCase());
	const allRecipients = parsedEmail.to
		.map((t) => (t as { address?: string }).address?.toLowerCase())
		.filter((a): a is string => Boolean(a));

	let mailboxId: string | undefined;
	if (allowedAddresses.length > 0) {
		mailboxId = allRecipients.find((addr) => allowedAddresses.includes(addr));
		if (!mailboxId) {
			console.log("Ignoring email: no recipient matches EMAIL_ADDRESSES.");
			return null;
		}
	} else {
		mailboxId = allRecipients[0];
	}
	if (!mailboxId) throw new Error("received email with no valid recipient address");

	if (!(await env.BUCKET.head(`mailboxes/${mailboxId}.json`))) {
		console.log(`Ignoring email for ${mailboxId}: mailbox does not exist`);
		return null;
	}

	return { rawEmail: rawEmail.buffer as ArrayBuffer, parsedEmail, mailboxId };
}
