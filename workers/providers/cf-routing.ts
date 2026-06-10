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
import type { MailboxInbound, CatchallInbound } from "./types";
import { getDomainSettings } from "../lib/domain-settings";
import { getOrgSettings } from "../lib/org-settings";

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
 * Normalise a CF Email Routing event into a discriminated-union inbound value.
 *
 * - `MailboxInbound`  — recipient matched a registered mailbox.
 * - `CatchallInbound` — no registered mailbox, but recipient is on an owned
 *                       domain with `catchall_intel.enabled`.
 * - `null`            — silently drop (unowned domain, disabled catch-all, or
 *                       an EMAIL_ADDRESSES member whose mailbox JSON is missing).
 *
 * Any parse/stream failure throws so CF Email Routing can retry or bounce.
 */
export async function normalizeInbound(
	event: { raw: ReadableStream; rawSize: number },
	env: Env,
): Promise<MailboxInbound | CatchallInbound | null> {
	const rawEmail = await streamToArrayBuffer(event.raw, event.rawSize);
	const parsedEmail = await new PostalMime().parse(rawEmail);

	if (!parsedEmail.to?.length || !parsedEmail.to[0].address) {
		throw new Error("received email with empty to");
	}

	const allowedAddresses = ((env.EMAIL_ADDRESSES ?? []) as string[]).map((a) => a.toLowerCase());
	const allRecipients = parsedEmail.to
		.map((t) => (t as { address?: string }).address?.toLowerCase())
		.filter((a): a is string => Boolean(a));

	if (allowedAddresses.length > 0) {
		// Step 1: find a registered mailbox among allowed addresses.
		const registered = allRecipients.filter((addr) => allowedAddresses.includes(addr));
		for (const addr of registered) {
			if (await env.BUCKET.head(`mailboxes/${addr}.json`)) {
				return { kind: "mailbox", rawEmail: rawEmail.buffer as ArrayBuffer, parsedEmail, mailboxId: addr };
			}
		}
		if (registered.length > 0) {
			// An address matched EMAIL_ADDRESSES but has no mailbox JSON — keep today's drop.
			console.log("Ignoring email: registered address has no mailbox.");
			return null;
		}
		// No address matched EMAIL_ADDRESSES — try catch-all for all recipients.
		return resolveCatchall(allRecipients, rawEmail, parsedEmail, env);
	} else {
		// No EMAIL_ADDRESSES configured — single-recipient mode for registered
		// mailboxes, then catch-all for unregistered addresses on owned domains.
		const mailboxId = allRecipients[0];
		if (!mailboxId) throw new Error("received email with no valid recipient address");
		if (await env.BUCKET.head(`mailboxes/${mailboxId}.json`)) {
			return { kind: "mailbox", rawEmail: rawEmail.buffer as ArrayBuffer, parsedEmail, mailboxId };
		}
		return resolveCatchall(allRecipients, rawEmail, parsedEmail, env);
	}
}

async function getOwnedDomains(env: Env): Promise<string[]> {
	const seed = ((env.DOMAINS ?? "") as string).split(",").map((d) => d.trim().toLowerCase()).filter(Boolean);
	try {
		const org = await getOrgSettings(env);
		const orgDomains = ((org.domains as string[] | undefined) ?? []).map((d) => d.toLowerCase());
		const seen = new Set<string>();
		const out: string[] = [];
		for (const d of [...seed, ...orgDomains]) {
			if (!seen.has(d)) { seen.add(d); out.push(d); }
		}
		return out;
	} catch {
		return seed;
	}
}

async function resolveCatchall(
	recipients: string[],
	rawEmail: Uint8Array,
	parsedEmail: Awaited<ReturnType<PostalMime["parse"]>>,
	env: Env,
): Promise<CatchallInbound | null> {
	const ownedDomains = await getOwnedDomains(env);
	for (const addr of recipients) {
		const at = addr.lastIndexOf("@");
		if (at < 0) continue;
		const domain = addr.slice(at + 1).toLowerCase();
		if (!ownedDomains.includes(domain)) continue;
		let settings;
		try {
			settings = await getDomainSettings(env, domain);
		} catch {
			continue;
		}
		const ci = settings.catchall_intel;
		if (!ci?.enabled) continue;
		return {
			kind: "catchall",
			rawEmail: rawEmail.buffer as ArrayBuffer,
			parsedEmail,
			domain,
			retentionDays: ci.retention_days ?? 30,
			sampleLimit: ci.sample_limit ?? 50,
		};
	}
	console.log("Ignoring email: no recipient matches EMAIL_ADDRESSES.");
	return null;
}
