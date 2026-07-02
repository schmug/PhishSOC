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
 * Extract the RCPT TO address from the TOP `Received:` header's RFC 5321
 * `for <addr>` clause.
 *
 * Cloudflare Email Routing invokes `email()` once per SMTP envelope recipient
 * and prepends a `Received:` line stamped with the actual recipient of THIS
 * delivery (`for <addr>;`) before invoking the Worker. Because headers are
 * prepended at each hop, the first `Received:` header in the parsed list is the
 * one Cloudflare added at the trust boundary — the only one an upstream sender
 * cannot forge. We read the `for` clause from that header ONLY; a `for` clause
 * on any lower (older, attacker-reachable) Received line is ignored, so a
 * forged `Received: ... for <victim@owned>` cannot redirect delivery.
 *
 * Returns the lowercased address, or undefined when the top Received header is
 * absent or carries no `for` clause.
 */
export function topReceivedForAddress(headers: unknown): string | undefined {
	if (!Array.isArray(headers)) return undefined;
	let topReceived: string | undefined;
	for (const h of headers) {
		if (!h || typeof h !== "object") continue;
		const rec = h as { key?: unknown; name?: unknown; value?: unknown };
		const key = rec.key ?? rec.name;
		if (typeof key !== "string" || key.toLowerCase() !== "received") continue;
		if (typeof rec.value !== "string") continue;
		topReceived = rec.value;
		break; // first Received header = most-recent hop = Cloudflare's
	}
	if (!topReceived) return undefined;
	// RFC 5321 `for <addr>` clause. Require an '@' so a bare hostname token
	// (e.g. "for relay.example") is never mistaken for an address; tolerate
	// optional angle brackets; stop at whitespace, ';' or '>'.
	const m = /\bfor\s+<?([^\s<>;]+@[^\s<>;]+)>?/i.exec(topReceived);
	return m?.[1]?.toLowerCase();
}

/**
 * Normalise a CF Email Routing event into a discriminated-union inbound value.
 *
 * - `MailboxInbound`  — recipient matched a registered mailbox.
 * - `CatchallInbound` — no registered mailbox, but recipient is on an owned
 *                       domain with `catchall_intel.enabled`.
 * - `null`            — silently drop (unowned domain, disabled catch-all, or
 *                       an envelope recipient whose mailbox JSON is missing).
 *
 * Mailbox selection is keyed strictly off the authoritative SMTP envelope
 * recipient (the RCPT TO of this per-copy delivery), resolved as:
 *
 *   1. the TOP `Received: ... for <addr>` header Cloudflare stamps, then
 *   2. `event.to`.
 *
 * The top Received header wins because, on the Cloudflare Email Sending →
 * Cloudflare Email Routing cc/bcc/multi-recipient path, `event.to` is NOT the
 * distinct envelope recipient and collapses to the `To:` header's first
 * address — so a copy delivered for B was misfiled into A, silently losing
 * cc/bcc/secondary mail and (for bcc) disclosing it cross-mailbox
 * (GHSA-6jgg-fp96-7x3x).
 *
 * The parsed `To:`/`Cc:` headers are attacker-controlled and are NEVER used to
 * SELECT a provisioned mailbox: when the envelope recipient is known but has no
 * mailbox, we fail closed (catch-all for its own domain, else drop) rather than
 * misfile into a different mailbox named by the header. Header addresses are
 * consulted only as a last resort when no envelope recipient is available at
 * all (the single-recipient / no-Received legacy path) and for catch-all domain
 * scanning in that same case.
 *
 * Any parse/stream failure throws so CF Email Routing can retry or bounce.
 */
export async function normalizeInbound(
	event: { raw: ReadableStream; rawSize: number; to?: string },
	env: Env,
): Promise<MailboxInbound | CatchallInbound | null> {
	const rawEmail = await streamToArrayBuffer(event.raw, event.rawSize);
	const parsedEmail = await new PostalMime().parse(rawEmail);

	// Authoritative envelope recipient (RCPT TO) for this per-copy delivery:
	// the Cloudflare-stamped top `Received: ... for <addr>` wins over event.to.
	const eventTo = event.to?.trim().toLowerCase() || undefined;
	const receivedFor = topReceivedForAddress(parsedEmail.headers);
	const envelopeRecipient = receivedFor ?? eventTo;

	const headerRecipients = (parsedEmail.to ?? [])
		.map((t) => (t as { address?: string }).address?.toLowerCase())
		.filter((a): a is string => Boolean(a));

	// Candidate recipients for catch-all / allow-list scanning when no
	// authoritative envelope recipient is available: envelope recipient first,
	// then header addresses, de-duplicated.
	const allRecipients: string[] = [];
	for (const addr of [envelopeRecipient, ...headerRecipients]) {
		if (addr && !allRecipients.includes(addr)) allRecipients.push(addr);
	}
	if (allRecipients.length === 0) {
		throw new Error("received email with no envelope or header recipient");
	}

	const mkMailbox = (mailboxId: string): MailboxInbound => ({
		kind: "mailbox",
		rawEmail: rawEmail.buffer as ArrayBuffer,
		parsedEmail,
		mailboxId,
	});

	const allowedAddresses = ((env.EMAIL_ADDRESSES ?? []) as string[]).map((a) => a.toLowerCase());

	if (allowedAddresses.length > 0) {
		if (envelopeRecipient) {
			// Envelope recipient is authoritative: match it against the allow-list
			// and select strictly from it. Never file a copy delivered for one
			// RCPT into a different mailbox because that address appears in To:/Cc:.
			if (allowedAddresses.includes(envelopeRecipient)) {
				if (await env.BUCKET.head(`mailboxes/${envelopeRecipient}.json`)) {
					return mkMailbox(envelopeRecipient);
				}
				// Allowed but no mailbox JSON — fail closed (today's drop).
				console.log("Ignoring email: envelope recipient is registered but has no mailbox.");
				return null;
			}
			// Envelope recipient is not allow-listed — try catch-all for ITS domain.
			return resolveCatchall([envelopeRecipient], rawEmail, parsedEmail, env);
		}
		// No authoritative envelope recipient (single-recipient / no-Received
		// legacy path): fall back to scanning header addresses.
		const registered = allRecipients.filter((addr) => allowedAddresses.includes(addr));
		for (const addr of registered) {
			if (await env.BUCKET.head(`mailboxes/${addr}.json`)) {
				return mkMailbox(addr);
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
		// No EMAIL_ADDRESSES configured: any recipient with a provisioned mailbox
		// is deliverable.
		if (envelopeRecipient) {
			// Select strictly from the authoritative envelope recipient so a forged
			// `To:`/`Cc:` cannot misfile mail into another mailbox. If it has no
			// mailbox, fail closed to catch-all for ITS own domain — never a
			// header address's mailbox or domain.
			if (await env.BUCKET.head(`mailboxes/${envelopeRecipient}.json`)) {
				return mkMailbox(envelopeRecipient);
			}
			return resolveCatchall([envelopeRecipient], rawEmail, parsedEmail, env);
		}
		// No authoritative envelope recipient: single-recipient / no-Received
		// legacy path — resolve from the first header address, then catch-all.
		const mailboxId = headerRecipients[0];
		if (!mailboxId) throw new Error("received email with no valid recipient address");
		if (await env.BUCKET.head(`mailboxes/${mailboxId}.json`)) {
			return mkMailbox(mailboxId);
		}
		return resolveCatchall(allRecipients, rawEmail, parsedEmail, env);
	}
}

export async function getOwnedDomains(env: Env): Promise<string[]> {
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
			recipient: addr,
			domain,
			retentionDays: ci.retention_days ?? 30,
			sampleLimit: ci.sample_limit ?? 50,
		};
	}
	console.log("Ignoring email: no recipient matches EMAIL_ADDRESSES.");
	return null;
}
