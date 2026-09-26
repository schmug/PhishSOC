// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Outbound recipient history and send-risk context (follow-up to #15).
 * Pure `_xImpl(sql, ...)` functions so the logic is testable against
 * node:sqlite without a Workers runtime — same pattern as
 * `sidecar-state.ts`. `MailboxDO` exposes thin delegates.
 *
 * `recipient_graph` (migration 32) is written ONLY when a row lands in
 * SENT, and every path that writes SENT runs the send-risk gate first. So
 * a recipient's history can only grow through sends the gate already let
 * through — an attacker who can merely deliver mail to the mailbox cannot
 * make an address look "established". Inbound history deliberately plays
 * no part in outbound trust.
 */

import type { SqlLike } from "./catchall-intel";
import { Folders } from "../../shared/folders";

export interface RecipientHistoryRow {
	address: string;
	send_count: number;
	first_sent: string;
	last_sent: string;
}

export interface SendContextRows {
	/** History rows for the requested addresses that have been sent to before. */
	recipients: RecipientHistoryRow[];
	/** Total prior sends per requested domain (absent = never sent to). */
	domainSendCounts: Record<string, number>;
	/** Domains with at least `KNOWN_DOMAIN_MIN_SENDS` prior sends, busiest first. */
	knownDomains: string[];
	/**
	 * `security_verdict` JSON of the message being replied to or forwarded,
	 * or null when there is no such message or it was never scored.
	 */
	originalVerdict: string | null;
}

/** Addresses/domains looked up per send. A send beyond this is already Tier 1 on count alone. */
export const SEND_CONTEXT_LOOKUP_CAP = 100;
/** A domain needs this many prior sends before it anchors lookalike comparisons. */
export const KNOWN_DOMAIN_MIN_SENDS = 2;
const KNOWN_DOMAIN_LIMIT = 500;

/**
 * Split recipient fields ("a@x.com, b@y.com" as every send path stores them)
 * into unique lowercased bare addresses. A "Name <addr>" entry yields `addr`;
 * anything without an `@` is dropped.
 */
export function parseRecipientList(...fields: Array<string | string[] | null | undefined>): string[] {
	const out = new Set<string>();
	for (const field of fields) {
		if (!field) continue;
		const parts = Array.isArray(field) ? field : [field];
		for (const part of parts.flatMap((p) => p.split(","))) {
			const angle = part.match(/<([^>]+)>/);
			const addr = (angle ? angle[1] : part).trim().toLowerCase();
			if (addr.includes("@") && !/\s/.test(addr)) out.add(addr);
		}
	}
	return [...out];
}

export function domainOf(address: string): string {
	const at = address.lastIndexOf("@");
	return at >= 0 ? address.slice(at + 1).toLowerCase() : "";
}

/** Upsert one history row per recipient of a message just written to SENT. */
export function _recordSentRecipientsImpl(sql: SqlLike, addresses: string[], nowIso: string): void {
	for (const address of addresses) {
		const domain = domainOf(address);
		if (!domain) continue;
		sql.exec(
			`INSERT INTO recipient_graph (address, domain, send_count, first_sent, last_sent)
			 VALUES (?1, ?2, 1, ?3, ?3)
			 ON CONFLICT(address) DO UPDATE SET send_count = send_count + 1, last_sent = excluded.last_sent`,
			address,
			domain,
			nowIso,
		);
	}
}

function placeholders(n: number): string {
	return Array.from({ length: n }, (_, i) => `?${i + 1}`).join(", ");
}

/**
 * Resolve the verdict of the message a send replies to or forwards.
 * `originalRef` is an email row id (reply/forward routes, the composer) or
 * an RFC Message-ID (`in_reply_to` from API clients). A draft reference
 * resolves through its own `in_reply_to`, mirroring `resolveOriginalEmail`.
 */
function resolveOriginalVerdict(sql: SqlLike, originalRef: string): string | null {
	type Row = { security_verdict: string | null; folder_id: string; in_reply_to: string | null };
	const byId = (id: string) =>
		[...sql.exec<Row>(`SELECT security_verdict, folder_id, in_reply_to FROM emails WHERE id = ?1 LIMIT 1`, id)][0];

	let row = byId(originalRef);
	if (row && row.folder_id === Folders.DRAFT && row.in_reply_to) {
		row = byId(row.in_reply_to) ?? row;
	}
	if (!row) {
		const messageId = originalRef.trim().replace(/^<|>$/g, "");
		if (messageId) {
			row = [...sql.exec<Row>(
				`SELECT security_verdict, folder_id, in_reply_to FROM emails WHERE message_id = ?1 LIMIT 1`,
				messageId,
			)][0];
		}
	}
	return row?.security_verdict ?? null;
}

/** Gather everything the send-risk classifier needs from this mailbox in one read. */
export function _getSendContextImpl(
	sql: SqlLike,
	args: { addresses: string[]; originalRef?: string | null },
): SendContextRows {
	const addresses = [...new Set(args.addresses.map((a) => a.toLowerCase()))].slice(0, SEND_CONTEXT_LOOKUP_CAP);
	const domains = [...new Set(addresses.map(domainOf).filter(Boolean))];

	const recipients = addresses.length === 0 ? [] : [
		...sql.exec<RecipientHistoryRow>(
			`SELECT address, send_count, first_sent, last_sent FROM recipient_graph
			 WHERE address IN (${placeholders(addresses.length)})`,
			...addresses,
		),
	];

	const domainSendCounts: Record<string, number> = {};
	if (domains.length > 0) {
		for (const row of sql.exec<{ domain: string; total: number }>(
			`SELECT domain, SUM(send_count) AS total FROM recipient_graph
			 WHERE domain IN (${placeholders(domains.length)}) GROUP BY domain`,
			...domains,
		)) {
			domainSendCounts[row.domain] = Number(row.total);
		}
	}

	const knownDomains = [
		...sql.exec<{ domain: string }>(
			`SELECT domain FROM recipient_graph GROUP BY domain
			 HAVING SUM(send_count) >= ?1 ORDER BY SUM(send_count) DESC LIMIT ?2`,
			KNOWN_DOMAIN_MIN_SENDS,
			KNOWN_DOMAIN_LIMIT,
		),
	].map((r) => r.domain);

	const originalVerdict = args.originalRef ? resolveOriginalVerdict(sql, args.originalRef) : null;

	return {
		recipients: recipients.map((r) => ({ ...r, send_count: Number(r.send_count) })),
		domainSendCounts,
		knownDomains,
		originalVerdict,
	};
}
