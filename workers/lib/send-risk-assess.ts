// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Stateful wrapper around the pure `classifySend` (follow-up to #15).
 *
 * Gathers the mailbox state the send-risk rules need — recipient history
 * and the replied-to message's verdict from the MailboxDO, threat-intel feed
 * hits for links in the body, and the mailbox's security settings — then
 * classifies. The preflight endpoint and the send gate both call this, so
 * the tier the composer shows is computed the same way as the tier the gate
 * enforces.
 *
 * Every lookup is best-effort. A failed lookup drops only the rules that
 * depend on it and never raises the send above what the stateless rules
 * decide; established-correspondent trust needs recipient history, so it is
 * unavailable when the history read fails.
 */

import { classifySend, type ClassifySendInput, type SendRisk, type SendRiskContext } from "../security/send-risk";
import { extractUrls } from "../security/urls";
import { checkUrlsAgainstFeeds } from "../intel/feeds";
import { parseRecipientList, type SendContextRows } from "../durableObject/recipient-graph";
import { resolveMailboxSettings } from "./mailbox-settings";
import type { Env } from "../types";

/** The one MailboxDO method the assessment reads. */
export interface SendContextStub {
	getSendContext(args: { addresses: string[]; originalRef?: string | null }): Promise<SendContextRows>;
}

export interface AssessSendRiskInput extends Omit<ClassifySendInput, "context"> {
	/**
	 * The message this send replies to or forwards: an email row id (reply /
	 * forward routes, the composer) or an RFC Message-ID (`in_reply_to` from
	 * API clients). Drives the flagged-thread rule.
	 */
	originalRef?: string | null;
	/**
	 * Where the send came from. "api" is an authenticated UI/API route; "mcp"
	 * is an MCP tool call. Established-correspondent trust is only ever
	 * applied to "api" sends — an MCP client acts without a human in the loop.
	 */
	channel?: "api" | "mcp";
}

export type AssessEnv = Pick<Env, "BLOOM_KV"> & Partial<Env>;

/** Links checked against the threat-intel feeds per send. */
const FEED_URL_CAP = 10;

async function bestEffort<T>(label: string, fn: () => Promise<T>): Promise<T | null> {
	try {
		return await fn();
	} catch (e) {
		console.warn(`assessSendRisk: ${label} lookup failed:`, e instanceof Error ? e.message : String(e));
		return null;
	}
}

function parseThreadVerdict(raw: string | null | undefined): SendRiskContext["thread"] {
	if (!raw) return null;
	try {
		const v = JSON.parse(raw) as { action?: unknown; classification?: { label?: unknown } };
		return {
			action: typeof v.action === "string" ? v.action : undefined,
			label: typeof v.classification?.label === "string" ? v.classification.label : undefined,
		};
	} catch {
		return null;
	}
}

export async function gatherSendContext(
	env: AssessEnv,
	stub: SendContextStub | undefined,
	input: AssessSendRiskInput,
): Promise<SendRiskContext> {
	const addresses = parseRecipientList(input.to, input.cc, input.bcc);
	const urls = extractUrls(input.body ?? "", FEED_URL_CAP);

	const [rows, security, feedMatches] = await Promise.all([
		stub
			? bestEffort("send context", () => stub.getSendContext({ addresses, originalRef: input.originalRef ?? null }))
			: Promise.resolve(null),
		bestEffort("settings", async () => (await resolveMailboxSettings(env as Env, input.mailboxId)).security),
		urls.length > 0 && env.BLOOM_KV
			? bestEffort("feed", () => checkUrlsAgainstFeeds(env as Env, input.mailboxId, urls.map((u) => u.url)))
			: Promise.resolve(null),
	]);

	const feedHits = (feedMatches ?? []).flatMap((m, i) =>
		m ? [{ host: urls[i].hostname, feedId: m.feedId, confirmed: m.confirmed }] : [],
	);

	return {
		recipientHistory: rows ? Object.fromEntries(rows.recipients.map((r) => [r.address, r])) : undefined,
		domainSendCounts: rows?.domainSendCounts,
		knownDomains: rows?.knownDomains,
		thread: parseThreadVerdict(rows?.originalVerdict),
		feedHits,
		customBlockedExtensions: security?.attachment_policy?.custom_blocklist_extensions ?? [],
		trustKnownRecipients: input.channel === "api" && security?.send_risk?.trust_known_recipients === true,
	};
}

/** Classify a send with full mailbox context. Used by preflight and the send gate. */
export async function assessSendRisk(
	env: AssessEnv,
	stub: SendContextStub | undefined,
	input: AssessSendRiskInput,
): Promise<SendRisk> {
	const context = await gatherSendContext(env, stub, input);
	return classifySend({ ...input, context });
}
