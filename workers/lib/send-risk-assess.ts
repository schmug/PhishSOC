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
 *
 * The outbound LLM verdict (slice 3) is gathered here too, so preflight and
 * the gate share it. Preflight runs the model with a full budget and caches
 * the verdict in the DO keyed on the classifier input; the gate reuses a
 * cached verdict, and on a miss runs the model with a tight budget.
 */

import { classifySend, type ClassifySendInput, type SendRisk, type SendRiskContext } from "../security/send-risk";
import { extractUrls } from "../security/urls";
import { checkUrlsAgainstFeeds } from "../intel/feeds";
import { parseRecipientList, type SendContextRows } from "../durableObject/recipient-graph";
import type { CachedOutboundVerdict } from "../durableObject/send-risk-llm-cache";
import {
	GATE_BUDGET_MS,
	PREFLIGHT_BUDGET_MS,
	buildOutboundClassifierInput,
	classifyOutbound,
	outboundCacheKey,
	outboundModel,
	type OriginalMessage,
} from "../security/send-risk-llm";
import type { MailboxSecuritySettings } from "../security/defaults";
import { resolveMailboxSettings } from "./mailbox-settings";
import type { Env } from "../types";

/** The MailboxDO methods the assessment uses. The cache methods are optional: absent = no caching. */
export interface SendContextStub {
	getSendContext(args: { addresses: string[]; originalRef?: string | null }): Promise<SendContextRows>;
	getSendRiskLlmCache?(key: string): Promise<CachedOutboundVerdict | null>;
	putSendRiskLlmCache?(key: string, verdict: CachedOutboundVerdict): Promise<void>;
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
	/**
	 * "preflight" gives the LLM classifier its full budget and warms the
	 * verdict cache; "gate" (default) prefers the cache and otherwise runs the
	 * model with a tight budget, since the user is waiting on Send.
	 */
	phase?: "preflight" | "gate";
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

/**
 * The outbound LLM verdict for this send, or undefined when the classifier
 * is off, there is no model binding, or the user wrote nothing to classify.
 */
async function gatherLlmVerdict(
	env: AssessEnv,
	stub: SendContextStub | undefined,
	input: AssessSendRiskInput,
	settings: MailboxSecuritySettings["send_risk"] | undefined,
	original: OriginalMessage | null,
): Promise<SendRiskContext["llm"]> {
	// A failed settings read leaves this on: the verdict can only raise the tier.
	if (settings?.llm_enabled === false) return undefined;
	const classifierInput = buildOutboundClassifierInput({
		subject: input.subject,
		body: input.body,
		original,
		agentAuthored: input.createdBy === "agent",
	});
	if (!classifierInput) return undefined;

	const model = outboundModel(settings?.classifier_model);
	const key = await outboundCacheKey(model, classifierInput);
	const cached = stub?.getSendRiskLlmCache
		? await bestEffort("llm cache", () => stub.getSendRiskLlmCache!(key))
		: null;
	if (cached) return cached;

	const timeoutMs = input.phase === "preflight" ? PREFLIGHT_BUDGET_MS : GATE_BUDGET_MS;
	const result = await classifyOutbound(env.AI, classifierInput, { model, timeoutMs });
	if (!result) return undefined;
	if (result.cacheable && stub?.putSendRiskLlmCache) {
		const verdict = result.verdict as CachedOutboundVerdict;
		await bestEffort("llm cache write", () => stub.putSendRiskLlmCache!(key, verdict));
	}
	return result.verdict;
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

	const llm = await gatherLlmVerdict(env, stub, input, security?.send_risk, rows?.original ?? null);

	return {
		recipientHistory: rows ? Object.fromEntries(rows.recipients.map((r) => [r.address, r])) : undefined,
		domainSendCounts: rows?.domainSendCounts,
		knownDomains: rows?.knownDomains,
		thread: parseThreadVerdict(rows?.originalVerdict),
		feedHits,
		customBlockedExtensions: security?.attachment_policy?.custom_blocklist_extensions ?? [],
		trustKnownRecipients: input.channel === "api" && security?.send_risk?.trust_known_recipients === true,
		...(llm ? { llm } : {}),
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
