// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Catch-all probe analyzer — no AI, no EmailAgent, no R2 writes.
 *
 * Composes the pure heuristic scorers from the synchronous security pipeline
 * (auth + URL heuristics) with CrowdSec CTI IP reputation. Intentionally
 * omits the LLM classifier, attachment OCR, and per-mailbox sender-reputation
 * store — catch-all mail is unsolicited and attacker-shaped; feeding it to
 * the classifier would inflate costs and pollute per-mailbox state.
 *
 * Spamhaus DROP/EDROP lookup is deferred to Follow-up F: `checkIpAgainstFeeds`
 * is `mailboxId`-scoped and needs domain-level feed resolution before it can
 * be called from the catch-all path.
 */

import type { Env } from "../types";
import {
	parseAuthResults,
	extractReceivedFromIp,
	scoreAuth,
	type AuthVerdict,
} from "./auth";
import { extractUrls, scoreUrls } from "./urls";
import { lookupIp, type CtiSummary } from "../intel/crowdsec-cti";
import { firstTimeSenderPriorFromCti } from "./reputation";

export interface CatchallInput {
	parsedEmail: {
		/** Raw headers array as produced by PostalMime. */
		headers: unknown;
		from?: { address?: string; name?: string };
		html?: string;
		text?: string;
	};
	env: Env;
}

export interface CatchallAnalysisResult {
	/** Aggregate threat score, 0–100. */
	score: number;
	/** Human-readable signal labels (auth fail, homograph, CTI reputation). */
	signals: string[];
	auth: AuthVerdict;
	/** Originating external IP extracted from `Received:` headers, if found. */
	senderIp: string | undefined;
	urlCount: number;
	homographUrls: number;
	shortenerUrls: number;
	/** CrowdSec CTI reputation bucket, or null when CTI is unconfigured / returned no data. */
	ctiReputation: CtiSummary["reputation"] | null;
}

/**
 * Analyze a catch-all probe email without invoking the LLM or accessing any
 * mailbox Durable Object. Returns a scored result suitable for persistence by
 * `CatchallIntelDO` (Core C).
 *
 * Never throws: all external lookups (CrowdSec CTI) are wrapped. A transient
 * CTI failure returns null for `ctiReputation` without degrading the auth or
 * URL portions of the score.
 */
export async function analyzeCatchall(
	input: CatchallInput,
): Promise<CatchallAnalysisResult> {
	const { parsedEmail, env } = input;
	const signals: string[] = [];

	// ── Stage 1: auth (SPF / DKIM / DMARC) ────────────────────────────
	const auth = parseAuthResults(parsedEmail.headers);
	const authResult = scoreAuth(auth);
	signals.push(...authResult.reasons);

	// ── Stage 2: URL heuristics ────────────────────────────────────────
	const body = parsedEmail.html ?? parsedEmail.text ?? "";
	const urls = extractUrls(body);
	const urlResult = scoreUrls(urls);
	signals.push(...urlResult.reasons);

	// ── Stage 3: CrowdSec CTI IP reputation ───────────────────────────
	// Only runs when the API key is configured; absent key is a no-op.
	const senderIp = extractReceivedFromIp(parsedEmail.headers);
	let ctiReputation: CtiSummary["reputation"] | null = null;
	let ctiScore = 0;

	if (senderIp && env.CROWDSEC_CTI_API_KEY) {
		const summary = await lookupIp(env, senderIp).catch(() => null);
		if (summary) {
			ctiReputation = summary.reputation;
			const prior = firstTimeSenderPriorFromCti(senderIp, summary);
			ctiScore = prior.score;
			signals.push(prior.reason);
		}
	}

	const score = Math.min(100, Math.max(0, authResult.score + urlResult.score + ctiScore));

	return {
		score,
		signals,
		auth,
		senderIp,
		urlCount: urls.length,
		homographUrls: urls.filter((u) => u.is_homograph).length,
		shortenerUrls: urls.filter((u) => u.is_shortener).length,
		ctiReputation,
	};
}
