// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Heuristic threat analyzer for catch-all (mailbox-less) mail.
 *
 * Composes the pure, mailbox-agnostic scorers — SPF/DKIM/DMARC auth, URL
 * homograph/shortener heuristics, and source-IP reputation via Spamhaus DROP
 * and CrowdSec CTI — into a structured verdict. No LLM, no per-mailbox
 * reputation graph, no persistence: the caller owns storage (issue D).
 *
 * All IP-reputation lookups are best-effort. Transient KV or CTI failures
 * degrade to no-boost without throwing.
 */

import type { Env } from "../types";
import type { AuthVerdict } from "./auth";
import { parseAuthResults, scoreAuth, extractReceivedFromIp } from "./auth";
import { extractUrls, scoreUrls } from "./urls";
import { lookupIp } from "../intel/crowdsec-cti";
import { checkIpAgainstDefaultFeeds } from "../intel/feeds";

export interface CatchallInput {
	/** PostalMime raw-headers array — passed straight to `parseAuthResults`. */
	rawHeaders: unknown;
	/** HTML or plain-text body. Null/undefined → no URLs extracted. */
	body: string | null | undefined;
	from?: { address?: string; name?: string };
	subject?: string;
}

export type CatchallBand = "low" | "medium" | "high";

export interface CatchallIntelMatch {
	source: "spamhaus" | "crowdsec";
	/** Human-readable detail: CIDR for Spamhaus, reputation+score for CrowdSec. */
	detail: string;
}

export interface CatchallVerdict {
	/** Heuristic threat score, clamped to [0, 100]. */
	score: number;
	/** Risk band derived from score: low <30, medium 30–59, high ≥60. */
	band: CatchallBand;
	/** Human-readable signal list. */
	signals: string[];
	/** Parsed SPF/DKIM/DMARC verdict. */
	auth: AuthVerdict;
	/** Summary of URL heuristic findings. */
	urlFlags: { homograph: boolean; shortener: boolean; count: number };
	/** First IP-reputation match (Spamhaus preferred over CrowdSec), or null. */
	intelMatch: CatchallIntelMatch | null;
	/** Lowercase sender address, or empty string. */
	sender: string;
	/** First public IP from Received: headers, or undefined. */
	sourceIp: string | undefined;
}

const BAND_MEDIUM = 30;
const BAND_HIGH = 60;

function toBand(score: number): CatchallBand {
	if (score >= BAND_HIGH) return "high";
	if (score >= BAND_MEDIUM) return "medium";
	return "low";
}

/**
 * Score boost applied when CrowdSec CTI reports an IP's reputation.
 * `known` is intentionally modest — "appeared in CTI data" without a
 * clear malice verdict is a weak signal; only escalate on explicit
 * malicious/suspicious classifications.
 */
const CTI_BOOST: Record<string, number> = {
	malicious: 25,
	suspicious: 15,
	known: 5,
};

export async function analyzeCatchall(
	env: Env,
	input: CatchallInput,
): Promise<CatchallVerdict> {
	const signals: string[] = [];
	let score = 0;

	const sender = (input.from?.address ?? "").toLowerCase();

	// ── Auth ──────────────────────────────────────────────────────────────
	// No trusted authserv-id list for catch-all — there's no per-mailbox
	// config to draw one from.
	const auth = parseAuthResults(input.rawHeaders);
	const authResult = scoreAuth(auth);
	score += authResult.score;
	signals.push(...authResult.reasons);

	// ── URL heuristics ────────────────────────────────────────────────────
	const urls = extractUrls(input.body);
	const urlResult = scoreUrls(urls);
	score += urlResult.score;
	signals.push(...urlResult.reasons);

	const urlFlags: CatchallVerdict["urlFlags"] = {
		homograph: urls.some((u) => u.is_homograph),
		shortener: urls.some((u) => u.is_shortener),
		count: urls.length,
	};

	// ── Source-IP reputation ──────────────────────────────────────────────
	const sourceIp = extractReceivedFromIp(input.rawHeaders);
	let intelMatch: CatchallIntelMatch | null = null;

	if (sourceIp) {
		// Spamhaus DROP / EDROP — best-effort; swallow KV errors
		let dropMatch: Awaited<ReturnType<typeof checkIpAgainstDefaultFeeds>> = null;
		try {
			dropMatch = await checkIpAgainstDefaultFeeds(env, sourceIp);
		} catch {
			// Transient KV failure — degrade to no signal
		}
		if (dropMatch) {
			score += 30;
			const detail = `${dropMatch.feedDescription} (${dropMatch.cidr})`;
			signals.push(`Spamhaus DROP match: ${detail}`);
			intelMatch = { source: "spamhaus", detail };
		}

		// CrowdSec CTI — lookupIp never throws; errors already swallowed inside
		let cti: Awaited<ReturnType<typeof lookupIp>> = null;
		try {
			cti = await lookupIp(env, sourceIp);
		} catch {
			// Defense-in-depth: lookupIp shouldn't throw but be safe anyway
		}
		if (cti) {
			const boost = CTI_BOOST[cti.reputation] ?? 0;
			if (boost > 0) {
				const detail = `CrowdSec ${cti.reputation} (threat:${cti.scores.threat})`;
				score += boost;
				signals.push(detail);
				if (!intelMatch) {
					intelMatch = { source: "crowdsec", detail };
				}
			}
		}
	}

	score = Math.max(0, Math.min(100, Math.round(score)));

	return {
		score,
		band: toBand(score),
		signals,
		auth,
		urlFlags,
		intelMatch,
		sender,
		sourceIp,
	};
}
