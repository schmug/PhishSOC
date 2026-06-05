// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Catch-all analyzer — heuristic threat scoring for mailbox-less messages.
 *
 * Composes the existing pure scorers (auth, URLs) with env-level IP reputation
 * (CrowdSec CTI + Spamhaus DROP/EDROP). Never calls env.AI, never reads
 * per-mailbox settings, never persists — the caller owns storage.
 */

import type { Email } from "postal-mime";
import type { Env } from "../types";
import { parseAuthResults, scoreAuth, extractReceivedFromIp } from "./auth";
import { extractUrls, scoreUrls } from "./urls";
import { lookupIp } from "../intel/crowdsec-cti";
import { checkIpAgainstDefaultFeeds } from "../intel/feeds";

export type CatchallBand = "low" | "medium" | "high";

export interface CatchallInput {
	parsedEmail: Email;
}

export interface CatchallVerdict {
	score: number;
	band: CatchallBand;
	signals: string[];
	auth: ReturnType<typeof parseAuthResults>;
	urlFlags: { homograph: boolean; shortener: boolean };
	intelMatch: { crowdsec: boolean; drop: boolean };
	sender: string;
	sourceIp: string | undefined;
}

function toBand(score: number): CatchallBand {
	if (score >= 60) return "high";
	if (score >= 30) return "medium";
	return "low";
}

export async function analyzeCatchall(
	env: Env,
	input: CatchallInput,
): Promise<CatchallVerdict> {
	const { parsedEmail } = input;

	const auth = parseAuthResults(parsedEmail.headers);
	const authScore = scoreAuth(auth);

	const body = parsedEmail.html ?? parsedEmail.text ?? null;
	const urls = extractUrls(body);
	const urlScore = scoreUrls(urls);

	const sourceIp = extractReceivedFromIp(parsedEmail.headers);
	const sender = parsedEmail.from?.address ?? "";

	let score = Math.min(authScore.score, 30) + Math.min(urlScore.score, 25);
	const signals: string[] = [...authScore.reasons, ...urlScore.reasons];

	const intelMatch = { crowdsec: false, drop: false };

	if (sourceIp) {
		const [cti, drop] = await Promise.all([
			lookupIp(env, sourceIp).catch(() => null),
			checkIpAgainstDefaultFeeds(env, sourceIp).catch(() => null),
		]);
		if (cti && (cti.reputation === "malicious" || cti.reputation === "suspicious")) {
			const boost = cti.reputation === "malicious" ? 20 : 10;
			score += boost;
			signals.push(`crowdsec-cti: ${sourceIp} reputation=${cti.reputation}`);
			intelMatch.crowdsec = true;
		}
		if (drop) {
			score += 25;
			signals.push(`spamhaus-drop: ${sourceIp} in ${drop.cidr} (${drop.feedId})`);
			intelMatch.drop = true;
		}
	}

	score = Math.max(0, Math.min(100, score));

	return {
		score,
		band: toBand(score),
		signals,
		auth,
		urlFlags: {
			homograph: urls.some((u) => u.is_homograph),
			shortener: urls.some((u) => u.is_shortener),
		},
		intelMatch,
		sender,
		sourceIp,
	};
}
