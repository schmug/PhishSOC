// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Cloudflare URL Scanner client (issue #754). Analyst-triggered only: never
 * call from the receive pipeline, the security pipeline or deep-scan, and
 * never expose `submitScan` to the agent or MCP (email content could
 * prompt-inject it into spending quota or visiting attacker links).
 *
 * `visibility` is hard-coded to "Unlisted" — a Public scan would publish
 * recipient-specific link tokens to every Radar user. No `customHeaders` or
 * `referer` is ever sent, so no recipient data leaves with the scan.
 */

import type { Env } from "../types";
import { canonicalFeedUrl } from "../lib/url-canonical";

export type ScanTransport = (url: string, init?: RequestInit) => Promise<Response>;

export const DEFAULT_MONTHLY_CAP = 450;
export const MIN_SUBMIT_SPACING_S = 10;
const REQUEST_TIMEOUT_MS = 8000;
const QUOTA_PREFIX = "urlscan:quota:";
const LAST_SUBMIT_KEY = "urlscan:last-submit";

export interface ScanResult {
	uuid: string;
	status: "pending" | "done";
	malicious: boolean | null;
	categories: string[];
	finalUrl: string | null;
}

export type SubmitOutcome =
	| { ok: true; uuid: string; reused: boolean }
	| { ok: false; reason: "not_configured" | "invalid_url" | "quota" | "spacing" | "upstream"; remaining?: number };

type ScannerEnv = Pick<Env, "BLOOM_KV"> & {
	URLSCAN_API_TOKEN?: string;
	URLSCAN_ACCOUNT_ID?: string;
	URLSCAN_MONTHLY_CAP?: string;
};

export function isConfigured(env: ScannerEnv): boolean {
	return Boolean(env.URLSCAN_API_TOKEN && env.URLSCAN_ACCOUNT_ID);
}

function base(env: ScannerEnv): string {
	return `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(env.URLSCAN_ACCOUNT_ID ?? "")}/urlscanner/v2/`;
}

function headers(env: ScannerEnv, json = false): Record<string, string> {
	const h: Record<string, string> = { authorization: `Bearer ${env.URLSCAN_API_TOKEN}` };
	if (json) h["content-type"] = "application/json";
	return h;
}

function monthKey(now: Date): string {
	return QUOTA_PREFIX + now.toISOString().slice(0, 7);
}

function cap(env: ScannerEnv): number {
	const n = Number.parseInt(env.URLSCAN_MONTHLY_CAP ?? "", 10);
	return Number.isFinite(n) && n > 0 ? n : DEFAULT_MONTHLY_CAP;
}

/** Remaining submits this month (cap − used). */
export async function remainingQuota(env: ScannerEnv, now = new Date()): Promise<number> {
	const used = Number.parseInt((await env.BLOOM_KV?.get(monthKey(now), "text").catch(() => null)) ?? "0", 10);
	return Math.max(0, cap(env) - (Number.isFinite(used) ? used : 0));
}

/** Look for a prior scan (public or this account's unlisted) of the canonical URL. */
export async function findPriorScan(
	env: ScannerEnv,
	canonical: string,
	fetchImpl: ScanTransport = fetch,
): Promise<string | null> {
	try {
		const q = encodeURIComponent(`page.url:"${canonical.replace(/["\\]/g, "\\$&")}"`);
		const res = await fetchImpl(`${base(env)}search?q=${q}&size=1`, {
			headers: headers(env),
			signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
		});
		if (!res.ok) return null;
		const body = (await res.json()) as { results?: Array<{ _id?: string; task?: { uuid?: string } }> };
		const hit = body.results?.[0];
		return hit?.task?.uuid ?? hit?._id ?? null;
	} catch {
		return null;
	}
}

/**
 * Submit a scan. `opts` deliberately has no visibility field. Order: config →
 * canonicalize → search-first reuse (free, unless `force`) → spacing → quota →
 * POST. Quota/spacing failures make no outbound call.
 */
export async function submitScan(
	env: ScannerEnv,
	rawUrl: string,
	opts: { force?: boolean; now?: Date } = {},
	fetchImpl: ScanTransport = fetch,
): Promise<SubmitOutcome> {
	if (!isConfigured(env)) return { ok: false, reason: "not_configured" };
	const canonical = canonicalFeedUrl(rawUrl);
	if (!canonical) return { ok: false, reason: "invalid_url" };

	if (!opts.force) {
		const prior = await findPriorScan(env, canonical, fetchImpl);
		if (prior) return { ok: true, uuid: prior, reused: true };
	}

	const now = opts.now ?? new Date();
	const remaining = await remainingQuota(env, now);
	if (remaining <= 0) return { ok: false, reason: "quota", remaining: 0 };
	const last = Number.parseInt((await env.BLOOM_KV?.get(LAST_SUBMIT_KEY, "text").catch(() => null)) ?? "0", 10);
	if (Number.isFinite(last) && now.getTime() - last < MIN_SUBMIT_SPACING_S * 1000) {
		return { ok: false, reason: "spacing", remaining };
	}

	let res: Response;
	try {
		res = await fetchImpl(`${base(env)}scan`, {
			method: "POST",
			headers: headers(env, true),
			body: JSON.stringify({ url: canonical, visibility: "Unlisted" }),
			signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
		});
	} catch {
		return { ok: false, reason: "upstream" };
	}
	if (!res.ok) return { ok: false, reason: "upstream" };
	const body = (await res.json().catch(() => null)) as { uuid?: string; result?: { uuid?: string } } | null;
	const uuid = body?.uuid ?? body?.result?.uuid;
	if (!uuid) return { ok: false, reason: "upstream" };

	await env.BLOOM_KV?.put(monthKey(now), String(cap(env) - remaining + 1), { expirationTtl: 40 * 86400 }).catch(() => {});
	await env.BLOOM_KV?.put(LAST_SUBMIT_KEY, String(now.getTime()), { expirationTtl: 60 }).catch(() => {});
	return { ok: true, uuid, reused: false };
}

/** Poll a scan. 404 ⇒ pending. Returns null on not-configured or transient failure. */
export async function getScanResult(
	env: ScannerEnv,
	uuid: string,
	fetchImpl: ScanTransport = fetch,
): Promise<ScanResult | null> {
	if (!isConfigured(env) || !/^[0-9a-f-]{8,64}$/i.test(uuid)) return null;
	let res: Response;
	try {
		res = await fetchImpl(`${base(env)}result/${uuid}`, {
			headers: headers(env),
			signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
		});
	} catch {
		return null;
	}
	if (res.status === 404) return { uuid, status: "pending", malicious: null, categories: [], finalUrl: null };
	if (!res.ok) return null;
	const body = (await res.json().catch(() => null)) as {
		result?: unknown;
		verdicts?: { overall?: { malicious?: unknown; categories?: unknown } };
		page?: { url?: unknown };
	} | null;
	if (!body) return null;
	const overall = body.verdicts?.overall;
	const cats = Array.isArray(overall?.categories)
		? (overall.categories as unknown[]).flatMap((c) =>
				typeof c === "string" ? [c] : typeof (c as { name?: unknown })?.name === "string" ? [(c as { name: string }).name] : [],
			)
		: [];
	return {
		uuid,
		status: "done",
		malicious: typeof overall?.malicious === "boolean" ? overall.malicious : null,
		categories: cats,
		finalUrl: typeof body.page?.url === "string" ? body.page.url : null,
	};
}

/** Fetch the screenshot PNG for an authenticated Worker route to proxy. */
export async function fetchScreenshot(
	env: ScannerEnv,
	uuid: string,
	fetchImpl: ScanTransport = fetch,
): Promise<Response | null> {
	if (!isConfigured(env) || !/^[0-9a-f-]{8,64}$/i.test(uuid)) return null;
	try {
		const res = await fetchImpl(`${base(env)}screenshots/${uuid}.png`, {
			headers: headers(env),
			signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
		});
		return res.ok ? res : null;
	} catch {
		return null;
	}
}
