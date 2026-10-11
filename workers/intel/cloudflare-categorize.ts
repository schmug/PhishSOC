// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Analyst-confirmed "Submit to Cloudflare" phishing categorization (issue
 * #755). Sends a registrable domain to Cloudflare's miscategorization
 * endpoint requesting a security category (Phishing 131 by default).
 *
 * The endpoint is fire-and-forget (no ticket id, no status API) and draws on
 * the account's shared 100/month Threat Intel quota, so this module owns the
 * guard rails: registrable-domain reduction, a never-submit list, per-domain
 * dedupe and a monthly cap. Records live in BLOOM_KV under `cf-cat:*`. KV is
 * not atomic, so the cap is best-effort under concurrent clicks.
 *
 * Never called from `report-phish` or any pipeline stage.
 */

import { normalizeHost } from "../lib/url-canonical";
import { HIGH_VALUE_DOMAINS } from "../security/urls";
import type { Env } from "../types";

export const CATEGORY_PHISHING = 131;
export const CATEGORY_SCAM = 191;
export const CATEGORY_MALWARE = 117;
export const ALLOWED_CATEGORIES = [CATEGORY_PHISHING, CATEGORY_SCAM, CATEGORY_MALWARE] as const;

export const DEFAULT_MONTHLY_CAP = 20;

/** Shared platforms: a submission cannot succeed and wastes review time. */
const SHARED_PLATFORM_DOMAINS = [
	"sharepoint.com", "google.com", "forms.gle", "goo.gl", "docs.google.com",
	"googleapis.com", "gstatic.com", "withgoogle.com", "page.link",
	"live.com", "office.com", "office365.com", "microsoft.com", "microsoftonline.com",
	"windows.net", "azurewebsites.net", "azureedge.net", "onmicrosoft.com",
	"cloudflare.com", "workers.dev", "pages.dev", "r2.dev",
	"github.io", "githubusercontent.com", "gitlab.io",
	"herokuapp.com", "netlify.app", "vercel.app", "web.app", "firebaseapp.com",
	"blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "squarespace.com",
	"notion.site", "canva.com", "typeform.com", "jotform.com", "airtable.com",
	"dropbox.com", "box.com", "wetransfer.com", "docusign.net",
	"amazonaws.com", "cloudfront.net", "bit.ly", "t.co", "tinyurl.com",
];

/** Second-level labels that make a 2-letter ccTLD a public suffix (co.uk). */
const CC_SECOND_LEVEL = new Set(["co", "com", "org", "net", "gov", "edu", "ac", "ne", "or", "go"]);

/**
 * Registrable domain (eTLD+1) of a host, or null for an invalid host or an IP
 * literal. Heuristic without a public-suffix list: the last two labels, or
 * three when a 2-letter ccTLD is preceded by a common second-level label.
 */
export function registrableDomain(host: string): string | null {
	const h = normalizeHost(host);
	if (!h || h.includes(":") || /^\d+(\.\d+){3}$/.test(h)) return null;
	const labels = h.split(".");
	if (labels.length < 2) return null;
	const tld = labels[labels.length - 1];
	const sld = labels[labels.length - 2];
	if (tld.length === 2 && CC_SECOND_LEVEL.has(sld) && labels.length >= 3) {
		return labels.slice(-3).join(".");
	}
	return labels.slice(-2).join(".");
}

function parseExtraBlocked(raw: string | undefined): string[] {
	if (!raw) return [];
	return raw
		.split(",")
		.map((d) => normalizeHost(d))
		.filter((d): d is string => !!d);
}

/** True when `domain` equals, or is a subdomain of, any never-submit entry. */
export function isBlockedDomain(env: Pick<Env, "CF_CATEGORIZE_EXTRA_BLOCKED">, domain: string): boolean {
	const blocked = [...HIGH_VALUE_DOMAINS, ...SHARED_PLATFORM_DOMAINS, ...parseExtraBlocked(env.CF_CATEGORIZE_EXTRA_BLOCKED)];
	return blocked.some((b) => domain === b || domain.endsWith(`.${b}`));
}

export function isCategorizeConfigured(env: Pick<Env, "CLOUDFLARE_INTEL_API_TOKEN" | "CLOUDFLARE_INTEL_ACCOUNT_ID">): boolean {
	return !!env.CLOUDFLARE_INTEL_API_TOKEN && !!env.CLOUDFLARE_INTEL_ACCOUNT_ID;
}

export function monthlyCap(env: Pick<Env, "CF_CATEGORIZE_MONTHLY_CAP">): number {
	const n = Number.parseInt(env.CF_CATEGORIZE_MONTHLY_CAP ?? "", 10);
	return Number.isFinite(n) && n >= 0 ? n : DEFAULT_MONTHLY_CAP;
}

export interface CloudflareSubmission {
	domain: string;
	case_id: string;
	analyst: string;
	submitted_at: string;
	category_id: number;
}

const domainKey = (d: string) => `cf-cat:domain:${d}`;
const caseKey = (id: string) => `cf-cat:case:${id}`;
const capKey = (now: Date) => `cf-cat:cap:${now.toISOString().slice(0, 7)}`;

export async function getDomainSubmission(kv: KVNamespace, domain: string): Promise<CloudflareSubmission | null> {
	return (await kv.get(domainKey(domain), "json").catch(() => null)) as CloudflareSubmission | null;
}

export async function listCaseSubmissions(kv: KVNamespace | undefined, caseId: string): Promise<CloudflareSubmission[]> {
	if (!kv) return [];
	const v = (await kv.get(caseKey(caseId), "json").catch(() => null)) as CloudflareSubmission[] | null;
	return Array.isArray(v) ? v : [];
}

export async function monthlyCount(kv: KVNamespace, now: Date = new Date()): Promise<number> {
	const n = Number.parseInt((await kv.get(capKey(now), "text").catch(() => null)) ?? "0", 10);
	return Number.isFinite(n) ? n : 0;
}

/** Sends the request. Returns true only on an HTTP 2xx with `success: true`. */
export async function sendCategorization(
	env: Pick<Env, "CLOUDFLARE_INTEL_API_TOKEN" | "CLOUDFLARE_INTEL_ACCOUNT_ID">,
	domain: string,
	categoryId: number,
	fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
	try {
		const res = await fetchImpl(
			`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(env.CLOUDFLARE_INTEL_ACCOUNT_ID ?? "")}/intel/miscategorization`,
			{
				method: "POST",
				headers: {
					authorization: `Bearer ${env.CLOUDFLARE_INTEL_API_TOKEN}`,
					"content-type": "application/json",
				},
				body: JSON.stringify({ indicator_type: "domain", url: domain, security_adds: [categoryId] }),
				signal: AbortSignal.timeout(10_000),
			},
		);
		if (!res.ok) return false;
		const body = (await res.json().catch(() => null)) as { success?: boolean } | null;
		return body?.success === true;
	} catch {
		return false;
	}
}

/** Persists the submission record and bumps the monthly counter. */
export async function recordSubmission(
	kv: KVNamespace,
	sub: CloudflareSubmission,
	now: Date = new Date(),
): Promise<void> {
	await kv.put(domainKey(sub.domain), JSON.stringify(sub));
	const existing = await listCaseSubmissions(kv, sub.case_id);
	await kv.put(caseKey(sub.case_id), JSON.stringify([...existing, sub]));
	const count = await monthlyCount(kv, now);
	await kv.put(capKey(now), String(count + 1), { expirationTtl: 40 * 86400 });
}
