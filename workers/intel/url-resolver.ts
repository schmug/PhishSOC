// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Follow a URL's redirect chain and surface the final URL + page title.
 *
 * The synchronous pipeline only sees the URL as it appears in the email.
 * Many phishing links use short-URLs or tracking redirectors that hop
 * through several hosts before landing on the credential-theft page. By
 * resolving the final hostname we let downstream heuristics (homograph,
 * intel-feed match) operate on the actual destination.
 *
 * The `fetchImpl` parameter is there so tests can avoid touching the
 * network; production callers use the global `fetch`.
 */

import { isPrivateOrLoopbackIp } from "../security/auth";

export const MAX_REDIRECT_HOPS = 5;
export const RESOLVE_TIMEOUT_MS = 8000;

/** Timeout for each DoH lookup performed by the SSRF guard. */
export const SSRF_DOH_TIMEOUT_MS = 2000;

const DOH_HOST = "cloudflare-dns.com";

export interface ResolvedUrl {
	original: string;
	resolved: string;
	hops: number;
	/** Trimmed `<title>` from the final GET, if any. Capped at 200 chars. */
	title: string | null;
	/** Set when the chain exits the starting hostname — a strong anti-phishing tell. */
	host_changed: boolean;
	/** HTTP status of the final response; 0 when the fetch failed. */
	final_status: number;
	/** True when the chain stopped because of MAX_REDIRECT_HOPS. */
	truncated: boolean;
}

/**
 * Resolve a hostname to its A and AAAA records via Cloudflare DNS-over-HTTPS.
 * Used by the SSRF guard to check whether a redirect destination resolves
 * to a private/loopback/link-local IP before following the hop. AAAA is
 * queried alongside A so a hostname whose v6 record points at ::1 / fc00::/7
 * is caught too (GHSA-vpmq-j44v-vjr6).
 *
 * Returns [] on any failure so the guard degrades gracefully (fail-open);
 * the Workers platform already blocks private destinations at the network
 * layer, so a transient DNS error here does not introduce new SSRF reach.
 */
export async function resolveHostIps(
	hostname: string,
	fetchImpl: typeof fetch,
): Promise<string[]> {
	const [a, aaaa] = await Promise.all([
		queryDoh(hostname, "A", fetchImpl),
		queryDoh(hostname, "AAAA", fetchImpl),
	]);
	return [...a, ...aaaa];
}

/** Answer record type numbers per RFC 1035 / RFC 3596. */
const DOH_RECORD_TYPE = { A: 1, AAAA: 28 } as const;

async function queryDoh(
	hostname: string,
	type: keyof typeof DOH_RECORD_TYPE,
	fetchImpl: typeof fetch,
): Promise<string[]> {
	try {
		const res = await fetchImpl(
			`https://${DOH_HOST}/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`,
			{
				headers: { accept: "application/dns-json" },
				signal: AbortSignal.timeout(SSRF_DOH_TIMEOUT_MS),
			},
		);
		if (!res.ok) return [];
		const body = await res.json() as { Answer?: Array<{ type?: number; data?: unknown }> };
		const answer = body.Answer;
		if (!Array.isArray(answer)) return [];
		const ips: string[] = [];
		for (const a of answer) {
			if (a.type !== DOH_RECORD_TYPE[type]) continue;
			if (typeof a.data !== "string") continue;
			// Reject anything not shaped like the expected IP literal
			// (paranoia: DoH data is inserted into log strings).
			if (type === "A") {
				if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(a.data)) continue;
			} else {
				if (!/^[0-9a-fA-F:.]{2,45}$/.test(a.data) || !a.data.includes(":")) continue;
			}
			ips.push(a.data);
		}
		return ips;
	} catch {
		return [];
	}
}

/**
 * SSRF guard: return a blocked-reason string if `url` must not be fetched,
 * or null if the destination is acceptable.
 *
 * Rejects:
 *  - Non-http/https schemes.
 *  - Bare IPv4/IPv6 literals in the hostname that map to loopback,
 *    link-local, RFC-1918, IPv6-ULA, or cloud-metadata ranges.
 *  - Hostnames whose DoH-resolved A or AAAA records land in those same
 *    ranges.
 */
async function checkSsrf(
	url: string,
	dnsLookup: (hostname: string) => Promise<string[]>,
): Promise<string | null> {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return "blocked:invalid-url";
	}

	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		return `blocked:scheme:${parsed.protocol}`;
	}

	const { hostname } = parsed;

	// Strip IPv6 brackets added by the URL serializer: "[::1]" → "::1".
	const ipStr = hostname.startsWith("[") && hostname.endsWith("]")
		? hostname.slice(1, -1)
		: hostname;

	// Check bare IP literals without a DNS round-trip.
	const isIpLiteral = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ipStr) || ipStr.includes(":");
	if (isIpLiteral) {
		return isPrivateOrLoopbackIp(ipStr) ? `blocked:private-ip:${hostname}` : null;
	}

	// Resolve hostname via DoH and check every returned A/AAAA record.
	const ips = await dnsLookup(hostname);
	for (const ip of ips) {
		if (isPrivateOrLoopbackIp(ip)) {
			return `blocked:private-ip:${ip}`;
		}
	}

	return null;
}

export async function resolveUrl(
	rawUrl: string,
	fetchImpl: typeof fetch = fetch,
): Promise<ResolvedUrl | null> {
	const startHost = safeHost(rawUrl);
	if (!startHost) return null;

	const dnsLookup = (h: string) => resolveHostIps(h, fetchImpl);

	const result: ResolvedUrl = {
		original: rawUrl,
		resolved: rawUrl,
		hops: 0,
		title: null,
		host_changed: false,
		final_status: 0,
		truncated: false,
	};

	// First, do a HEAD-follow chain with manual redirect handling so we can
	// count hops and surface the hostname change. We'd use `redirect: "follow"`
	// on fetch but that hides the intermediate Location headers we want to
	// count.
	let current = rawUrl;
	for (let i = 0; i <= MAX_REDIRECT_HOPS; i++) {
		if (i === MAX_REDIRECT_HOPS) {
			result.truncated = true;
			break;
		}

		// SSRF guard — enforce scheme ∈ {http, https} and reject private/
		// loopback/cloud-metadata destinations before each fetch.
		if (await checkSsrf(current, dnsLookup)) {
			result.final_status = 0;
			break;
		}

		let res: Response;
		try {
			res = await fetchImpl(current, {
				method: "GET",
				redirect: "manual",
				signal: AbortSignal.timeout(RESOLVE_TIMEOUT_MS),
				headers: {
					// Many phishing redirectors refuse to emit Location without a
					// recognisable browser UA. Use a generic one.
					"user-agent": "Mozilla/5.0 (compatible; AgenticInboxSecurity/1.0)",
				},
			});
		} catch {
			result.final_status = 0;
			result.resolved = current;
			break;
		}
		result.hops = i + 1;
		result.final_status = res.status;
		if (res.status >= 300 && res.status < 400) {
			const loc = res.headers.get("location");
			if (!loc) break;
			const next = absolutize(current, loc);
			if (!next) break;

			// SSRF guard — also enforce on the absolutized redirect target
			// before updating current, so an attacker-supplied Location header
			// pointing at an internal host is caught immediately.
			if (await checkSsrf(next, dnsLookup)) {
				result.resolved = current;
				break;
			}

			current = next;
			continue;
		}
		result.resolved = current;
		// Only bother extracting a title on HTML-ish responses.
		const ct = res.headers.get("content-type") || "";
		if (ct.toLowerCase().includes("html")) {
			try {
				const text = (await res.text()).slice(0, 200_000);
				result.title = extractTitle(text);
			} catch {
				// ignore body read failures — we have the URL already
			}
		}
		break;
	}

	const endHost = safeHost(result.resolved);
	result.host_changed = !!endHost && endHost !== startHost;
	return result;
}

function absolutize(base: string, loc: string): string | null {
	try {
		return new URL(loc, base).toString();
	} catch {
		return null;
	}
}

function safeHost(url: string): string | null {
	try {
		return new URL(url).hostname.toLowerCase();
	} catch {
		return null;
	}
}

const TITLE_RE = /<title\b[^>]*>([\s\S]*?)<\/title>/i;

export function extractTitle(html: string): string | null {
	const match = html.match(TITLE_RE);
	if (!match) return null;
	return match[1]
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, 200) || null;
}
