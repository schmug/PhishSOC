/**
 * Source-IP label resolution for DMARC Sending-sources enrichment.
 *
 * Resolves a PTR hostname via DoH and cross-references it with the static
 * provider map. Best-effort: failures return null (persisted as NULL in
 * dmarc_sources so the resolution is not retried on every page load — the
 * caller uses INSERT OR IGNORE to write exactly once per IP).
 */

import { matchProviderByPtr } from "../../shared/dmarc-provider-labels";

const DOH_HOST = "cloudflare-dns.com";
const DOH_URL = `https://${DOH_HOST}/dns-query`;
const PTR_TIMEOUT_MS = 2000;
const PTR_DNS_TYPE = 12;

/**
 * Convert an IPv4 address to its in-addr.arpa name for PTR lookup.
 * e.g. "203.0.113.1" → "1.113.0.203.in-addr.arpa"
 */
function ipToArpa(ip: string): string {
	return `${ip.split(".").reverse().join(".")}.in-addr.arpa`;
}

/**
 * Resolve a human-readable label for a DMARC source IP.
 *
 * Resolution order:
 * 1. PTR lookup via DoH
 * 2. If PTR matches a known provider suffix → return the provider name
 * 3. Otherwise return the raw PTR hostname
 * 4. On failure → null
 *
 * Exported for testing; inject a `mockFetch` to avoid real network calls.
 */
export async function resolveSourceLabel(
	ip: string,
	fetchFn: typeof fetch = fetch,
): Promise<string | null> {
	const name = ipToArpa(ip);
	let res: Response;
	try {
		res = await fetchFn(
			`${DOH_URL}?name=${encodeURIComponent(name)}&type=PTR`,
			{
				headers: { accept: "application/dns-json" },
				signal: AbortSignal.timeout(PTR_TIMEOUT_MS),
			},
		);
	} catch {
		return null;
	}
	if (!res.ok) return null;
	let body: unknown;
	try {
		body = await res.json();
	} catch {
		return null;
	}
	const answer = (body as { Answer?: Array<{ type?: number; data?: string }> }).Answer;
	if (!Array.isArray(answer)) return null;
	for (const rr of answer) {
		if (rr.type !== PTR_DNS_TYPE) continue;
		if (typeof rr.data !== "string") continue;
		const ptr = rr.data.replace(/\.$/, "");
		const provider = matchProviderByPtr(ptr);
		return provider ?? ptr;
	}
	return null;
}

export { DOH_HOST };
