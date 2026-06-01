// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * IP → country + ASN enrichment for DMARC source IPs.
 *
 * Uses Team Cymru's DNS-based IP-to-ASN mapping service via Cloudflare
 * DNS-over-HTTPS. Two lookups per IPv4 address:
 *   1. `{reversed}.origin.asn.cymru.com TXT` → ASN number + country code
 *   2. `AS{N}.asn.cymru.com TXT` → org name (best-effort, skipped on failure)
 *
 * Both lookups are free, require no API key, and reuse the same DoH
 * infrastructure already established in this workers codebase.
 */

import { normalizeDohTxtData } from "./txt";

export interface IpGeoResult {
	asn: string | null;
	country: string | null;
}

const DOH_HOST = "cloudflare-dns.com";
const DOH_URL = `https://${DOH_HOST}/dns-query`;
const GEO_TIMEOUT_MS = 3000;

/** Matches a plain IPv4 dotted-quad. */
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * Look up country and ASN for a source IP using Team Cymru's DNS mapping.
 *
 * Returns `{ asn: null, country: null }` for:
 *   - IPv6 addresses (not in scope for DMARC enrichment)
 *   - Invalid / private / loopback IPs
 *   - Any DoH failure (timeout, non-200, empty answer)
 *
 * The caller is responsible for de-duplicating IPs and persisting results.
 */
export async function lookupIpGeo(
	ip: string,
	fetchImpl: typeof fetch = globalThis.fetch,
): Promise<IpGeoResult> {
	const empty: IpGeoResult = { asn: null, country: null };

	if (!IPV4_RE.test(ip)) return empty;

	const reversed = ip.split(".").reverse().join(".");

	const originTxt = await queryDohTxt(
		`${reversed}.origin.asn.cymru.com`,
		fetchImpl,
	);
	if (!originTxt) return empty;

	// Format: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
	const parts = originTxt.split("|").map((p) => p.trim());
	const asnNum = parts[0];
	const countryRaw = parts[2];
	const country = countryRaw && /^[A-Z]{2}$/.test(countryRaw) ? countryRaw : null;

	if (!asnNum || !/^\d+$/.test(asnNum)) return { asn: null, country };

	// Second lookup: get the org name for the AS number.
	const peerTxt = await queryDohTxt(`AS${asnNum}.asn.cymru.com`, fetchImpl);
	let asn: string;
	if (peerTxt) {
		// Format: "15169 | US | arin | 1992-12-01 | GOOGLE, US"
		const peerParts = peerTxt.split("|").map((p) => p.trim());
		const org = peerParts[4];
		asn = org ? `AS${asnNum} ${org}` : `AS${asnNum}`;
	} else {
		asn = `AS${asnNum}`;
	}

	return { asn, country };
}

async function queryDohTxt(
	name: string,
	fetchImpl: typeof fetch,
): Promise<string | null> {
	let res: Response;
	try {
		res = await fetchImpl(
			`${DOH_URL}?name=${encodeURIComponent(name)}&type=TXT`,
			{
				headers: { accept: "application/dns-json" },
				signal: AbortSignal.timeout(GEO_TIMEOUT_MS),
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
	const answer = (body as { Answer?: Array<{ type?: number; data?: unknown }> })
		.Answer;
	if (!Array.isArray(answer)) return null;
	for (const a of answer) {
		if (a.type !== 16) continue;
		if (typeof a.data !== "string") continue;
		return normalizeDohTxtData(a.data);
	}
	return null;
}
