// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Reverse-DNS (PTR) lookup via DNS-over-HTTPS.
 *
 * Workers runtime has no `node:dns` — we query cloudflare-dns.com over HTTPS
 * with `type=PTR` against the `.in-addr.arpa` form of the address.
 * All failures return null; callers must treat the label as best-effort.
 */

export const PTR_DOH_HOST = "cloudflare-dns.com";
const PTR_TIMEOUT_MS = 2000;

/** Convert an IPv4 address to its reverse-ARPA form. Returns null for non-IPv4. */
export function ipToArpa(ip: string): string | null {
	const parts = ip.split(".");
	if (parts.length !== 4 || parts.some((p) => p === "" || Number.isNaN(Number(p)))) return null;
	return `${parts[3]}.${parts[2]}.${parts[1]}.${parts[0]}.in-addr.arpa`;
}

type FetchImpl = (url: string, init?: RequestInit) => Promise<Response>;

/**
 * Resolve the PTR record for `ip` via DoH.
 * Returns the hostname (trailing dot stripped) or null on any failure.
 *
 * Accepts an optional `fetchImpl` for test injection.
 */
export async function resolvePtr(
	ip: string,
	{ fetchImpl = fetch }: { fetchImpl?: FetchImpl } = {},
): Promise<string | null> {
	const arpa = ipToArpa(ip);
	if (!arpa) return null;

	let res: Response;
	try {
		res = await fetchImpl(
			`https://${PTR_DOH_HOST}/dns-query?name=${encodeURIComponent(arpa)}&type=PTR`,
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

	for (const a of answer) {
		// DNS type 12 = PTR
		if (a.type === 12 && typeof a.data === "string") {
			return a.data.replace(/\.$/, "");
		}
	}
	return null;
}
