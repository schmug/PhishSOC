// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Canonical forms for hosts and link URLs. Shared by link extraction
 * (`workers/security/urls.ts`), intel-feed ingest and lookup
 * (`workers/intel/feeds.ts`), deep-scan and the hub report builders.
 *
 * Invariant: both sides of any host or URL comparison go through the same
 * function here. A value canonicalized on one side only compares unequal to
 * the same resource written differently on the other side.
 */

const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

/**
 * Canonical hostname: lowercase, WHATWG IDNA (punycode) form, exactly one
 * trailing dot removed. Returns null for an empty host, a host with an empty
 * label (`a..example`, `.a.example`, `a.example..`) or one WHATWG rejects.
 * Never throws.
 */
export function normalizeHost(host: string): string | null {
	let h = host.trim().toLowerCase();
	if (h.endsWith(".")) h = h.slice(0, -1);
	if (!h || h.split(".").some((label) => label === "")) return null;
	try {
		h = new URL(`http://${h}/`).hostname;
	} catch {
		return null;
	}
	return h || null;
}

/**
 * Lossless canonical form of an http(s) URL, used for url-kind feed entries
 * at ingest and for links at lookup. `new URL` lowercases the scheme and
 * host, drops a default port and resolves dot segments; on top of that this
 * applies `normalizeHost`, removes an empty `?` and an empty `#`, decodes
 * percent-escapes of unreserved path characters and uppercases the hex of the
 * remaining path escapes (RFC 3986 §6.2.2). The query and a non-empty
 * fragment are kept unchanged: dropping either is lossy (see the derived tier
 * in `feeds.ts`). Returns null for a non-http(s) or unparseable URL, or a
 * host `normalizeHost` rejects.
 */
export function canonicalFeedUrl(raw: string): string | null {
	let u: URL;
	try {
		u = new URL(raw.trim());
	} catch {
		return null;
	}
	if (u.protocol !== "http:" && u.protocol !== "https:") return null;
	const host = normalizeHost(u.hostname);
	if (!host) return null;
	u.hostname = host;
	if (u.search === "") u.search = "";
	if (u.hash === "") u.hash = "";
	u.pathname = u.pathname.replace(/%([0-9A-Fa-f]{2})/g, (_escape, hex: string) => {
		const ch = String.fromCharCode(parseInt(hex, 16));
		return UNRESERVED.test(ch) ? ch : `%${hex.toUpperCase()}`;
	});
	return u.href;
}
