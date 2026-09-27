// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * The sender identity that trust decisions (hard-allow allowlists and trusted
 * history, the honeypot owned-domain guard) may act on.
 *
 * `sender` is PostalMime's `from.address`, which is not always a plain
 * addr-spec. Allowlists vouch only for the domain the authserv evaluated
 * DMARC on, so the identity is accepted only when:
 *   - the address is a single plain `local@domain` (exactly one `@`, no
 *     quoting, angle brackets, comments, routes or group syntax), and
 *   - when the authserv reported `header.from`, the address's domain is
 *     exactly that domain.
 * Callers keep their own `dmarc === "pass"` / `auth.trusted` gates.
 */

import type { AuthVerdict } from "./auth";

const SINGLE_ADDR_SPEC_RE = /^[^\s@"<>()[\]\\,:;]+@[^\s@"<>()[\]\\,:;]+$/;

export interface SenderIdentity {
	address: string;
	domain: string;
}

/** Drop a single trailing root dot so `example.com.` == `example.com`. */
function normalizeDomain(d: string): string {
	return d.endsWith(".") ? d.slice(0, -1) : d;
}

/**
 * The DMARC-authenticated sender identity, or null when the address is not a
 * single plain addr-spec whose domain the authserv actually evaluated. This
 * does NOT require `header.from` — a caller that fails closed (hard-allow)
 * must additionally reject an absent `header.from`; a caller that fails toward
 * suppression (honeypot owned-domain guard) can act on the shape-checked
 * identity alone, since the spoof `"x@owned"@attacker` still fails the shape
 * check and is not treated as owned.
 */
export function authenticatedSender(
	sender: string,
	auth: Pick<AuthVerdict, "headerFrom">,
): SenderIdentity | null {
	const address = sender.trim().toLowerCase();
	if (!SINGLE_ADDR_SPEC_RE.test(address)) return null;
	const domain = normalizeDomain(address.slice(address.indexOf("@") + 1));
	// Reject empty labels and leading/trailing dots (".example.com", "a..b").
	if (!domain || domain.startsWith(".") || domain.includes("..")) return null;
	if (auth.headerFrom && normalizeDomain(auth.headerFrom.toLowerCase()) !== domain) return null;
	return { address, domain };
}
