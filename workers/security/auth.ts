// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * SPF/DKIM/DMARC verdict extraction from `Authentication-Results` headers.
 *
 * Cloudflare Email Routing preserves upstream auth headers and adds its own.
 * This parser handles the IANA-standard `Authentication-Results` format plus
 * the common Gmail and Microsoft variants.
 *
 * THREAT MODEL: An attacker who controls their own mail server can inject
 * an `Authentication-Results` header claiming pass results for their own
 * forged From address. Per RFC 8601 §5, receivers MUST validate the
 * authserv-id against a trusted list before acting on the reported
 * results. When `trusted_authserv_ids` is configured on the mailbox, only
 * headers whose authserv-id appears in that list contribute to the verdict;
 * all others are ignored.
 *
 * When no trusted list is configured we fall back to first-header-wins,
 * which matches the behaviour pre-hardening. That's still exploitable if
 * a forged header precedes the authentic one in the array, so operators
 * are strongly encouraged to set the trusted list.
 */

export type AuthResult =
	| "pass"
	| "fail"
	| "neutral"
	| "none"
	| "softfail"
	| "temperror"
	| "permerror";

export interface AuthVerdict {
	spf: AuthResult;
	dkim: AuthResult;
	dmarc: AuthResult;
	/** The `authserv-id` that produced the verdict, if captured. */
	authservId?: string;
	/**
	 * True when at least one header with a trusted authserv-id was found.
	 * When `trusted_authserv_ids` is configured and no header matched, this
	 * stays false and the verdict remains all-none — the aggregator treats
	 * that as a strong suspicion signal.
	 */
	trusted?: boolean;
	/**
	 * `(domain, selector)` pairs observed on `dkim=pass` / `dkim=fail` results
	 * with both `header.d=` and `header.s=` properties present. Subject to the
	 * same trusted-authserv-id gate as the rest of the verdict — observations
	 * from forged headers (untrusted authserv-id when gating is on) are never
	 * surfaced. `dkim=none/temperror/permerror` results are excluded because
	 * they don't carry a verified selector to roll up.
	 *
	 * Domain and selector are lower-cased at extraction so the per-mailbox-DO
	 * `(domain, selector)` PRIMARY KEY de-dupes case variants without extra
	 * normalisation in the storage path. Issue #170.
	 */
	dkimObservations: ReadonlyArray<{ domain: string; selector: string }>;
}

export function emptyVerdict(): AuthVerdict {
	return { spf: "none", dkim: "none", dmarc: "none", dkimObservations: [] };
}

/**
 * Extract `Authentication-Results` header value(s) from the raw-headers JSON
 * that PostalMime produces. Each header entry is `{ key, value }`; the key
 * casing varies across senders so we compare lowercased.
 */
function findAuthHeaders(rawHeaders: unknown): string[] {
	if (!Array.isArray(rawHeaders)) return [];
	const out: string[] = [];
	for (const h of rawHeaders) {
		if (!h || typeof h !== "object") continue;
		const rec = h as { key?: unknown; name?: unknown; value?: unknown };
		const key = rec.key ?? rec.name;
		const value = rec.value;
		if (typeof key !== "string" || typeof value !== "string") continue;
		if (key.toLowerCase() === "authentication-results") out.push(value);
	}
	return out;
}

const RESULT_RE = /(spf|dkim|dmarc)\s*=\s*(pass|fail|neutral|none|softfail|temperror|permerror)/gi;

/**
 * Match `header.d=<value>` or `header.s=<value>` with either a quoted or bare
 * value. Values run until the next whitespace or `;` (the method-segment
 * delimiter). Quoted values let through `header.s="some selector"` which
 * exists in the wild for selectors with unusual characters. Used to extract
 * DKIM selector observations for the per-mailbox `dkim_selectors_observed`
 * rollup (#170).
 */
const HEADER_PROP_RE = /header\.([ds])\s*=\s*(?:"([^"]*)"|([^\s;]+))/gi;
/** Match `dkim=pass` or `dkim=fail` with a word boundary so `dkim=none`,
 * `dkim=temperror`, etc. are excluded from selector observation. */
const DKIM_PASS_OR_FAIL_RE = /\bdkim\s*=\s*(pass|fail)\b/i;

function extractAuthservId(raw: string): string | undefined {
	const firstToken = raw.split(";")[0]?.trim();
	if (!firstToken || firstToken.includes("=")) return undefined;
	return firstToken.toLowerCase();
}

export interface ParseAuthOptions {
	/**
	 * Lowercased list of trusted authserv-id values. When non-empty, only
	 * `Authentication-Results` headers whose authserv-id is on this list
	 * contribute to the verdict. Empty/unset means "trust any".
	 */
	trustedAuthservIds?: readonly string[];
}

/** Suffix-aware authserv-id match. `google.com` matches `mx.google.com`. */
function matchesTrusted(authservId: string, trusted: readonly string[]): boolean {
	for (const t of trusted) {
		if (authservId === t) return true;
		if (authservId.endsWith("." + t)) return true;
	}
	return false;
}

export function parseAuthResults(rawHeaders: unknown, options: ParseAuthOptions = {}): AuthVerdict {
	const verdict: AuthVerdict = {
		spf: "none",
		dkim: "none",
		dmarc: "none",
		dkimObservations: [],
	};
	// Local mutable observations buffer; we freeze into the readonly field at
	// the end. Dedupe by `domain|selector` so a header carrying multiple
	// signatures from the same selector (gmail re-sign chains do this)
	// contributes once.
	const observations: Array<{ domain: string; selector: string }> = [];
	const seen = new Set<string>();
	const headerValues = findAuthHeaders(rawHeaders);
	if (headerValues.length === 0) return verdict;

	const trusted = options.trustedAuthservIds ?? [];
	const gating = trusted.length > 0;

	// Track which methods are already set so a legitimate `dkim=none` result
	// doesn't leave the state indistinguishable from "not set" — which would
	// otherwise let a subsequent (possibly forged) header overwrite it.
	const set = { spf: false, dkim: false, dmarc: false };

	for (const raw of headerValues) {
		const authservId = extractAuthservId(raw);
		if (gating) {
			if (!authservId) continue;
			if (!matchesTrusted(authservId, trusted)) continue;
		}
		if (!verdict.authservId && authservId) verdict.authservId = authservId;
		// Only mark the verdict trusted when an operator-configured authserv-id
		// actually matched (gating === true). With no allowlist configured we
		// still parse results so scoring keeps working, but `trusted` stays
		// false — so a forged Authentication-Results header on a default
		// deployment cannot satisfy the hard-allow short-circuit downstream.
		if (gating && !verdict.trusted) verdict.trusted = true;

		for (const match of raw.matchAll(RESULT_RE)) {
			const method = match[1].toLowerCase() as "spf" | "dkim" | "dmarc";
			const result = match[2].toLowerCase() as AuthResult;
			if (!set[method]) {
				verdict[method] = result;
				set[method] = true;
			}
		}

		// DKIM selector observations. Each `;`-separated method segment with a
		// `dkim=pass` or `dkim=fail` result contributes one `(domain, selector)`
		// pair when both `header.d=` and `header.s=` are present. The split on
		// `;` matters: a single header like `auth; spf=pass header.d=other;
		// dkim=pass header.s=sel1` would otherwise associate `header.d=other`
		// (an SPF property) with the DKIM selector and emit a wrong domain.
		for (const segment of raw.split(";")) {
			if (!DKIM_PASS_OR_FAIL_RE.test(segment)) continue;
			let domain = "";
			let selector = "";
			for (const m of segment.matchAll(HEADER_PROP_RE)) {
				const name = m[1].toLowerCase();
				const value = m[2] ?? m[3] ?? "";
				if (!value) continue;
				if (name === "d" && !domain) domain = value.toLowerCase();
				else if (name === "s" && !selector) selector = value.toLowerCase();
			}
			if (!domain || !selector) continue;
			const key = `${domain}|${selector}`;
			if (seen.has(key)) continue;
			seen.add(key);
			observations.push({ domain, selector });
		}
	}
	verdict.dkimObservations = observations;
	return verdict;
}

/**
 * Auth-signal score contribution (positive = suspicious).
 *
 * Confidence (issue #105, v1):
 *   - 0.9 — at least one trusted authserv-id matched the verdict (the
 *     pipeline gating made spoofing the result expensive).
 *   - 0.5 — auth headers were present but no `trusted_authserv_ids` was
 *     configured, so we fell back to first-header-wins (still useful as a
 *     signal, but exploitable by an attacker who can inject their own
 *     `Authentication-Results` header before the authentic one).
 *   - 0.2 — no `Authentication-Results` headers found at all (verdict is
 *     all-`none`); whatever we contributed has very little to back it up.
 *
 * `contributions` (issue #100): structured per-rule breakdown for the
 * mitigations layer. Each entry carries the raw weight before the 30-cap so
 * mitigations can zero out individual rule contributions without needing to
 * know about the cap. The cap case (dmarc_fail + spf_fail + dkim_fail → raw
 * 40, capped 30) never triggers `dmarc_pass_compensates_method_fail` because
 * that mitigation only fires when dmarc=pass — so the delta computed from
 * uncapped contributions is always correct in practice.
 */
export function scoreAuth(verdict: AuthVerdict): {
	score: number;
	reasons: string[];
	confidence: number;
	contributions: Array<{ scorer: "auth"; rule: string; weight: number; reason: string }>;
} {
	const reasons: string[] = [];
	const contributions: Array<{ scorer: "auth"; rule: string; weight: number; reason: string }> = [];
	let score = 0;
	if (verdict.dmarc === "fail") {
		score += 20;
		reasons.push("DMARC failed");
		contributions.push({ scorer: "auth", rule: "dmarc_fail", weight: 20, reason: "DMARC failed" });
	}
	if (verdict.spf === "fail" || verdict.spf === "softfail") {
		score += 10;
		reasons.push("SPF failed");
		contributions.push({ scorer: "auth", rule: "spf_fail", weight: 10, reason: "SPF failed" });
	}
	if (verdict.dkim === "fail") {
		score += 10;
		reasons.push("DKIM failed");
		contributions.push({ scorer: "auth", rule: "dkim_fail", weight: 10, reason: "DKIM failed" });
	}
	if (score > 30) score = 30;
	if (verdict.dmarc === "pass") {
		score -= 10;
		contributions.push({ scorer: "auth", rule: "dmarc_pass", weight: -10, reason: "DMARC passed" });
	}
	const allNone =
		verdict.spf === "none" && verdict.dkim === "none" && verdict.dmarc === "none";
	const confidence = verdict.trusted ? 0.9 : allNone ? 0.2 : 0.5;
	return { score, reasons, confidence, contributions };
}

/**
 * Pull all `Received:` header values out of the PostalMime raw-headers array.
 * Header order is preserved — most-recent hop first, originating hop last.
 */
function findReceivedHeaders(rawHeaders: unknown): string[] {
	if (!Array.isArray(rawHeaders)) return [];
	const out: string[] = [];
	for (const h of rawHeaders) {
		if (!h || typeof h !== "object") continue;
		const rec = h as { key?: unknown; name?: unknown; value?: unknown };
		const key = rec.key ?? rec.name;
		const value = rec.value;
		if (typeof key !== "string" || typeof value !== "string") continue;
		if (key.toLowerCase() === "received") out.push(value);
	}
	return out;
}

// `Received: from <host> ([<ip>])` is the canonical RFC 5321 form, but the
// shape varies wildly across senders — the IP may be inside `[brackets]`,
// `(parens)`, or bare; the hostname may be missing/quoted/duplicated. Rather
// than try to parse every variant precisely, we walk all IP-shaped tokens in
// the header value and let the public/private filter pick the right one.
//
// The regex is run with `matchAll` against each header value; the helper
// returns the first match whose IP isn't private/loopback. IPv4 is matched
// first (cheaper and far more common); IPv6 (any token containing two
// or more colons) is matched separately.
const RECEIVED_IPV4_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
const RECEIVED_IPV6_RE = /(?:IPv6:)?([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})/gi;

/**
 * Return true for IPs we should skip when walking `Received:` headers in
 * search of the originating external hop:
 *
 *   - RFC1918 private space (10/8, 172.16/12, 192.168/16)
 *   - Loopback (127/8, ::1)
 *   - Link-local (169.254/16, fe80::/10)
 *   - Unique-local IPv6 (fc00::/7)
 *   - Cloudflare Email Routing's own internal hops (no public range to
 *     enumerate, so we lean on the private-range check above plus the
 *     fact that Email Routing's outermost `Received:` line records the
 *     real client IP).
 */
export function isPrivateOrLoopbackIp(ip: string): boolean {
	const lower = ip.toLowerCase().replace(/^ipv6:/, "");
	// IPv4
	if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(lower)) {
		return isPrivateOrLoopbackIpv4(lower);
	}
	// IPv6
	if (lower === "::1") return true;
	if (lower === "::") return true; // unspecified address
	if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) return true;
	if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
	// IPv4-mapped (::ffff:0:0/96) and NAT64 well-known prefix (64:ff9b::/96)
	// embed an IPv4 address in the low 32 bits. WHATWG URL serializes
	// http://[::ffff:127.0.0.1]/ to the hex form ::ffff:7f00:1, so both the
	// dotted-quad and hex spellings must unwrap to the embedded IPv4 and
	// re-run the IPv4 private/loopback checks (GHSA-vpmq-j44v-vjr6).
	if (lower.includes(":")) {
		const groups = expandIpv6(lower);
		if (groups) {
			if (groups.every((g) => g === 0)) return true; // expanded unspecified (::)
			if (groups[7] === 1 && groups.slice(0, 7).every((g) => g === 0)) return true; // expanded ::1
			const isV4Mapped =
				groups[0] === 0 && groups[1] === 0 && groups[2] === 0 &&
				groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff;
			const isNat64 =
				groups[0] === 0x64 && groups[1] === 0xff9b &&
				groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0;
			if (isV4Mapped || isNat64) {
				const embedded = `${groups[6] >> 8}.${groups[6] & 0xff}.${groups[7] >> 8}.${groups[7] & 0xff}`;
				return isPrivateOrLoopbackIpv4(embedded);
			}
		}
	}
	// Treat anything that's not a recognisable IP as "skip" rather than "use".
	if (!/[0-9]/.test(lower)) return true;
	return false;
}

/** IPv4 private/loopback/link-local/unspecified check on a dotted-quad string. */
function isPrivateOrLoopbackIpv4(ip: string): boolean {
	const parts = ip.split(".").map((p) => parseInt(p, 10));
	if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
	const [a, b] = parts;
	if (a === 10) return true;
	if (a === 127) return true;
	if (a === 172 && b >= 16 && b <= 31) return true;
	if (a === 192 && b === 168) return true;
	if (a === 169 && b === 254) return true;
	if (a === 0) return true;
	return false;
}

/**
 * Expand an IPv6 textual address into its 8 hextet values (0–0xffff).
 * Handles `::` zero-compression and a trailing embedded dotted-quad
 * (`::ffff:127.0.0.1`). Returns null when the string is not a parseable
 * IPv6 address — callers treat null as "not an IPv6 literal".
 */
function expandIpv6(ip: string): number[] | null {
	let s = ip;
	// Convert a trailing embedded dotted-quad into its two hextets so the
	// rest of the parse only deals with hex groups.
	if (s.includes(".")) {
		const lastColon = s.lastIndexOf(":");
		if (lastColon === -1) return null;
		const quad = s.slice(lastColon + 1).split(".");
		if (quad.length !== 4) return null;
		const bytes = quad.map((p) => (/^\d{1,3}$/.test(p) ? parseInt(p, 10) : NaN));
		if (bytes.some((n) => Number.isNaN(n) || n > 255)) return null;
		const hi = ((bytes[0] << 8) | bytes[1]).toString(16);
		const lo = ((bytes[2] << 8) | bytes[3]).toString(16);
		s = `${s.slice(0, lastColon + 1)}${hi}:${lo}`;
	}
	const halves = s.split("::");
	if (halves.length > 2) return null;
	const parseGroups = (part: string): number[] | null => {
		if (part === "") return [];
		const out: number[] = [];
		for (const g of part.split(":")) {
			if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
			out.push(parseInt(g, 16));
		}
		return out;
	};
	const head = parseGroups(halves[0]);
	if (head === null) return null;
	if (halves.length === 1) {
		return head.length === 8 ? head : null;
	}
	const tail = parseGroups(halves[1]);
	if (tail === null) return null;
	const fill = 8 - head.length - tail.length;
	if (fill < 1) return null; // `::` must stand for at least one zero group
	return [...head, ...new Array<number>(fill).fill(0), ...tail];
}

/**
 * Extract the originating external IP from `Received:` headers.
 *
 * PostalMime preserves header order; `Received:` lines run most-recent hop
 * first → originating hop last. We walk in array order and return the first
 * `from <host> [ip]` whose IP is public — that's the outermost externally-
 * controlled hop. Returns `undefined` when no usable IP is found (malformed
 * trace, internal-only chain, or no `Received:` headers at all).
 *
 * Threat-model note: `Received:` headers from outside our infra are
 * untrusted and forge-able. The CTI lookup that consumes this IP is treated
 * as a *signal*, not as ground truth — a forged "from 8.8.8.8" doesn't get
 * us a free pass, it just shifts the prior up or down within a bounded
 * range. The aggressive private-range filter below is the main defence: an
 * attacker can't mask as a private hop to suppress the lookup.
 */
export function extractReceivedFromIp(rawHeaders: unknown): string | undefined {
	const headers = findReceivedHeaders(rawHeaders);
	for (const raw of headers) {
		// Try IPv4 first — cheap, and the overwhelming common case for a
		// `Received: from` clause.
		for (const m of raw.matchAll(RECEIVED_IPV4_RE)) {
			const ip = m[1];
			if (!isPrivateOrLoopbackIp(ip)) return ip;
		}
		for (const m of raw.matchAll(RECEIVED_IPV6_RE)) {
			const ip = m[1];
			if (!ip) continue;
			if (!isPrivateOrLoopbackIp(ip)) return ip;
		}
	}
	return undefined;
}
