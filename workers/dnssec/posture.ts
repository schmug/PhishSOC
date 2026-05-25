// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * DNSSEC posture lookup.
 *
 * Resolves whether a domain is DNSSEC-signed by trusting the upstream
 * resolver's AD (Authenticated Data) bit on a standard A-record query.
 * No local chain walking — posture only, per issue #324 constraints.
 *
 * Two DoH queries per cache miss:
 *   1. A-record at apex with cd=0 → read the AD bit.
 *   2. DS-record at apex → check whether a delegation-signer record
 *      exists at the parent zone (type=43).
 *
 * Mirrors the DoH + KV + 1500ms-cap pattern from `workers/dmarc/bimi.ts`
 * verbatim: same resolver host, same AbortSignal.timeout cap, same
 * fire-and-forget KV write, same empty-sentinel on any failure path.
 *
 * SECURITY_SPEC.md Rule 5: any failure (timeout, NXDOMAIN, SERVFAIL,
 * non-200) returns `emptyDnssecPosture()` and never throws.
 *
 * Issue: #324 (part of #156).
 */

/**
 * DNSSEC posture returned by `fetchDnssecPosture`.
 *
 * `{ signed: false }` — resolver did not set AD=true on the apex A query,
 * or any lookup failed. Covers unsigned domains, NXDOMAIN, timeout, etc.
 *
 * `{ signed: true, hasDsAtParent: boolean }` — resolver confirmed DNSSEC
 * validation (AD=true). `hasDsAtParent` is true when a DS record (type=43)
 * exists at the apex label in the parent zone, false when the DS query
 * returned no DS records (broken chain or DS query failure).
 */
export type DnssecPosture =
	| { signed: false }
	| { signed: true; hasDsAtParent: boolean };

/** Sentinel returned when DNSSEC is not configured or any failure occurred. */
export function emptyDnssecPosture(): DnssecPosture {
	return { signed: false };
}

const KV_PREFIX = "dmarc-dnssec:v1:";
/** 1h TTL — matches the apex-DMARC KV TTL and the BIMI/TLS-RPT pattern. */
const KV_TTL_S = 60 * 60;
/** DoH resolver host. Hostname-based mock matching is required by repo CLAUDE.md. */
const DOH_HOST = "cloudflare-dns.com";
const DOH_URL = `https://${DOH_HOST}/dns-query`;
/** Hard-cap the upstream — slow lookup must not block dashboard rendering.
 * Matches the 1500ms cap in `workers/dmarc/bimi.ts`. */
const DOH_TIMEOUT_MS = 1500;

/** Minimal `KVNamespace` view we depend on; lets tests pass a fake. */
export interface DnssecKv {
	get(key: string, type: "json"): Promise<unknown>;
	put(
		key: string,
		value: string,
		options?: { expirationTtl?: number },
	): Promise<void>;
}

/** Minimal `fetch` view we depend on; lets tests inject a stub. */
export type DnssecFetch = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * Fetch and parse the DNSSEC posture for `<domain>`, with KV caching.
 *
 * Two sequential DoH queries on cache miss: an A-record query to read the
 * resolver's AD bit, then a DS-record query to confirm the delegation signer.
 * Any failure at either step degrades gracefully — see type docs above.
 *
 * Per SECURITY_SPEC.md Rule 5, no error is ever thrown.
 */
export async function fetchDnssecPosture(
	domain: string,
	options: {
		kv?: DnssecKv | null;
		fetchImpl?: DnssecFetch;
	} = {},
): Promise<DnssecPosture> {
	if (!domain || typeof domain !== "string") return emptyDnssecPosture();
	const fetchImpl = options.fetchImpl ?? (globalThis.fetch as DnssecFetch);
	const kv = options.kv ?? null;
	const cacheKey = `${KV_PREFIX}${domain}`;

	if (kv) {
		try {
			const cached = (await kv.get(cacheKey, "json")) as DnssecPosture | null;
			if (cached && typeof cached === "object" && "signed" in cached) {
				if (cached.signed === false) return { signed: false };
				if (cached.signed === true) {
					const hasDsAtParent =
						typeof (cached as { signed: true; hasDsAtParent?: unknown })
							.hasDsAtParent === "boolean"
							? (cached as { signed: true; hasDsAtParent: boolean }).hasDsAtParent
							: false;
					return { signed: true, hasDsAtParent };
				}
			}
		} catch {
			// KV read failure is non-fatal; fall through to DoH.
		}
	}

	const posture = await resolveDnssecPosture(domain, fetchImpl);

	if (kv) {
		// Fire-and-forget — matches the bimi.ts pattern.
		void kv
			.put(cacheKey, JSON.stringify(posture), { expirationTtl: KV_TTL_S })
			.catch(() => {});
	}

	return posture;
}

async function resolveDnssecPosture(
	domain: string,
	fetchImpl: DnssecFetch,
): Promise<DnssecPosture> {
	// Step 1: A-record query at apex with cd=0 (DNSSEC checking enabled by
	// default; cd=0 is explicit for clarity). Read the AD bit from the response.
	let adRes: Response;
	try {
		adRes = await fetchImpl(
			`${DOH_URL}?name=${encodeURIComponent(domain)}&type=A&cd=0`,
			{
				headers: { accept: "application/dns-json" },
				signal: AbortSignal.timeout(DOH_TIMEOUT_MS),
			},
		);
	} catch {
		// Timeout or network error → not-signed sentinel (Rule 5).
		return emptyDnssecPosture();
	}
	if (!adRes.ok) return emptyDnssecPosture();

	let adBody: unknown;
	try {
		adBody = await adRes.json();
	} catch {
		return emptyDnssecPosture();
	}

	const adBit = (adBody as { AD?: boolean }).AD === true;
	if (!adBit) return { signed: false };

	// Step 2: DS-record query to check for a delegation signer at the parent.
	// Failure here degrades to hasDsAtParent=false — we know the domain is
	// signed but can't confirm the parent delegation.
	let dsRes: Response;
	try {
		dsRes = await fetchImpl(
			`${DOH_URL}?name=${encodeURIComponent(domain)}&type=DS`,
			{
				headers: { accept: "application/dns-json" },
				signal: AbortSignal.timeout(DOH_TIMEOUT_MS),
			},
		);
	} catch {
		return { signed: true, hasDsAtParent: false };
	}
	if (!dsRes.ok) return { signed: true, hasDsAtParent: false };

	let dsBody: unknown;
	try {
		dsBody = await dsRes.json();
	} catch {
		return { signed: true, hasDsAtParent: false };
	}

	const answer = (dsBody as { Answer?: Array<{ type?: number }> }).Answer;
	// DS records are type=43 in DoH JSON (RFC 4034 §5).
	const hasDsAtParent =
		Array.isArray(answer) && answer.some((a) => a.type === 43);

	return { signed: true, hasDsAtParent };
}
