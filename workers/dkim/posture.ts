// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * DKIM published-record posture lookup.
 *
 * Unlike the other posture surfaces (DMARC / MTA-STS / BIMI / SPF / TLS-RPT)
 * which read a single well-known label, DKIM posture is per-selector — a
 * domain may publish many selectors (`s1._domainkey.<domain>`,
 * `s2._domainkey.<domain>`, ...) and we have no a-priori list. The selectors
 * come from inbound `Authentication-Results.dkim header.s=` observations
 * persisted per-mailbox-DO; the caller passes the deduplicated 30d set in.
 *
 * For each selector we resolve `<selector>._domainkey.<domain>` over DoH and
 * answer one question: is a DKIM record still published at that label? A
 * record exists when the resolver returns at least one TXT entry and one
 * of those entries either starts with `v=DKIM1` or carries a non-empty `p=`
 * tag (RFC 6376 §3.6.1 lets `v=` be absent — `p=` is the only required tag).
 *
 * Per-key cache shape lets one bad selector not invalidate the whole domain:
 * a selector that resolves cleanly today stays cached for an hour even if a
 * sibling lookup times out the next time around.
 *
 * Mirrors the DoH + KV + 1500ms-cap pattern from `workers/dmarc/txt.ts` and
 * `workers/tlsrpt/posture.ts`. Issue: #170.
 */

/** Per-selector posture row.
 *
 * `published: null` is the "lookup unavailable" sentinel — DoH timed out,
 * returned non-200, or returned malformed JSON. The dashboard renders this
 * with the same affordance as `false` (per Constraints in #170) but the
 * cache layer keeps them separate so a transient blip doesn't poison the
 * cache for an hour.
 *
 * `source` is present on results from `mergeDkimPosture` (#358):
 *   - `"observed"` — selector lifted from inbound `Authentication-Results` headers.
 *   - `"probed"` — found by the active well-known-selector probe with `published=true`.
 *   - `"both"` — observed inbound AND confirmed by the active probe.
 */
export interface DkimSelectorPosture {
	selector: string;
	published: boolean | null;
	source?: "observed" | "probed" | "both";
}

/** Whole-domain DKIM posture surface — the list of observed selectors with
 * each one's published-record status. Empty `selectors` means "no selectors
 * observed in the 30d window"; the UI renders the appropriate empty state.
 */
export interface DkimPosture {
	selectors: ReadonlyArray<DkimSelectorPosture>;
}

/** Sentinel for "no observations yet" — same shape as a degenerate result. */
export function emptyDkimPosture(): DkimPosture {
	return { selectors: [] };
}

/**
 * Well-known DKIM selector names used by the active probe (#358). Keeping
 * this list in one place ensures callers share the same candidate set.
 *
 * The list covers the most widely deployed ESPs and mail platforms. Per-domain
 * custom selectors remain out of scope for now.
 */
export const DKIM_PROBE_SELECTORS: ReadonlyArray<string> = [
	"google",
	"selector1",
	"selector2",
	"k1",
	"k2",
	"default",
	"mandrill",
	"s1",
	"s2",
	"dkim",
	"mail",
	"smtp",
];

/**
 * Actively probe `DKIM_PROBE_SELECTORS` against `domain` and return only the
 * selectors confirmed as published (i.e. `published === true`). Each returned
 * row is tagged `source: "probed"`.
 *
 * Absent selectors (`published === false`) are silently dropped — surfacing
 * them would flood the card with 12 "missing" entries for a domain that
 * happens not to use any well-known name. Transient failures (`published ===
 * null`) are also dropped; the caller receives `emptyDkimPosture()` on any
 * uncaught error from the underlying resolver.
 */
export async function probeDkimSelectors(
	domain: string,
	options: {
		kv?: DkimPostureKv | null;
		fetchImpl?: DkimPostureFetch;
	} = {},
): Promise<DkimPosture> {
	let result: DkimPosture;
	try {
		result = await fetchDkimPosture(domain, DKIM_PROBE_SELECTORS, options);
	} catch {
		return emptyDkimPosture();
	}
	return {
		selectors: result.selectors
			.filter((s) => s.published === true)
			.map((s) => ({
				selector: s.selector,
				published: true,
				source: "probed" as const,
			})),
	};
}

/**
 * Merge an observed posture (from per-mailbox `getDkimSelectorsObserved`
 * fan-out + `fetchDkimPosture`) with a probed posture (from
 * `probeDkimSelectors`).
 *
 * Rules:
 *   - Observed-only selectors keep their `published` status and get
 *     `source: "observed"`.
 *   - Probed-only selectors (always `published: true`) get `source: "probed"`.
 *   - Selectors present in both get the observed `published` value (the
 *     inbound observation is authoritative for whether the record is still
 *     live) and `source: "both"`.
 *
 * Output is alphabetically sorted for stable UI rendering.
 */
export function mergeDkimPosture(
	observed: DkimPosture,
	probed: DkimPosture,
): DkimPosture {
	const out = new Map<string, DkimSelectorPosture>();

	for (const s of observed.selectors) {
		out.set(s.selector, {
			selector: s.selector,
			published: s.published,
			source: "observed",
		});
	}

	for (const s of probed.selectors) {
		const existing = out.get(s.selector);
		if (existing) {
			out.set(s.selector, {
				selector: s.selector,
				published: existing.published,
				source: "both",
			});
		} else {
			out.set(s.selector, {
				selector: s.selector,
				published: s.published,
				source: "probed",
			});
		}
	}

	const rows = [...out.values()];
	rows.sort((a, b) => a.selector.localeCompare(b.selector));
	return { selectors: rows };
}

/** Number of days an observed selector remains in the rollup before the
 * DO's read filter (and lazy-GC pass on writes) drops it. The 30-day window
 * is the issue's stated horizon (#170 Constraints). Exported so the DO and
 * tests share the same source of truth — keeping the cutoff math in one
 * place avoids the failure mode where one site reads the same data the
 * other just deleted. */
export const DKIM_OBSERVATION_WINDOW_DAYS = 30;

/**
 * Compute the inclusive ISO cutoff for the DKIM-selector observation window.
 * Rows whose `last_seen_iso >= cutoff` are still fresh; rows older than the
 * cutoff are eligible for GC and excluded from reads.
 *
 * Pure helper so the boundary semantics are unit-testable without standing
 * up a DO. The codebase has no DO test harness, so the cutoff math is the
 * one piece of the 30-day-window invariant we can exercise directly.
 */
export function dkimObservationCutoffIso(
	nowIso: string,
	windowDays: number = DKIM_OBSERVATION_WINDOW_DAYS,
): string {
	const nowMs = Date.parse(nowIso);
	if (!Number.isFinite(nowMs)) {
		// Defensive: a caller passing a malformed `nowIso` would otherwise
		// produce a NaN cutoff and the SQL filter would silently match
		// nothing. Fall back to "now − window" using the runtime clock so
		// the read still returns recent rows.
		const fallback = Date.now() - windowDays * 24 * 60 * 60 * 1000;
		return new Date(fallback).toISOString();
	}
	return new Date(nowMs - windowDays * 24 * 60 * 60 * 1000).toISOString();
}

const KV_PREFIX = "dkim-published:v1:";
/** 1h TTL: matches the DMARC / MTA-STS / BIMI / SPF / TLS-RPT cadence so
 * operators don't have to memorise a different per-surface refresh time. */
const KV_TTL_S = 60 * 60;
/** DoH resolver host. Hostname-based mock matching is required by repo CLAUDE.md. */
const DOH_HOST = "cloudflare-dns.com";
const DOH_URL = `https://${DOH_HOST}/dns-query`;
/** Hard cap matches `workers/dmarc/txt.ts` and the rest of the posture set. */
const DOH_TIMEOUT_MS = 1500;

/** Minimal `KVNamespace` view we depend on; lets tests pass a fake. */
export interface DkimPostureKv {
	get(key: string, type: "json"): Promise<unknown>;
	put(
		key: string,
		value: string,
		options?: { expirationTtl?: number },
	): Promise<void>;
}

/** Minimal `fetch` view we depend on; lets tests inject a stub. */
export type DkimPostureFetch = (
	input: string,
	init?: RequestInit,
) => Promise<Response>;

/**
 * Strip surrounding quotes and concatenate multi-string TXT-record fragments
 * DoH returns. Same logic as `workers/tlsrpt/posture.ts:normalizeDohTxtData`
 * — duplicated to keep the DKIM module decoupled.
 */
export function normalizeDohTxtData(data: string): string {
	if (typeof data !== "string") return "";
	const matches = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)];
	if (matches.length === 0) {
		return data.replace(/^"|"$/g, "");
	}
	return matches.map((m) => m[1]).join("");
}

/**
 * Decide whether a single TXT-record string represents a published DKIM
 * key. Two acceptance forms:
 *   - `v=DKIM1; ...` (canonical RFC 6376 form).
 *   - any record carrying a non-empty `p=<base64>` tag (RFC 6376 §3.6.1
 *     lets `v=` be absent for backwards-compat, and `p=` is the only
 *     mandatory tag).
 *
 * A record with `p=` empty (`p=`) is the "key-revoked" sentinel per RFC
 * 6376 §3.6.1 — the label still exists, but the record is publishing
 * "this selector is intentionally retired". For posture purposes we count
 * that as NOT published — the operator wants the selector treated as gone.
 */
export function isPublishedDkimRecord(record: string): boolean {
	if (typeof record !== "string") return false;
	const trimmed = record.trim();
	if (!trimmed) return false;
	const tags = new Map<string, string>();
	for (const part of trimmed.split(";")) {
		const eq = part.indexOf("=");
		if (eq < 0) continue;
		const name = part.slice(0, eq).trim().toLowerCase();
		const value = part.slice(eq + 1).trim();
		if (!name) continue;
		// First-wins to mirror the rest of the parser family.
		if (!tags.has(name)) tags.set(name, value);
	}
	const v = tags.get("v");
	const p = tags.get("p");
	if (v && /^DKIM1$/i.test(v)) {
		// Canonical record. `p=` empty is "revoked" — count as not published.
		if (p !== undefined) return p.length > 0;
		// `v=DKIM1` with no `p=` is malformed but published-shape; treat as
		// published rather than swallowing it (the operator did write a record).
		return true;
	}
	// No `v=DKIM1` — fall back to "non-empty `p=` tag exists".
	return typeof p === "string" && p.length > 0;
}

/**
 * Pick whether any TXT entry at `<selector>._domainkey.<domain>` is a
 * published DKIM record. A label may carry multiple TXT entries (vendor
 * verifications, an old DKIM record left next to a new one); any one of
 * them being a valid DKIM record means "published".
 */
export function isAnyPublished(records: readonly string[]): boolean {
	for (const r of records) {
		if (isPublishedDkimRecord(r)) return true;
	}
	return false;
}

/**
 * Fetch the DKIM posture for `domain` over DoH, one selector at a time.
 *
 * The resolver is sequential — selector counts per domain are bounded by
 * the 30d observation window (single-digit common case, low-double-digit
 * worst case for forwarder-heavy domains). Sequential keeps the Worker
 * from fan-firing 30+ concurrent DoH requests and tripping rate limits;
 * each resolution is hard-capped at 1.5s so even 10 misses cap the call
 * at 15s wall time before the surrounding handler's timeout takes over.
 *
 * Empty `selectors` short-circuits — we return `{ selectors: [] }` without
 * touching DoH. The UI renders that as "no DKIM selectors observed".
 *
 * Per-selector results are cached in KV. The transient `published: null`
 * sentinel is NEVER cached — same invariant as `tlsrpt/posture.ts`.
 */
export async function fetchDkimPosture(
	domain: string,
	selectors: readonly string[],
	options: {
		kv?: DkimPostureKv | null;
		fetchImpl?: DkimPostureFetch;
	} = {},
): Promise<DkimPosture> {
	if (!domain || typeof domain !== "string") return emptyDkimPosture();
	if (selectors.length === 0) return emptyDkimPosture();
	const fetchImpl = options.fetchImpl ?? (globalThis.fetch as DkimPostureFetch);
	const kv = options.kv ?? null;

	// Dedupe + lower-case at the entry — the DO already lower-cases on
	// observation, but this guards against callers that union from elsewhere.
	const uniq: string[] = [];
	const seen = new Set<string>();
	for (const sel of selectors) {
		if (typeof sel !== "string") continue;
		const key = sel.toLowerCase();
		if (!key || seen.has(key)) continue;
		seen.add(key);
		uniq.push(key);
	}

	const out: DkimSelectorPosture[] = [];
	for (const selector of uniq) {
		const cacheKey = `${KV_PREFIX}${domain}:${selector}`;

		let cached: boolean | null | undefined;
		if (kv) {
			try {
				const v = await kv.get(cacheKey, "json");
				if (v && typeof v === "object") {
					const pub = (v as { published?: unknown }).published;
					if (typeof pub === "boolean") cached = pub;
				}
			} catch {
				// KV read failure is non-fatal — fall through to a fresh DoH lookup.
			}
		}

		if (cached !== undefined) {
			out.push({ selector, published: cached });
			continue;
		}

		const published = await resolveOneSelector(domain, selector, fetchImpl);
		out.push({ selector, published });

		// Only cache durable answers — `published: null` is transient (DoH
		// timed out or returned non-200). Caching it would mean an hour of
		// "unavailable" after a single blip. Mirrors `tlsrpt/posture.ts`.
		if (kv && published !== null) {
			void kv
				.put(cacheKey, JSON.stringify({ published }), {
					expirationTtl: KV_TTL_S,
				})
				.catch(() => {});
		}
	}

	// Stable ordering keeps the UI tile layout deterministic across reloads.
	out.sort((a, b) => a.selector.localeCompare(b.selector));

	return { selectors: out };
}

async function resolveOneSelector(
	domain: string,
	selector: string,
	fetchImpl: DkimPostureFetch,
): Promise<boolean | null> {
	const name = `${selector}._domainkey.${domain}`;
	let res: Response;
	try {
		res = await fetchImpl(
			`${DOH_URL}?name=${encodeURIComponent(name)}&type=TXT`,
			{
				headers: { accept: "application/dns-json" },
				signal: AbortSignal.timeout(DOH_TIMEOUT_MS),
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
	// Cloudflare's resolver returns NXDOMAIN as `Status: 3` with no `Answer`
	// field — that's a durable "no record at this label", which for DKIM means
	// the selector is not published. Distinguishing it from "lookup unavailable"
	// matters for caching: a stable false stays cached, a transient null does
	// not.
	const status = (body as { Status?: unknown }).Status;
	if (Array.isArray(answer)) {
		const txts: string[] = [];
		for (const a of answer) {
			if (a.type !== 16) continue;
			if (typeof a.data !== "string") continue;
			txts.push(normalizeDohTxtData(a.data));
		}
		return isAnyPublished(txts);
	}
	// `Status: 3` is NXDOMAIN per RFC 8484 §4.2.1 / DoH JSON convention.
	// `Status: 0` with no Answer is NOERROR-no-data — also durable "no record".
	// Anything else (SERVFAIL=2, etc.) is treated as transient unavailability.
	if (status === 0 || status === 3) return false;
	return null;
}
