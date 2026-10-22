// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * MTA-STS posture lookup (RFC 8461).
 *
 * Two-step resolution: a `_mta-sts.<domain>` TXT record carries a `v=STSv1`
 * marker plus a policy `id`, then `https://mta-sts.<domain>/.well-known/mta-sts.txt`
 * carries the actual policy (`mode`, `mx`, `max_age`).
 *
 * Cache key includes the policy id so a published-id change auto-invalidates
 * cached entries — operators who roll their MTA-STS policy don't have to wait
 * for a TTL race. Negative results (no TXT record / no policy file / parse
 * failure) are cached briefly under a separate key to avoid hammering DoH.
 *
 * Issue: #165 (carve-out from #156, item 2).
 */

/**
 * Parsed `{mode, mx, maxAge, id}` extracted from the MTA-STS pair (TXT record
 * + policy file). All fields nullable: an absent TXT record, a missing policy
 * file, a non-200 fetch, or a malformed policy all surface the same all-null
 * sentinel so the dashboard can render one "unavailable" affordance.
 */
export interface MtaStsPosture {
	mode: "enforce" | "testing" | "none" | null;
	mx: readonly string[] | null;
	maxAge: number | null;
	id: string | null;
}

/** Sentinel returned when posture is unavailable for any reason. */
export function emptyMtaStsPosture(): MtaStsPosture {
	return { mode: null, mx: null, maxAge: null, id: null };
}

const KV_PREFIX = "mta-sts:v1:";
/** Long TTL on positive cache entries — they're keyed by policy id, so a
 * fresh `id` produces a fresh cache key. 24h is well under the typical
 * `max_age` operators publish (1 week+). */
const KV_TTL_POSITIVE_S = 24 * 60 * 60;
/** Short TTL on negative entries — when an operator publishes for the first
 * time we want to discover it within minutes, not days. */
const KV_TTL_NEGATIVE_S = 5 * 60;
/** DoH resolver host. Hostname-based mock matching is required by repo CLAUDE.md. */
const DOH_HOST = "cloudflare-dns.com";
const DOH_URL = `https://${DOH_HOST}/dns-query`;
/** Hard cap per upstream call — same budget as `workers/dmarc/txt.ts` so a
 * slow MTA-STS server can't block the dashboard. Worst-case total is two
 * sequential calls (TXT + HTTPS); the route wraps this in `Promise.allSettled`
 * so even the worst case degrades to "unavailable" rather than a 5xx. */
const UPSTREAM_TIMEOUT_MS = 1500;
/** Cap policy-file size at 64 KiB. RFC 8461 §3.2 doesn't specify a limit but
 * real policies are well under 1 KiB; this defends against a misconfigured
 * server returning an HTML error page or an attacker pointing the policy URL
 * at a large payload. */
const POLICY_MAX_BYTES = 64 * 1024;

/** Minimal `KVNamespace` view we depend on; lets tests pass a fake. */
export interface MtaStsKv {
	get(key: string, type: "json"): Promise<unknown>;
	put(
		key: string,
		value: string,
		options?: { expirationTtl?: number },
	): Promise<void>;
}

/** Minimal `fetch` view we depend on; lets tests inject a stub. */
export type MtaStsFetch = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * Parse a `_mta-sts.<domain>` TXT-record string into `{id}`. Only records
 * starting with `v=STSv1` are considered. Tags are `;`-separated `name=value`
 * pairs per RFC 8461 §3.1. Returns `null` when the record isn't a valid
 * STS marker or when the `id` tag is missing.
 *
 * Tag names are case-insensitive; `id` values are not (the spec says they're
 * arbitrary 1-32 char tokens, A-Za-z0-9).
 */
export function parseMtaStsTxt(record: string): { id: string } | null {
	if (typeof record !== "string") return null;
	const trimmed = record.trim();
	if (!trimmed) return null;
	const tags = new Map<string, string>();
	for (const part of trimmed.split(";")) {
		const eq = part.indexOf("=");
		if (eq < 0) continue;
		const name = part.slice(0, eq).trim().toLowerCase();
		const value = part.slice(eq + 1).trim();
		if (!name) continue;
		// First-wins, mirroring the DMARC parser. A record with duplicate `id`
		// is malformed; first-wins gives a deterministic answer rather than
		// silently switching on tag-order in the upstream.
		if (!tags.has(name)) tags.set(name, value);
	}
	if (tags.get("v") !== "STSv1") return null;
	const id = tags.get("id");
	// Per RFC 8461 §3.1 the id is 1-32 chars, A-Za-z0-9. Be defensive and
	// reject empty / over-length / non-alphanumeric ids — a bogus id would
	// still cache-bust correctly but it's likely a misconfiguration we'd
	// rather surface as "unavailable" than as a phantom posture.
	if (!id || id.length === 0 || id.length > 32) return null;
	if (!/^[A-Za-z0-9]+$/.test(id)) return null;
	return { id };
}

/**
 * Pick the STSv1 policy record from a list of TXT strings published at
 * `_mta-sts.<domain>`. Multiple TXT entries at that label are common (e.g. an
 * old STS marker left next to a new one); RFC 8461 §3.1 says only the
 * `v=STSv1`-prefixed record is authoritative. Returns null when none match.
 */
export function selectMtaStsTxtRecord(records: readonly string[]): string | null {
	for (const r of records) {
		if (typeof r !== "string") continue;
		const t = r.trim();
		if (/^v\s*=\s*STSv1\b/i.test(t)) return t;
	}
	return null;
}

/**
 * Strip surrounding quotes and concatenate multi-string TXT-record fragments
 * DoH returns. Same logic as `workers/dmarc/txt.ts:normalizeDohTxtData` —
 * duplicated here rather than re-exported to keep `mta-sts/posture.ts`
 * decoupled from the DMARC module's API surface.
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
 * Parse the MTA-STS policy file body (RFC 8461 §3.2). Format is
 * `key: value` per line, separated by `\r\n` per spec but we tolerate `\n`
 * since real-world servers vary. `mx` may repeat. Required keys are
 * `version: STSv1`, `mode`, and `max_age`; missing required keys produce a
 * null result. Unknown keys are ignored.
 */
export function parseMtaStsPolicy(body: string): {
	mode: "enforce" | "testing" | "none";
	mx: string[];
	maxAge: number;
} | null {
	if (typeof body !== "string") return null;
	let version: string | null = null;
	let mode: string | null = null;
	let maxAgeRaw: string | null = null;
	const mx: string[] = [];
	for (const rawLine of body.split(/\r?\n/)) {
		const line = rawLine.trim();
		if (!line || line.startsWith("#")) continue;
		const colon = line.indexOf(":");
		if (colon < 0) continue;
		const key = line.slice(0, colon).trim().toLowerCase();
		const value = line.slice(colon + 1).trim();
		if (!key) continue;
		switch (key) {
			case "version":
				version ??= value;
				break;
			case "mode":
				mode ??= value.toLowerCase();
				break;
			case "max_age":
				maxAgeRaw ??= value;
				break;
			case "mx":
				if (value) mx.push(value.toLowerCase());
				break;
		}
	}
	if (version !== "STSv1") return null;
	if (mode !== "enforce" && mode !== "testing" && mode !== "none") return null;
	if (maxAgeRaw === null) return null;
	const maxAge = Number.parseInt(maxAgeRaw, 10);
	if (!Number.isFinite(maxAge) || maxAge < 0) return null;
	return { mode, mx, maxAge };
}

/**
 * Fetch and parse the MTA-STS posture for `<domain>`, with KV caching.
 *
 * Each upstream call (TXT + HTTPS) is hard-capped at `UPSTREAM_TIMEOUT_MS`
 * and any failure (timeout, non-200, malformed JSON, missing record, parse
 * failure) degrades to the all-null sentinel. Cache key includes the policy
 * `id` so a published-id change auto-invalidates without a TTL race.
 *
 * The HTTPS policy fetch uses `redirect: "manual"` per the global CLAUDE.md
 * rule — MTA-STS clients must not follow redirects when fetching the policy
 * file (RFC 8461 §3.3 implies the well-known URI is the authoritative source
 * and following a redirect could let an attacker substitute a permissive
 * policy from a domain they control).
 */
export async function fetchMtaStsPosture(
	domain: string,
	options: {
		kv?: MtaStsKv | null;
		fetchImpl?: MtaStsFetch;
	} = {},
): Promise<MtaStsPosture> {
	if (!domain || typeof domain !== "string") return emptyMtaStsPosture();
	const fetchImpl = options.fetchImpl ?? (globalThis.fetch as MtaStsFetch);
	const kv = options.kv ?? null;

	// Negative results (no TXT record) are cached under a distinct key so we
	// don't re-resolve on every dashboard hit. Consult it before DoH so a
	// hit actually saves the lookup. Short TTL — when the operator publishes
	// for the first time, surface it within minutes.
	const negKey = `${KV_PREFIX}${domain}:none`;
	if (kv) {
		try {
			const cached = await kv.get(negKey, "json");
			if (cached && typeof cached === "object") {
				return coerceMtaStsPosture(cached);
			}
		} catch {
			// KV read failure is non-fatal — fall through to a fresh lookup.
		}
	}

	const txtId = await resolveMtaStsTxtId(domain, fetchImpl);

	if (!txtId) {
		if (kv) {
			void kv
				.put(negKey, JSON.stringify(emptyMtaStsPosture()), {
					expirationTtl: KV_TTL_NEGATIVE_S,
				})
				.catch(() => {});
		}
		return emptyMtaStsPosture();
	}

	const cacheKey = `${KV_PREFIX}${domain}:${txtId}`;

	if (kv) {
		try {
			const cached = await kv.get(cacheKey, "json");
			if (cached && typeof cached === "object") {
				return coerceMtaStsPosture(cached);
			}
		} catch {
			// KV read failure is non-fatal; fall through to a fresh fetch.
		}
	}

	const policy = await fetchAndParseMtaStsPolicy(domain, fetchImpl);
	const posture: MtaStsPosture = policy
		? { mode: policy.mode, mx: policy.mx, maxAge: policy.maxAge, id: txtId }
		: { mode: null, mx: null, maxAge: null, id: txtId };

	if (kv) {
		// Write the resolved posture under the id-keyed cache. Long TTL is
		// safe because publishing a new policy bumps the id and lands on a
		// different cache key. A failed or unparseable policy fetch (timeout,
		// non-200, malformed) is a negative result and only cached briefly so
		// a transient outage doesn't pin "unavailable" for a day.
		void kv
			.put(cacheKey, JSON.stringify(posture), {
				expirationTtl: policy ? KV_TTL_POSITIVE_S : KV_TTL_NEGATIVE_S,
			})
			.catch(() => {});
	}

	return posture;
}

async function resolveMtaStsTxtId(
	domain: string,
	fetchImpl: MtaStsFetch,
): Promise<string | null> {
	const name = `_mta-sts.${domain}`;
	let res: Response;
	try {
		res = await fetchImpl(
			`${DOH_URL}?name=${encodeURIComponent(name)}&type=TXT`,
			{
				headers: { accept: "application/dns-json" },
				signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
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
	const txts: string[] = [];
	for (const a of answer) {
		// TXT records are type=16 in DoH JSON.
		if (a.type !== 16) continue;
		if (typeof a.data !== "string") continue;
		txts.push(normalizeDohTxtData(a.data));
	}
	const record = selectMtaStsTxtRecord(txts);
	if (!record) return null;
	const parsed = parseMtaStsTxt(record);
	return parsed?.id ?? null;
}

async function fetchAndParseMtaStsPolicy(
	domain: string,
	fetchImpl: MtaStsFetch,
): Promise<{
	mode: "enforce" | "testing" | "none";
	mx: string[];
	maxAge: number;
} | null> {
	const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
	let res: Response;
	try {
		res = await fetchImpl(url, {
			// MTA-STS clients must not follow redirects — RFC 8461 §3.3 makes
			// the well-known URI authoritative; a redirect would let an
			// attacker substitute a permissive policy from a domain they
			// control. (Global CLAUDE.md: MTA-STS fetches use redirect: manual.)
			redirect: "manual",
			signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
		});
	} catch {
		return null;
	}
	if (!res.ok) return null;
	let text: string;
	try {
		// Defend against oversized responses by reading bytes and truncating.
		const buf = await res.arrayBuffer();
		if (buf.byteLength > POLICY_MAX_BYTES) return null;
		text = new TextDecoder().decode(buf);
	} catch {
		return null;
	}
	return parseMtaStsPolicy(text);
}

function coerceMtaStsPosture(value: unknown): MtaStsPosture {
	if (!value || typeof value !== "object") return emptyMtaStsPosture();
	const v = value as {
		mode?: unknown;
		mx?: unknown;
		maxAge?: unknown;
		id?: unknown;
	};
	const validMode =
		v.mode === "enforce" || v.mode === "testing" || v.mode === "none"
			? v.mode
			: null;
	const mx = Array.isArray(v.mx)
		? v.mx.filter((s): s is string => typeof s === "string")
		: null;
	const maxAge = typeof v.maxAge === "number" ? v.maxAge : null;
	const id = typeof v.id === "string" ? v.id : null;
	return { mode: validMode, mx, maxAge, id };
}
