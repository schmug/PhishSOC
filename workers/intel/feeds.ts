// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Threat-intel feed refresh and lookup.
 *
 * Refresh flow (runs on cron, see workers/app.ts scheduled handler):
 *   1. Read mailbox list from R2.
 *   2. For each mailbox with `intel.feeds`, fetch each feed (If-None-Match).
 *   3. Parse entries (domain or URL, ignore `#` comments).
 *   4. Build a bloom filter and store under KV key `intel:{feedId}:bloom`.
 *   5. Write a single `intel:{feedId}:exact-blob` JSON array (deduplicated,
 *      capped at EXACT_KEY_CAP entries) so we can confirm a bloom hit
 *      without false positives (one blob per feed, not one key per entry).
 *   6. Update `intel_feed_state` row on the mailbox DO.
 *
 * Lookup flow:
 *   - `checkUrlAgainstFeeds(env, mailboxId, url)` — called by the security
 *     pipeline. Returns `{ matched: true, feed: string }` on confirmed hit,
 *     `null` otherwise.
 */

import type { Env } from "../types";
import { DEFAULT_FEEDS, type FeedDefinition } from "./defaults";
import {
	addToBloom,
	checkBloom,
	createBloom,
	deserializeBloom,
	serializeBloom,
} from "./bloom";
import { findCidrMatch, parseCidr, parseIpv4, type Ipv4Cidr } from "./cidr";
import { getMailboxStub, listMailboxes } from "../lib/email-helpers";
import { hostAllowed } from "../lib/host-allowlist";
import { resolveMailboxSettings } from "../lib/mailbox-settings";

const EXACT_KEY_CAP = 2000; // per-feed cap — exact blob stores at most this many entries

function bloomKey(feedId: string) { return `intel:${feedId}:bloom`; }
/** Single blob key holding a JSON array of up to EXACT_KEY_CAP exact-match values. */
function exactBlobKey(feedId: string) { return `intel:${feedId}:exact-blob`; }
/**
 * Storage key for `ip-cidr` feeds. Bloom filters don't fit CIDR membership
 * (an IP is checked against a *range*, not an exact string) so we materialise
 * the whole list as a JSON blob and linear-scan on lookup. DROP-class feeds
 * are a few thousand CIDRs — well under any KV size limit.
 */
function cidrKey(feedId: string) { return `intel:${feedId}:cidrs`; }

export interface MailboxIntelSettings {
	feeds?: Array<{
		id: string;
		url?: string;
		kind?: "domain" | "url";
		refresh_hours?: number;
		headers?: Record<string, string>;
		/** If set, reads header value from a Worker secret of this name at refresh time. */
		auth_secret?: string;
	}>;
	hub?: {
		url: string;
		org_uuid: string;
		api_key_secret_name: string;
		auto_report: boolean;
		default_sharing_group_uuid?: string;
	};
}

/**
 * Load the resolved per-mailbox intel block (post-#106). The resolver
 * returns whichever tier supplied an `intel` value — mailbox if set, else
 * org, else empty — and `intel.feeds` / `intel.hub` are whole-replaced
 * (never deep-merged across tiers). Defaults from `DEFAULT_FEEDS` are
 * stitched in by `resolveFeeds` below.
 */
async function loadMailboxIntelSettings(env: Env, mailboxId: string): Promise<MailboxIntelSettings> {
	try {
		const resolved = await resolveMailboxSettings(env, mailboxId);
		return resolved.intel as MailboxIntelSettings;
	} catch {
		return {};
	}
}

/**
 * Hostnames of the built-in default feeds. Always part of the
 * credential-destination allowlist below: a secret-bearing override of an
 * operator-trusted default feed keeps working with no extra config.
 */
const DEFAULT_FEED_HOSTS: string[] = DEFAULT_FEEDS.map((f) => safeHostname(f.url)).filter(
	(h): h is string => h !== null,
);

function resolveFeeds(env: Env, settings: MailboxIntelSettings): FeedDefinition[] {
	const defaults = settings.feeds && settings.feeds.length > 0 ? [] : DEFAULT_FEEDS;
	const byId = new Map<string, FeedDefinition>(DEFAULT_FEEDS.map((f) => [f.id, f]));
	const user: FeedDefinition[] = [];
	for (const f of settings.feeds ?? []) {
		const base = byId.get(f.id);
		const url = f.url ?? base?.url ?? "";
		const headers: Record<string, string> = { ...(f.headers ?? {}) };
		// Prevent confused deputy / secret exfiltration via unconstrained secret access.
		// Two conditions, both required (GHSA-jfj6-w954-96vg f27):
		//   1. Only explicitly designated feed secrets (`FEED_SECRET_` prefix)
		//      may be referenced from settings.
		//   2. The destination host must be pinned: the feed URL is
		//      teammate-editable, so the secret is only attached when the URL
		//      is https AND its hostname is on the operator-set
		//      `FEED_ALLOWED_HOSTS` env allowlist (or is a built-in
		//      DEFAULT_FEEDS host). Off-allowlist feeds still fetch — public
		//      no-secret feeds are never blocked — they just never carry the
		//      credential.
		if (
			f.auth_secret &&
			f.auth_secret.startsWith("FEED_SECRET_") &&
			hostAllowed(url, env.FEED_ALLOWED_HOSTS, DEFAULT_FEED_HOSTS)
		) {
			const secretValue = (env as unknown as Record<string, string>)[f.auth_secret];
			if (secretValue) headers["Authorization"] = secretValue;
		}
		user.push({
			id: f.id,
			url,
			kind: f.kind ?? base?.kind ?? "url",
			refreshHours: f.refresh_hours ?? base?.refreshHours ?? 6,
			description: base?.description ?? "User-configured feed",
			headers: Object.keys(headers).length > 0 ? headers : undefined,
		});
	}
	// NOTE: We deliberately do NOT filter out feeds with an empty `url` here.
	// Default-feed entries may ship with `url: ""` as placeholders for
	// operator-configured endpoints (e.g. `crowdsec-community`, whose
	// download URL is account-specific and not public). Such feeds:
	//   - skip refresh in `refreshAllFeeds` via the explicit URL guard;
	//   - still participate in lookup via `checkIpAgainstFeeds` /
	//     `checkUrlAgainstFeeds` once their data has been materialised in
	//     KV (either by an operator-configured override URL or out-of-band).
	// Filtering them here would silently drop already-refreshed lookup data.
	return [...defaults, ...user];
}

export function parseFeedBody(body: string, kind: "domain" | "url"): string[] {
	const lines = body.split(/\r?\n/);
	const out: string[] = [];
	for (const raw of lines) {
		const line = raw.trim();
		if (!line || line.startsWith("#")) continue;
		if (kind === "domain") {
			out.push(normalizeDomain(line));
		} else {
			// `url` feeds (URLhaus, OpenPhish) list specific malicious URLs.
			// Do NOT also derive the bare host: that would collapse e.g.
			// `https://github.com/evil/x` to `github.com` and later flag every
			// legitimate github.com link as a confirmed hit → hard_block. Match
			// the full URL only; host-level blocking is the job of `domain` feeds.
			out.push(line);
		}
	}
	return out;
}

/**
 * Parse a CIDR-per-line body (e.g. Spamhaus DROP/EDROP).
 *
 * Format expected:
 *   - One CIDR (or bare IP) per line.
 *   - Comment lines start with `;` (Spamhaus convention) or `#`.
 *   - Each entry can have a trailing reference suffix separated by `;`,
 *     e.g. `1.10.16.0/20 ; SBL233763` — strip everything from `;` onwards
 *     and parse the leading token.
 *   - Blank lines are skipped.
 *
 * A malformed entry is logged and skipped — a single bad line shouldn't
 * poison the whole feed refresh.
 */
export function parseCidrFeedBody(
	body: string,
	feedId: string,
): Ipv4Cidr[] {
	const lines = body.split(/\r?\n/);
	const out: Ipv4Cidr[] = [];
	for (const raw of lines) {
		const trimmed = raw.trim();
		if (!trimmed) continue;
		// Spamhaus uses `;` for comments; tolerate `#` too for foreign feeds.
		if (trimmed.startsWith(";") || trimmed.startsWith("#")) continue;
		// Strip trailing reference suffix. Each entry typically looks like
		// `1.10.16.0/20 ; SBL233763`; `;` and anything after is metadata.
		const semi = trimmed.indexOf(";");
		const head = (semi === -1 ? trimmed : trimmed.slice(0, semi)).trim();
		if (!head) continue;
		const cidr = parseCidr(head);
		if (!cidr) {
			console.warn(`feed ${feedId}: skipping malformed CIDR entry ${JSON.stringify(head)}`);
			continue;
		}
		out.push(cidr);
	}
	return out;
}

function normalizeDomain(s: string): string {
	return s.toLowerCase().replace(/^https?:\/\//, "").split(/[\/?#]/)[0];
}

function safeHostname(url: string): string | null {
	try { return new URL(url).hostname.toLowerCase(); } catch { return null; }
}

/** Refresh all feeds across all mailboxes. Called from the cron handler. */
export async function refreshAllFeeds(env: Env): Promise<{ feeds: number; entries: number }> {
	if (!env.BLOOM_KV) {
		console.warn("BLOOM_KV binding not configured — skipping intel feed refresh");
		return { feeds: 0, entries: 0 };
	}
	const mailboxes = await listMailboxes(env.BUCKET);
	const handled = new Set<string>();
	let feeds = 0;
	let entries = 0;
	for (const { id: mailboxId } of mailboxes) {
		const settings = await loadMailboxIntelSettings(env, mailboxId);
		const resolved = resolveFeeds(env, settings);
		for (const feed of resolved) {
			if (handled.has(feed.id)) continue; // global, not per-mailbox, to avoid duplicate work
			handled.add(feed.id);
			// Placeholder defaults (e.g. `crowdsec-community`) carry an
			// empty URL until an operator overrides it. Skip silently —
			// the lookup path still consults KV for any data that's been
			// materialised out-of-band.
			if (!feed.url) continue;
			try {
				const stub = getMailboxStub(env, mailboxId);
				const state = await stub.getIntelFeedState(feed.id);
				// Honor refreshHours: skip if the feed was fetched more recently than
				// its configured interval. A null/absent last_fetched_at is treated as
				// a first run and always triggers a fetch.
				if (state?.last_fetched_at) {
					const elapsedMs = Date.now() - new Date(state.last_fetched_at).getTime();
					if (elapsedMs < feed.refreshHours * 3600 * 1000) continue;
				}
				const refreshed = await refreshFeed(env, mailboxId, feed, state);
				feeds++;
				entries += refreshed.entries;
			} catch (e) {
				console.error(`feed refresh ${feed.id} failed:`, (e as Error).message);
			}
		}
	}
	return { feeds, entries };
}

type FeedState = Awaited<ReturnType<ReturnType<typeof getMailboxStub>["getIntelFeedState"]>>;

async function refreshFeed(
	env: Env,
	mailboxId: string,
	feed: FeedDefinition,
	state: FeedState,
): Promise<{ entries: number }> {
	const stub = getMailboxStub(env, mailboxId);

	// Read the blobs this feed's lookups depend on BEFORE fetching. A 304
	// carries no body, so the only way to renew their TTL (KV has no touch
	// operation) is to rewrite the values just read — and if any blob has
	// already TTL-expired, only an unconditional 200 can rebuild it.
	const requiredBlobs: Array<{ key: string; type: "arrayBuffer" | "text" }> =
		feed.kind === "ip-cidr"
			? [{ key: cidrKey(feed.id), type: "text" }]
			: [
					{ key: bloomKey(feed.id), type: "arrayBuffer" },
					{ key: exactBlobKey(feed.id), type: "text" },
				];
	const existingBlobs: Array<{ key: string; value: ArrayBuffer | string }> = [];
	for (const blob of requiredBlobs) {
		const value =
			blob.type === "arrayBuffer"
				? await env.BLOOM_KV.get(blob.key, "arrayBuffer")
				: await env.BLOOM_KV.get(blob.key, "text");
		if (value !== null) existingBlobs.push({ key: blob.key, value });
	}
	const blobsIntact = existingBlobs.length === requiredBlobs.length;

	const headers: Record<string, string> = { ...(feed.headers ?? {}) };
	// Conditional GET only while every required blob is still alive in KV — a
	// 304 is only safe to trust if the data it vouches for hasn't expired.
	if (state?.etag && blobsIntact) headers["If-None-Match"] = state.etag;

	const res = await fetch(feed.url, { headers, signal: AbortSignal.timeout(15000) });
	const ttlSeconds = Math.max(feed.refreshHours * 3600 * 4, 86400);
	if (res.status === 304) {
		if (!blobsIntact) {
			// We didn't send If-None-Match, so this 304 violates the protocol —
			// and with blobs missing there is no body to rebuild from. Fail the
			// refresh; last_fetched_at stays stale so the next cron run retries.
			throw new Error(`${feed.url} returned 304 to an unconditional request`);
		}
		// Renew the TTLs by rewriting the just-read values, and record the
		// refresh so the refreshHours gate keeps renewal at O(feeds) writes per
		// interval rather than per cron run.
		for (const { key, value } of existingBlobs) {
			await env.BLOOM_KV.put(key, value, { expirationTtl: ttlSeconds });
		}
		await stub.upsertIntelFeedState(feed.id, {
			url: feed.url,
			last_fetched_at: new Date().toISOString(),
			etag: state?.etag ?? null,
			entry_count: state?.entry_count ?? 0,
			bloom_kv_key: feed.kind === "ip-cidr" ? cidrKey(feed.id) : bloomKey(feed.id),
		});
		return { entries: state?.entry_count ?? 0 };
	}
	if (!res.ok) throw new Error(`${feed.url} returned ${res.status}`);

	const body = await res.text();

	if (feed.kind === "ip-cidr") {
		// CIDR feeds use a separate storage path: a JSON blob of
		// `{ network, mask, prefix }` rows, scanned linearly on lookup. Bloom
		// filters answer "is this exact string in the set" — they can't answer
		// "is this IP inside any of these ranges". DROP-class feeds are a few
		// thousand entries (well under any KV size limit) so JSON is fine.
		const cidrs = parseCidrFeedBody(body, feed.id);
		if (cidrs.length === 0) return { entries: 0 };
		const serialized = JSON.stringify(
			cidrs.map((c) => ({ n: c.network, m: c.mask, p: c.prefix })),
		);
		await env.BLOOM_KV.put(cidrKey(feed.id), serialized, {
			expirationTtl: ttlSeconds,
		});
		await stub.upsertIntelFeedState(feed.id, {
			url: feed.url,
			last_fetched_at: new Date().toISOString(),
			etag: res.headers.get("ETag") ?? null,
			entry_count: cidrs.length,
			bloom_kv_key: cidrKey(feed.id),
		});
		return { entries: cidrs.length };
	}

	const values = parseFeedBody(body, feed.kind);
	if (values.length === 0) return { entries: 0 };

	const bloom = createBloom(values.length);
	for (const v of values) addToBloom(bloom, v);
	await env.BLOOM_KV.put(bloomKey(feed.id), serializeBloom(bloom), {
		// Bounded TTL — a dead cron should eventually stop consulting stale data.
		expirationTtl: ttlSeconds,
	});

	// Write a bounded subset of exact-match values as a single JSON blob.
	// This reduces KV writes from O(entries) to O(1) per feed per refresh.
	// Deduped first: url-kind values repeat hostnames, and duplicates would
	// waste the cap.
	const exactSlice = [...new Set(values)].slice(0, EXACT_KEY_CAP);
	await env.BLOOM_KV.put(exactBlobKey(feed.id), JSON.stringify(exactSlice), {
		expirationTtl: ttlSeconds,
	});

	await stub.upsertIntelFeedState(feed.id, {
		url: feed.url,
		last_fetched_at: new Date().toISOString(),
		etag: res.headers.get("ETag") ?? null,
		entry_count: values.length,
		bloom_kv_key: bloomKey(feed.id),
	});

	return { entries: values.length };
}

export interface FeedMatch {
	matched: true;
	feedId: string;
	value: string;
	confirmed: boolean;
}

/**
 * Check a URL against all configured feeds: the bare hostname for `domain`
 * feeds, the full URL for `url` feeds. Returns the first confirmed match, or
 * the first bloom-only hit if no exact confirmations are available.
 *
 * `url` feeds are matched on the full URL only — never on the apex host — so a
 * URLhaus/OpenPhish entry hosted on a shared host (github.com, drive.google.com,
 * …) cannot collateral-block every legitimate link to that host.
 */
export async function checkUrlAgainstFeeds(
	env: Env,
	mailboxId: string,
	fullUrl: string,
): Promise<FeedMatch | null> {
	if (!env.BLOOM_KV) return null;
	const host = safeHostname(fullUrl);
	if (!host) return null;
	const settings = await loadMailboxIntelSettings(env, mailboxId);
	const feeds = resolveFeeds(env, settings);
	let bloomOnly: FeedMatch | null = null;

	for (const feed of feeds) {
		// URL/domain-feed lookup only — CIDR feeds use `checkIpAgainstFeeds`.
		// Mixing them would bloom-test a URL string against IP ranges and
		// emit nonsense.
		if (feed.kind !== "domain" && feed.kind !== "url") continue;
		const serialized = await env.BLOOM_KV.get(bloomKey(feed.id), "arrayBuffer");
		if (!serialized) continue;
		const filter = deserializeBloom(serialized);
		if (!filter) continue;
		// `domain` feeds match the bare host; `url` feeds match the full URL
		// only. parseFeedBody no longer stores apex hosts for url feeds, so
		// matching `host` here would never confirm and would only risk a
		// shared-host false positive (e.g. github.com).
		const candidates = feed.kind === "domain" ? [host] : [fullUrl];
		// The exact blob is ~200 KB and this runs per URL on the security
		// pipeline's hot path — fetch it lazily on the first bloom hit, at
		// most once per feed.
		let exactSet: Set<string> | null | undefined;
		for (const v of candidates) {
			if (!checkBloom(filter, v)) continue;
			if (exactSet === undefined) exactSet = await loadExactSet(env, feed.id);
			// No exact blob (missing or unparseable) → degrade to a bloom-only
			// hit (`confirmed: false`) rather than throwing out of the lookup.
			if (exactSet?.has(v)) return { matched: true, feedId: feed.id, value: v, confirmed: true };
			if (!bloomOnly) bloomOnly = { matched: true, feedId: feed.id, value: v, confirmed: false };
		}
	}
	return bloomOnly;
}

/**
 * Load a feed's exact-match blob. Returns null when the key is missing or
 * unparseable — a bloom hit then degrades to `confirmed: false` (bloom-only)
 * instead of failing the whole lookup.
 */
async function loadExactSet(env: Env, feedId: string): Promise<Set<string> | null> {
	const raw = await env.BLOOM_KV.get(exactBlobKey(feedId), "text");
	if (!raw) return null;
	try {
		const parsed: unknown = JSON.parse(raw);
		if (!Array.isArray(parsed)) return null;
		return new Set(parsed.filter((v): v is string => typeof v === "string"));
	} catch {
		return null;
	}
}

export interface IpFeedMatch {
	matched: true;
	feedId: string;
	feedDescription: string;
	ip: string;
	cidr: string;
}

interface SerializedCidrRow { n: number; m: number; p: number; }

/**
 * Resolve and check an IPv4 address against every configured `ip-cidr` feed.
 * Returns the first matching feed (feeds are checked in `resolveFeeds` order:
 * defaults first, then user-configured) so callers don't double-score one IP.
 *
 * Membership is checked via masked IPv4-as-uint32 comparison — see
 * `workers/intel/cidr.ts`. The serialized list is fetched once per feed per
 * call; callers that loop over many IPs should memoise it themselves.
 */
export async function checkIpAgainstFeeds(
	env: Env,
	mailboxId: string,
	ip: string,
): Promise<IpFeedMatch | null> {
	if (!env.BLOOM_KV) return null;
	const ipNum = parseIpv4(ip);
	if (ipNum === null) return null;
	const settings = await loadMailboxIntelSettings(env, mailboxId);
	const feeds = resolveFeeds(env, settings).filter((f) => f.kind === "ip-cidr");
	for (const feed of feeds) {
		const serialized = await env.BLOOM_KV.get(cidrKey(feed.id), "text");
		if (!serialized) continue;
		let rows: SerializedCidrRow[];
		try {
			rows = JSON.parse(serialized) as SerializedCidrRow[];
		} catch {
			continue;
		}
		if (!Array.isArray(rows)) continue;
		const cidrs: Ipv4Cidr[] = rows.map((r) => ({
			network: r.n >>> 0,
			mask: r.m >>> 0,
			prefix: r.p,
		}));
		const match = findCidrMatch(ipNum, cidrs);
		if (match) {
			const cidrText = formatCidr(match);
			return {
				matched: true,
				feedId: feed.id,
				feedDescription: feed.description,
				ip,
				cidr: cidrText,
			};
		}
	}
	return null;
}

function formatCidr(c: Ipv4Cidr): string {
	const a = (c.network >>> 24) & 0xff;
	const b = (c.network >>> 16) & 0xff;
	const cc = (c.network >>> 8) & 0xff;
	const d = c.network & 0xff;
	return `${a}.${b}.${cc}.${d}/${c.prefix}`;
}

/**
 * Mailbox-agnostic variant of `checkIpAgainstFeeds` — checks only the
 * default `ip-cidr` feeds (Spamhaus DROP/EDROP) against global `BLOOM_KV`.
 * Used by the catch-all analyzer which has no per-mailbox context.
 */
export async function checkIpAgainstDefaultFeeds(
	env: Env,
	ip: string,
): Promise<IpFeedMatch | null> {
	if (!env.BLOOM_KV) return null;
	const ipNum = parseIpv4(ip);
	if (ipNum === null) return null;
	const feeds = DEFAULT_FEEDS.filter((f) => f.kind === "ip-cidr");
	for (const feed of feeds) {
		const serialized = await env.BLOOM_KV.get(cidrKey(feed.id), "text");
		if (!serialized) continue;
		let rows: SerializedCidrRow[];
		try {
			rows = JSON.parse(serialized) as SerializedCidrRow[];
		} catch {
			continue;
		}
		if (!Array.isArray(rows)) continue;
		const cidrs: Ipv4Cidr[] = rows.map((r) => ({
			network: r.n >>> 0,
			mask: r.m >>> 0,
			prefix: r.p,
		}));
		const match = findCidrMatch(ipNum, cidrs);
		if (match) return { matched: true, feedId: feed.id, feedDescription: feed.description, ip, cidr: formatCidr(match) };
	}
	return null;
}
