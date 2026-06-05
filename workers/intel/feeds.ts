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
 *   5. Also write an `intel:{feedId}:exact:<value>` marker for a subset of
 *      high-confidence entries so we can confirm a bloom hit without false
 *      positives. (Bounded to prevent runaway KV writes.)
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
import { resolveMailboxSettings } from "../lib/mailbox-settings";

const EXACT_KEY_CAP = 2000; // per-feed cap — we only fast-path confirm up to this many

function bloomKey(feedId: string) { return `intel:${feedId}:bloom`; }
function exactKey(feedId: string, value: string) { return `intel:${feedId}:exact:${value}`; }
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

function resolveFeeds(env: Env, settings: MailboxIntelSettings): FeedDefinition[] {
	const defaults = settings.feeds && settings.feeds.length > 0 ? [] : DEFAULT_FEEDS;
	const byId = new Map<string, FeedDefinition>(DEFAULT_FEEDS.map((f) => [f.id, f]));
	const user: FeedDefinition[] = [];
	for (const f of settings.feeds ?? []) {
		const base = byId.get(f.id);
		const headers: Record<string, string> = { ...(f.headers ?? {}) };
		if (f.auth_secret) {
			const secretValue = (env as unknown as Record<string, string>)[f.auth_secret];
			if (secretValue) headers["Authorization"] = secretValue;
		}
		user.push({
			id: f.id,
			url: f.url ?? base?.url ?? "",
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

function parseFeedBody(body: string, kind: "domain" | "url"): string[] {
	const lines = body.split(/\r?\n/);
	const out: string[] = [];
	for (const raw of lines) {
		const line = raw.trim();
		if (!line || line.startsWith("#")) continue;
		if (kind === "domain") {
			out.push(normalizeDomain(line));
		} else {
			out.push(line);
			const host = safeHostname(line);
			if (host) out.push(normalizeDomain(host));
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
				const refreshed = await refreshFeed(env, mailboxId, feed);
				feeds++;
				entries += refreshed.entries;
			} catch (e) {
				console.error(`feed refresh ${feed.id} failed:`, (e as Error).message);
			}
		}
	}
	return { feeds, entries };
}

async function refreshFeed(
	env: Env,
	mailboxId: string,
	feed: FeedDefinition,
): Promise<{ entries: number }> {
	const stub = getMailboxStub(env, mailboxId);
	const state = await stub.getIntelFeedState(feed.id);

	const headers: Record<string, string> = { ...(feed.headers ?? {}) };
	if (state?.etag) headers["If-None-Match"] = state.etag;

	const res = await fetch(feed.url, { headers, signal: AbortSignal.timeout(15000) });
	if (res.status === 304) return { entries: state?.entry_count ?? 0 };
	if (!res.ok) throw new Error(`${feed.url} returned ${res.status}`);

	const body = await res.text();
	const ttlSeconds = Math.max(feed.refreshHours * 3600 * 4, 86400);

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

	// Write a bounded subset of exact-match markers for secondary confirmation.
	const exactSlice = values.slice(0, EXACT_KEY_CAP);
	const writes: Promise<void>[] = [];
	for (const v of exactSlice) {
		writes.push(
			env.BLOOM_KV
				.put(exactKey(feed.id, v), "1", {
					expirationTtl: feed.refreshHours * 3600 * 4,
				})
				.catch(() => {}), // isolated; individual failures shouldn't abort refresh
		);
	}
	await Promise.all(writes);

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
 * Check a URL's hostname and full URL against all configured feeds.
 * Returns the first confirmed match, or the first bloom-only hit if no
 * exact confirmations are available.
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
		const candidates = feed.kind === "domain" ? [host] : [fullUrl, host];
		for (const v of candidates) {
			if (!checkBloom(filter, v)) continue;
			const exact = await env.BLOOM_KV.get(exactKey(feed.id, v), "text");
			if (exact === "1") return { matched: true, feedId: feed.id, value: v, confirmed: true };
			if (!bloomOnly) bloomOnly = { matched: true, feedId: feed.id, value: v, confirmed: false };
		}
	}
	return bloomOnly;
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
 * Mailbox-agnostic variant of {@link checkIpAgainstFeeds} that checks an IPv4
 * address against the global `DEFAULT_FEEDS` ip-cidr entries (Spamhaus DROP +
 * EDROP) stored in `BLOOM_KV`. Does NOT load per-mailbox settings — safe to
 * call from paths that have no `mailboxId` (e.g. the catch-all analyzer).
 *
 * Returns the first matching feed or `null`. Never throws — callers should
 * treat `null` as "no signal" rather than "failed", matching the best-effort
 * contract of the whole intel layer.
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
		if (match) {
			return {
				matched: true,
				feedId: feed.id,
				feedDescription: feed.description,
				ip,
				cidr: formatCidr(match),
			};
		}
	}
	return null;
}
