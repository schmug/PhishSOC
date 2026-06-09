// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Domain-level settings persistence and read cache (#142).
 *
 * Mirrors `workers/lib/org-settings.ts` from #106 — same module-scope
 * ETag cache discipline, same "404 caches an absent sentinel so the hot
 * path doesn't re-fetch" pattern, same centralised key helper for a
 * future multi-tenant refactor.
 *
 * Per-domain blob lives at `domains/<domain>.json`. The cache is keyed by
 * domain so reading mailbox A on `acme.com` and mailbox B on `widgets.io`
 * both hit their own cache slots — invalidating one doesn't churn the
 * other.
 */

import {
	DomainSettings,
	parseDomainSettings,
} from "../../shared/domain-settings";
import { parseSettingsLenient } from "../../shared/mailbox-settings";

interface DomainSettingsCacheEntry {
	etag: string | null;
	settings: DomainSettings;
}

const cache = new Map<string, DomainSettingsCacheEntry>();

/** Sentinel etag used when R2 returns 404 — lets us cache "no domain
 *  settings for this domain" without a separate `present?` flag. */
const ABSENT_ETAG = "__absent__";

/**
 * R2 key for a domain's settings blob. Centralised so a future re-keying
 * (e.g. multi-tenant `orgs/<orgId>/domains/<domain>.json`) is one helper
 * change rather than a cross-cutting grep.
 */
export function domainSettingsKey(domain: string): string {
	return `domains/${domain.toLowerCase()}.json`;
}

/**
 * Extract the domain part of a mailbox id (which today equals the email
 * address). Returns null for malformed input — callers treat null as "no
 * domain tier" and the resolver falls through to org/default.
 */
export function domainFromMailboxId(mailboxId: string): string | null {
	const at = mailboxId.lastIndexOf("@");
	if (at < 0 || at === mailboxId.length - 1) return null;
	const domain = mailboxId.slice(at + 1).toLowerCase();
	if (!domain) return null;
	return domain;
}

/**
 * Read the domain settings blob from R2, honouring a per-domain
 * module-scope ETag cache.
 *
 * - First call (no cache): GET → parse → cache `{etag, settings}`.
 * - Subsequent calls: GET with `If-None-Match`. 304 → return cached. 200 →
 *   reparse and replace cache.
 * - 404: cache an empty `{}` under `ABSENT_ETAG` so subsequent reads still
 *   short-circuit without hammering R2.
 * - Parse failure or any other error: return empty settings, do NOT cache
 *   the failure (so a transient corruption can self-heal on the next read).
 */
export async function getDomainSettings(
	env: { BUCKET: R2Bucket },
	domain: string,
): Promise<DomainSettings> {
	const key = domainSettingsKey(domain);
	const cached = cache.get(key);

	const opts: R2GetOptions | undefined = cached?.etag && cached.etag !== ABSENT_ETAG
		? { onlyIf: { etagDoesNotMatch: cached.etag } }
		: undefined;

	let obj: R2ObjectBody | null;
	try {
		obj = await env.BUCKET.get(key, opts);
	} catch {
		return cached?.settings ?? {};
	}

	if (!obj) {
		if (cached) return cached.settings;
		cache.set(key, { etag: ABSENT_ETAG, settings: {} });
		return {};
	}

	try {
		const raw = await obj.json<Record<string, unknown>>();
		const parsed = parseSettingsLenient(DomainSettings, raw);
		cache.set(key, { etag: obj.etag ?? null, settings: parsed });
		return parsed;
	} catch {
		return cached?.settings ?? {};
	}
}

/**
 * Persist domain-level settings. Validates through the DomainSettings
 * schema so a malformed PUT can't write a blob the resolver would reject
 * on the next read. Invalidates the per-domain cache slot so subsequent
 * reads see the new value.
 */
export async function putDomainSettings(
	env: { BUCKET: R2Bucket },
	domain: string,
	settings: unknown,
): Promise<DomainSettings> {
	const parsed = parseDomainSettings(settings);
	if (!parsed) {
		throw new Error("Invalid DomainSettings");
	}
	const key = domainSettingsKey(domain);
	await env.BUCKET.put(key, JSON.stringify(parsed));
	cache.delete(key);
	return parsed;
}

/**
 * Drop the in-memory cache. Exported for tests; production code reaches
 * it through `putDomainSettings`.
 */
export function clearDomainSettingsCache(): void {
	cache.clear();
}
