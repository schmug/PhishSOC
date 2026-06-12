// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Org-wide settings persistence and read cache (#106).
 *
 * Reads `org/settings.json` from R2 with a module-scope ETag cache so the
 * per-email inheritance hierarchy doesn't cost an R2 GET on every read.
 * The cache is invalidated on PUT and refreshed on a 200 response from R2;
 * a 304 (If-None-Match hit) keeps the cached value as-is.
 *
 * Multi-tenant note: today the key is the flat `org/settings.json`
 * (single-org-per-deploy, matching #104). The R2 key is centralised here
 * (`orgSettingsKey`) so a future multi-tenant refactor — e.g.
 * `orgs/<orgId>/settings.json` keyed off CF Access claims — is one helper
 * change rather than a cross-cutting grep. The cache key is derived from
 * the same helper for the same reason.
 */

import { OrgSettings, parseOrgSettings } from "../../shared/org-settings";
import { parseSettingsLenient } from "../../shared/mailbox-settings";

interface OrgSettingsCacheEntry {
	etag: string | null;
	settings: OrgSettings;
}

const cache = new Map<string, OrgSettingsCacheEntry>();

/** Sentinel etag used when R2 returns 404 — lets us cache "no org settings"
 *  without a separate `present?` flag. */
const ABSENT_ETAG = "__absent__";

/**
 * R2 key for the org settings blob. Centralised so multi-tenancy is one
 * change. Returns the same string for every call today; in the multi-tenant
 * future the signature can grow an `orgId` argument.
 */
export function orgSettingsKey(): string {
	return "org/settings.json";
}

/**
 * Read the org settings blob from R2, honouring a module-scope ETag cache.
 *
 * - First call (no cache): GET → parse → cache `{etag, settings}`.
 * - Subsequent calls: GET with `If-None-Match`. 304 → return cached. 200 →
 *   reparse and replace cache.
 * - 404: cache an empty `{}` under `ABSENT_ETAG` so subsequent reads still
 *   short-circuit without hammering R2.
 * - Parse failure or any other error: return empty settings, do NOT cache
 *   the failure (so a transient corruption can self-heal on the next read).
 */
export async function getOrgSettings(env: { BUCKET: R2Bucket }): Promise<OrgSettings> {
	const key = orgSettingsKey();
	const cached = cache.get(key);

	const opts: R2GetOptions | undefined = cached?.etag && cached.etag !== ABSENT_ETAG
		? { onlyIf: { etagDoesNotMatch: cached.etag } }
		: undefined;

	let obj: R2ObjectBody | null;
	try {
		// Workers R2 binding: when `onlyIf.etagDoesNotMatch` matches the stored
		// etag, get() returns null (semantically a 304). When the object is
		// absent, get() also returns null. We disambiguate by checking the
		// cache entry: if we have a cached value, null means "not modified",
		// so reuse the cache. If we have no cache, null means "object absent".
		obj = await env.BUCKET.get(key, opts);
	} catch {
		return cached?.settings ?? {};
	}

	if (!obj) {
		if (cached) return cached.settings;
		// No cache and no object → cache "absent" so we don't re-fetch on hot path.
		cache.set(key, { etag: ABSENT_ETAG, settings: {} });
		return {};
	}

	try {
		const raw = await obj.json<Record<string, unknown>>();
		// Read-side lenient parse: legacy intel.hub/feed secret names must not
		// wipe the whole org tier (same invariant as getMailboxSettings, #415).
		const parsed = parseSettingsLenient(OrgSettings, raw);
		cache.set(key, { etag: obj.etag ?? null, settings: parsed });
		return parsed;
	} catch {
		// Malformed blob: return empty, don't poison the cache.
		return cached?.settings ?? {};
	}
}

/**
 * Persist org-level settings. Validates the input through the OrgSettings
 * schema so a malformed PUT can't write a blob that getOrgSettings would
 * reject on the next read. Invalidates the cache so subsequent reads see
 * the new value (even though the next R2 GET would refetch on etag change,
 * dropping the cache here keeps the contract simple).
 */
export async function putOrgSettings(
	env: { BUCKET: R2Bucket },
	settings: unknown,
): Promise<OrgSettings> {
	const parsed = parseOrgSettings(settings);
	if (!parsed) {
		throw new Error("Invalid OrgSettings");
	}
	await env.BUCKET.put(orgSettingsKey(), JSON.stringify(parsed));
	cache.delete(orgSettingsKey());
	return parsed;
}

/**
 * Drop the in-memory cache. Exported for tests; production code reaches it
 * through `putOrgSettings`.
 */
export function clearOrgSettingsCache(): void {
	cache.clear();
}
