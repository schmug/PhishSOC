// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for `checkUrlAgainstFeedsForDomain` (issue #435).
 *
 * The catch-all path has no `mailboxId`, so it cannot use
 * `checkUrlAgainstFeeds(env, mailboxId, url)` to resolve feeds via per-mailbox
 * intel settings. This domain-scoped variant resolves feeds from domain-level
 * intel settings (falling back to `DEFAULT_FEEDS`) and is safe to call when
 * `BLOOM_KV` is unconfigured.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkUrlAgainstFeedsForDomain } from "../../workers/intel/feeds";
import {
	addToBloom,
	createBloom,
	serializeBloom,
} from "../../workers/intel/bloom";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import type { Env } from "../../workers/types";

const DOMAIN = "acme.example";
const LISTED_URL = "https://evil.example/login";

function makeKv() {
	const store = new Map<string, string | Uint8Array>();
	return {
		store,
		async get(key: string, type?: "text" | "arrayBuffer") {
			const val = store.get(key);
			if (val === undefined) return null;
			if (type === "arrayBuffer") return val instanceof Uint8Array ? val.buffer : null;
			if (type === "text") return typeof val === "string" ? val : null;
			return val;
		},
		async put(key: string, value: string | Uint8Array | ArrayBuffer) {
			store.set(key, value instanceof ArrayBuffer ? new Uint8Array(value) : value);
		},
	};
}

/** Materialise a `url`-kind feed's bloom + exact blob in KV, as a refresh would. */
function seedUrlFeed(kv: ReturnType<typeof makeKv>, feedId: string, urls: string[]) {
	const bloom = createBloom(urls.length);
	for (const u of urls) addToBloom(bloom, u);
	kv.store.set(`intel:${feedId}:bloom`, serializeBloom(bloom));
	kv.store.set(`intel:${feedId}:exact-blob`, JSON.stringify(urls));
}

/** Env with optional domain settings blob at `domains/<domain>.json`. */
function makeEnv(opts: { kv?: ReturnType<typeof makeKv>; domainSettings?: unknown } = {}): Env {
	const bucket = {
		async get(key: string) {
			if (opts.domainSettings && key === `domains/${DOMAIN}.json`) {
				return { etag: "etag-1", async json() { return opts.domainSettings; } };
			}
			return null;
		},
	};
	return {
		BLOOM_KV: opts.kv as unknown as KVNamespace | undefined,
		BUCKET: bucket as unknown as R2Bucket,
	} as unknown as Env;
}

beforeEach(() => {
	clearDomainSettingsCache();
});
afterEach(() => {
	vi.restoreAllMocks();
});

describe("checkUrlAgainstFeedsForDomain", () => {
	it("returns a confirmed hit for a URL present in a default feed", async () => {
		const kv = makeKv();
		seedUrlFeed(kv, "urlhaus", [LISTED_URL]);
		const env = makeEnv({ kv });

		const result = await checkUrlAgainstFeedsForDomain(env, DOMAIN, LISTED_URL);
		expect(result?.matched).toBe(true);
		expect(result?.feedId).toBe("urlhaus");
		expect(result?.confirmed).toBe(true);
		expect(result?.value).toBe(LISTED_URL);
	});

	it("returns null for a URL absent from all feeds", async () => {
		const kv = makeKv();
		seedUrlFeed(kv, "urlhaus", [LISTED_URL]);
		const env = makeEnv({ kv });

		const result = await checkUrlAgainstFeedsForDomain(
			env,
			DOMAIN,
			"https://totally-unlisted.example/safe",
		);
		expect(result).toBeNull();
	});

	it("returns null (no throw) when BLOOM_KV is not configured", async () => {
		const env = makeEnv({ kv: undefined });
		await expect(
			checkUrlAgainstFeedsForDomain(env, DOMAIN, LISTED_URL),
		).resolves.toBeNull();
	});

	it("uses a domain-level feed override instead of the defaults", async () => {
		const kv = makeKv();
		// Only the override feed id is materialised; the default `urlhaus` is not.
		seedUrlFeed(kv, "domain-phish", [LISTED_URL]);
		const env = makeEnv({
			kv,
			domainSettings: {
				intel: {
					feeds: [
						{ id: "domain-phish", url: "https://feeds.example/phish.txt", kind: "url" },
					],
				},
			},
		});

		const result = await checkUrlAgainstFeedsForDomain(env, DOMAIN, LISTED_URL);
		expect(result?.feedId).toBe("domain-phish");
		expect(result?.confirmed).toBe(true);
	});
});
