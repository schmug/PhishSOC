// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Regression: a `url`-kind feed (URLhaus, OpenPhish) must NOT cause a legit
 * URL to match merely because it shares an apex host with a listed malicious
 * URL.
 *
 * URLhaus is a list of *specific malicious URLs*, and malware is frequently
 * hosted ON shared, high-reputation hosts (github.com, drive.google.com,
 * raw.githubusercontent.com, pastebin.com, …). Deriving the bare hostname
 * from each URL entry and matching on it collapses every such entry to its
 * apex, so any later email linking to that apex gets a CONFIRMED intel hit →
 * `hard_block` (score 100, classifier skipped). That is exactly how a
 * legitimate `https://github.com/<user>/<repo>` link in a SerpApi support
 * reply got blocked as "phishing".
 *
 * Contract: `url` feeds match the full URL only. Host-level matching is the
 * job of `domain`-kind feeds.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	checkUrlAgainstFeeds,
	parseFeedBody,
	refreshAllFeeds,
} from "../../workers/intel/feeds";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import type { Env } from "../../workers/types";

const MAILBOX_ID = "user@example.com";

// ── Minimal KV / BUCKET / MAILBOX harness (mirrors feed-kv-writes.test.ts) ──

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

function makeEnv(mailboxSettings: unknown): Env {
	const kv = makeKv();
	const stub = {
		async getIntelFeedState() {
			return null;
		},
		async upsertIntelFeedState() {},
	};
	const mailboxNs = {
		idFromName(name: string) {
			return { toString: () => name } as unknown as DurableObjectId;
		},
		get() {
			return stub as unknown as DurableObjectStub;
		},
	} as unknown as DurableObjectNamespace;
	const bucket = {
		async list() {
			return { objects: [{ key: `mailboxes/${MAILBOX_ID}.json` }] };
		},
		async get(key: string) {
			if (key !== `mailboxes/${MAILBOX_ID}.json`) return null;
			return { etag: "etag-1", async json() { return mailboxSettings; } };
		},
	};
	return {
		BLOOM_KV: kv as unknown as KVNamespace,
		BUCKET: bucket as unknown as R2Bucket,
		MAILBOX: mailboxNs,
	} as unknown as Env;
}

const URL_FEED_SETTINGS = {
	intel: {
		feeds: [{ id: "urlhaus", url: "https://test.example/urlhaus.txt", kind: "url" }],
	},
};

// A URLhaus-shaped body: a malicious URL hosted on github.com, plus a
// dedicated-host phishing URL.
const FEED_BODY = [
	"https://github.com/evil-actor/malware-dropper",
	"https://evil.example/login",
].join("\n");

beforeEach(() => {
	clearOrgSettingsCache();
	clearDomainSettingsCache();
});
afterEach(() => {
	vi.restoreAllMocks();
});

// ── parseFeedBody: url entries never contribute a bare host ──────────────────

describe("parseFeedBody — url kind keeps full URLs, never derives bare host", () => {
	it("does not emit the apex host for a url-kind entry", () => {
		const values = parseFeedBody("https://github.com/evil-actor/malware-dropper", "url");
		expect(values).toContain("https://github.com/evil-actor/malware-dropper");
		expect(values).not.toContain("github.com");
	});

	it("domain kind still normalizes to the bare host", () => {
		expect(parseFeedBody("github.com", "domain")).toEqual(["github.com"]);
	});
});

// ── checkUrlAgainstFeeds: shared-apex links are not collateral-blocked ────────

describe("url-feed lookup — shared apex host is not a false positive", () => {
	it("a legit github.com link does NOT match a URLhaus entry hosted on github.com", async () => {
		vi.stubGlobal("fetch", async () => new Response(FEED_BODY, { status: 200 }));
		const env = makeEnv(URL_FEED_SETTINGS);
		await refreshAllFeeds(env);

		const result = await checkUrlAgainstFeeds(
			env,
			MAILBOX_ID,
			"https://github.com/rpanigrahi222/intruth-factcheck",
		);
		expect(result).toBeNull();
	});

	it("the exact listed malicious URL still produces a confirmed hit", async () => {
		vi.stubGlobal("fetch", async () => new Response(FEED_BODY, { status: 200 }));
		const env = makeEnv(URL_FEED_SETTINGS);
		await refreshAllFeeds(env);

		const result = await checkUrlAgainstFeeds(
			env,
			MAILBOX_ID,
			"https://github.com/evil-actor/malware-dropper",
		);
		expect(result?.confirmed).toBe(true);
		expect(result?.value).toBe("https://github.com/evil-actor/malware-dropper");
	});
});
