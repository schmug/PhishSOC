// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Org PUT is full-replace. Domains and intel.feeds are managed outside the
 * /settings form and must survive a stale settings-form save.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { app } from "../../workers/index";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";

function makeR2(initial: Record<string, string> = {}) {
	const store = new Map<string, string>(Object.entries(initial));
	return {
		async get(key: string) {
			if (!store.has(key)) return null;
			const val = store.get(key)!;
			return { etag: "etag-1", async json() { return JSON.parse(val); } };
		},
		async put(key: string, val: string) {
			store.set(key, val);
		},
		read(key: string) {
			return store.get(key);
		},
	};
}

beforeEach(() => {
	clearOrgSettingsCache();
});

describe("PUT /api/v1/org/settings — preserve server-managed keys", () => {
	it("does not clobber domains added via POST when PUT carries a stale snapshot", async () => {
		const bucket = makeR2({
			"org/settings.json": JSON.stringify({
				domains: ["newco.example", "seed.example"],
				agentModel: "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
			}),
		});
		const env = { BUCKET: bucket, DOMAINS: "seed.example" };

		const res = await app.request(
			"/api/v1/org/settings",
			{
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					settings: {
						domains: ["seed.example"],
						autoDraft: { enabled: false },
					},
				}),
			},
			env,
		);
		expect(res.status).toBe(200);

		const stored = JSON.parse(bucket.read("org/settings.json")!) as Record<string, unknown>;
		expect(stored.domains).toEqual(["newco.example", "seed.example"]);
		expect((stored.autoDraft as { enabled: boolean }).enabled).toBe(false);
	});

	it("preserves intel.feeds when PUT omits them", async () => {
		const feeds = [{ id: "custom-feed", url: "https://feeds.example.com/list" }];
		const bucket = makeR2({
			"org/settings.json": JSON.stringify({
				intel: { feeds },
			}),
		});
		const env = { BUCKET: bucket, DOMAINS: "" };

		const res = await app.request(
			"/api/v1/org/settings",
			{
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					settings: { autoDraft: { enabled: true } },
				}),
			},
			env,
		);
		expect(res.status).toBe(200);

		const stored = JSON.parse(bucket.read("org/settings.json")!) as {
			intel?: { feeds: unknown[] };
		};
		expect(stored.intel?.feeds).toEqual(feeds);
	});
});
