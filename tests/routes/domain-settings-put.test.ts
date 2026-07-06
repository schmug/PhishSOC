// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Domain-settings PUT writes a relay target host + credentials-secret name
 * that a gateway-mode relay will use with AUTH PLAIN. That tier must only
 * be writable for domains the operator actually owns (DOMAINS env +
 * org.domains) — parity with the ownership gate on catch-all routing and
 * on gateway routing (workers/providers/cf-routing.ts resolveUnregistered).
 */

import { beforeEach, describe, expect, it } from "vitest";
import { app } from "../../workers/index";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
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
	clearDomainSettingsCache();
	clearOrgSettingsCache();
});

describe("PUT /api/v1/domains/:domain/settings — ownership gate", () => {
	it("writes settings for a domain owned via DOMAINS env", async () => {
		const bucket = makeR2();
		const env = { BUCKET: bucket, DOMAINS: "example.com" };

		const res = await app.request(
			"/api/v1/domains/example.com/settings",
			{
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ settings: { catchall_intel: { enabled: true } } }),
			},
			env,
		);
		expect(res.status).toBe(200);
		expect(bucket.read("domains/example.com.json")).toBeDefined();
	});

	it("writes settings for a domain owned via org.domains", async () => {
		const bucket = makeR2({
			"org/settings.json": JSON.stringify({ domains: ["orgowned.example"] }),
		});
		const env = { BUCKET: bucket, DOMAINS: "" };

		const res = await app.request(
			"/api/v1/domains/orgowned.example/settings",
			{
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ settings: { catchall_intel: { enabled: true } } }),
			},
			env,
		);
		expect(res.status).toBe(200);
		expect(bucket.read("domains/orgowned.example.json")).toBeDefined();
	});

	it("rejects a PUT for a domain not in this org's owned domains (403)", async () => {
		const bucket = makeR2();
		const env = { BUCKET: bucket, DOMAINS: "example.com" };

		const res = await app.request(
			"/api/v1/domains/not-owned.example/settings",
			{
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					settings: { relay: { enabled: true, target: { host: "smtp-relay.gmail.com" } } },
				}),
			},
			env,
		);
		expect(res.status).toBe(403);
		// Nothing written for the unowned domain.
		expect(bucket.read("domains/not-owned.example.json")).toBeUndefined();
	});
});
