// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * `blocklist` is owned by the dedicated blocklist endpoints. The general
 * mailbox and domain settings PUTs must never wipe or rewrite it
 * (spec: sender-blocklist-design, API section).
 */

import { beforeEach, describe, expect, it } from "vitest";
import { app } from "../../workers/index";
import { preserveOwnedMailboxFields, stripDefaultEqual } from "../../workers/lib/mailbox-settings";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";

const RULE = { id: "r1", match: "podview.com", action: "drop", created_at: "2026-09-27T00:00:00Z" };

function makeR2(initial: Record<string, string> = {}) {
	const store = new Map<string, string>(Object.entries(initial));
	return {
		async get(key: string) {
			if (!store.has(key)) return null;
			const val = store.get(key)!;
			return { etag: "etag-1", async json() { return JSON.parse(val); } };
		},
		async head(key: string) { return store.has(key) ? { key } : null; },
		async put(key: string, val: string) { store.set(key, val); },
		read(key: string) { return store.get(key); },
	};
}

beforeEach(() => {
	clearDomainSettingsCache();
	clearOrgSettingsCache();
});

describe("stripDefaultEqual", () => {
	it("drops an empty blocklist", () => {
		expect(stripDefaultEqual({ blocklist: [] })).toEqual({});
		expect(stripDefaultEqual({ blocklist: [RULE] })).toEqual({ blocklist: [RULE] });
	});
});

describe("preserveOwnedMailboxFields", () => {
	it("keeps persisted honeypot and blocklist, drops incoming blocklist", () => {
		const out = preserveOwnedMailboxFields(
			{ blocklist: [RULE] as never, honeypot: { provisioned: true } as never },
			{ agentModel: "x", blocklist: [] as never },
		);
		expect(out).toEqual({ agentModel: "x", blocklist: [RULE], honeypot: { provisioned: true } });
		expect(preserveOwnedMailboxFields({}, { blocklist: [RULE] as never })).toEqual({});
	});
});

describe("settings PUTs preserve blocklist", () => {
	it("domain PUT keeps the persisted blocklist", async () => {
		const bucket = makeR2({ "domains/example.com.json": JSON.stringify({ blocklist: [RULE] }) });
		const env = { BUCKET: bucket, DOMAINS: "example.com" };
		const res = await app.request(
			"/api/v1/domains/example.com/settings",
			{ method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ settings: { agentModel: "x", blocklist: [] } }) },
			env,
		);
		expect(res.status).toBe(200);
		expect(JSON.parse(bucket.read("domains/example.com.json")!).blocklist).toEqual([RULE]);
	});
});
