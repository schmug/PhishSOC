// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for honeypot mailboxes (issue #24):
 *   - POST /api/v1/honeypots spins up N TTL'd honeypot mailboxes on an owned domain
 *   - the created blobs are flagged `honeypot.enabled` and carry an expiry
 *   - a non-owned domain is rejected
 *   - reapExpiredHoneypots GC's expired honeypots (and only those), reusing reapMailbox
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { app, reapExpiredHoneypots } from "../../workers/index";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";
import { stripDefaultEqual } from "../../workers/lib/mailbox-settings";

describe("honeypot settings — stripDefaultEqual", () => {
	it("strips a disabled/empty honeypot block but preserves an enabled one", () => {
		expect(stripDefaultEqual({ honeypot: { enabled: false } })).not.toHaveProperty("honeypot");
		expect(stripDefaultEqual({ honeypot: {} })).not.toHaveProperty("honeypot");
		const enabled = { honeypot: { enabled: true, expires_at: "2026-07-01T00:00:00Z", max_inbound: 1000 } };
		expect(stripDefaultEqual(enabled).honeypot).toEqual(enabled.honeypot);
	});
});

/** Minimal in-memory R2 supporting the subset of operations honeypots use. */
function makeR2(initial: Record<string, string> = {}) {
	const store = new Map<string, string>(Object.entries(initial));
	return {
		store,
		async head(key: string) {
			return store.has(key) ? { key } : null;
		},
		async get(key: string) {
			if (!store.has(key)) return null;
			const val = store.get(key)!;
			return { etag: "etag-1", async json() { return JSON.parse(val); } };
		},
		async put(key: string, val: string) {
			store.set(key, val);
		},
		async delete(key: string | string[]) {
			for (const k of Array.isArray(key) ? key : [key]) store.delete(k);
		},
		async list({ prefix }: { prefix: string }) {
			return {
				objects: [...store.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key })),
			};
		},
	};
}

function makeMailboxNs() {
	const stub = {
		getFolders: vi.fn().mockResolvedValue([]),
		reset: vi.fn().mockResolvedValue(undefined),
		listAllAttachmentKeys: vi.fn().mockResolvedValue([]),
	};
	return {
		stub,
		ns: {
			idFromName: (n: string) => ({ toString: () => n }),
			get: () => stub,
		},
	};
}

beforeEach(() => {
	clearDomainSettingsCache();
	clearOrgSettingsCache();
});

describe("POST /api/v1/honeypots", () => {
	it("spins up N honeypots on the default owned domain with a TTL", async () => {
		const bucket = makeR2({ "org/settings.json": JSON.stringify({}) });
		const { stub, ns } = makeMailboxNs();
		const env = {
			DOMAINS: "acme.example",
			BUCKET: bucket,
			MAILBOX: ns,
		} as unknown as Parameters<typeof app.request>[2];

		const res = await app.request(
			"/api/v1/honeypots",
			{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ count: 3, ttl_days: 7 }) },
			env,
		);
		expect(res.status).toBe(201);
		const body = (await res.json()) as { created: string[]; domain: string; expires_at: string; count: number };
		expect(body.count).toBe(3);
		expect(body.created).toHaveLength(3);
		expect(body.domain).toBe("acme.example");
		expect(Date.parse(body.expires_at)).toBeGreaterThan(Date.now());
		expect(stub.getFolders).toHaveBeenCalledTimes(3);

		// Each created blob exists, is flagged a honeypot, and carries the expiry.
		for (const email of body.created) {
			expect(email.endsWith("@acme.example")).toBe(true);
			const blob = JSON.parse(bucket.store.get(`mailboxes/${email}.json`)!) as {
				honeypot?: { enabled?: boolean; expires_at?: string };
			};
			expect(blob.honeypot?.enabled).toBe(true);
			expect(blob.honeypot?.expires_at).toBe(body.expires_at);
		}
	});

	it("rejects a domain that is not owned", async () => {
		const bucket = makeR2({ "org/settings.json": JSON.stringify({}) });
		const { ns } = makeMailboxNs();
		const env = {
			DOMAINS: "acme.example",
			BUCKET: bucket,
			MAILBOX: ns,
		} as unknown as Parameters<typeof app.request>[2];

		const res = await app.request(
			"/api/v1/honeypots",
			{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ domain: "notowned.example" }) },
			env,
		);
		expect(res.status).toBe(400);
	});
});

describe("reapExpiredHoneypots", () => {
	it("reaps expired honeypots only, reusing the mailbox-reap path", async () => {
		const past = new Date(Date.now() - 60_000).toISOString();
		const future = new Date(Date.now() + 86_400_000).toISOString();
		const bucket = makeR2({
			"org/settings.json": JSON.stringify({}),
			"mailboxes/hp-old@acme.example.json": JSON.stringify({ honeypot: { enabled: true, expires_at: past } }),
			"mailboxes/hp-new@acme.example.json": JSON.stringify({ honeypot: { enabled: true, expires_at: future } }),
			"mailboxes/alice@acme.example.json": JSON.stringify({ fromName: "Alice" }),
		});
		const { stub: mbStub, ns: mailboxNs } = makeMailboxNs();
		const { ns: agentNs } = makeMailboxNs();
		const env = {
			BUCKET: bucket,
			MAILBOX: mailboxNs,
			EMAIL_AGENT: agentNs,
		} as unknown as Parameters<typeof reapExpiredHoneypots>[0];

		const result = await reapExpiredHoneypots(env);
		expect(result.reaped).toBe(1);

		// Expired honeypot blob is gone; the live honeypot and normal mailbox remain.
		expect(bucket.store.has("mailboxes/hp-old@acme.example.json")).toBe(false);
		expect(bucket.store.has("mailboxes/hp-new@acme.example.json")).toBe(true);
		expect(bucket.store.has("mailboxes/alice@acme.example.json")).toBe(true);
		// The DO reap path ran for the expired honeypot.
		expect(mbStub.reset).toHaveBeenCalled();
	});
});
