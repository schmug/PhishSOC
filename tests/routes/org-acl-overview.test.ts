// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for GET /api/v1/org/acl-overview (#292).
 *
 * Uses in-memory R2 stubs and a minimal Hono app — same pattern as
 * tests/routes/mailboxes-acl-status.test.ts.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { readMailboxAcl, writeMailboxAcl } from "../../workers/lib/mailbox-acl";
import { listMailboxes } from "../../workers/lib/email-helpers";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";

// ---------------------------------------------------------------------------
// In-memory R2 stub
// ---------------------------------------------------------------------------

function makeR2Stub(initial: Record<string, string> = {}) {
	const store = { ...initial };
	return {
		async head(key: string) {
			return store[key] !== undefined ? { key } : null;
		},
		async get(key: string) {
			const val = store[key];
			if (!val) return null;
			return { json: async <T>() => JSON.parse(val) as T };
		},
		async put(key: string, value: string) {
			store[key] = value;
		},
		async delete(key: string) {
			delete store[key];
		},
		async list({ prefix }: { prefix: string }) {
			const objects = Object.keys(store)
				.filter((k) => k.startsWith(prefix))
				.map((key) => ({ key }));
			return { objects };
		},
		_store: store,
	};
}

// ---------------------------------------------------------------------------
// Minimal org/acl-overview app
// ---------------------------------------------------------------------------

function makeAclOverviewApp(bucketStore: Record<string, string>) {
	const bucket = makeR2Stub(bucketStore);

	const app = new Hono<{ Bindings: { BUCKET: typeof bucket } }>();

	app.get("/api/v1/org/acl-overview", async (c) => {
		const allMailboxes = await listMailboxes(c.env.BUCKET as unknown as R2Bucket);
		const acls = await Promise.all(
			allMailboxes.map((m) => readMailboxAcl(c.env as unknown as { BUCKET: R2Bucket }, m.id)),
		);

		return c.json({
			mailboxes: allMailboxes.map((m, i) => {
				const acl = acls[i];
				return {
					email: m.id,
					acl_status: (acl ? "scoped" : "unscoped") as "scoped" | "unscoped",
					owner: acl?.owner ?? null,
					members: acl?.members ?? [],
				};
			}),
		});
	});

	return {
		fetch() {
			return app.request(
				"/api/v1/org/acl-overview",
				{},
				{ BUCKET: bucket as unknown as R2Bucket },
			);
		},
		bucket,
	};
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const aliceId = "alice@example.com";
const aliceKey = `mailboxes/${aliceId}.json`;
const aliceAclKey = `mailboxes-acl/${aliceId}.json`;

const bobId = "bob@example.com";
const bobKey = `mailboxes/${bobId}.json`;

const aliceAcl: MailboxAcl = {
	owner: "alice@example.com",
	members: ["alice@example.com", "carol@example.com"],
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("GET /api/v1/org/acl-overview", () => {
	it("returns an empty mailboxes array when there are no mailboxes", async () => {
		const { fetch } = makeAclOverviewApp({});
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as { mailboxes: unknown[] };
		expect(body.mailboxes).toHaveLength(0);
	});

	it("returns unscoped for a mailbox with no ACL blob", async () => {
		const { fetch } = makeAclOverviewApp({ [aliceKey]: "{}" });
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as { mailboxes: Array<{ email: string; acl_status: string; owner: string | null; members: string[] }> };
		expect(body.mailboxes).toHaveLength(1);
		const entry = body.mailboxes[0];
		expect(entry.email).toBe(aliceId);
		expect(entry.acl_status).toBe("unscoped");
		expect(entry.owner).toBeNull();
		expect(entry.members).toHaveLength(0);
	});

	it("returns scoped with owner and members for a mailbox with an ACL", async () => {
		const store = {
			[aliceKey]: "{}",
			[aliceAclKey]: JSON.stringify(aliceAcl),
		};
		const { fetch } = makeAclOverviewApp(store);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as { mailboxes: Array<{ email: string; acl_status: string; owner: string | null; members: string[] }> };
		const entry = body.mailboxes.find((e) => e.email === aliceId);
		expect(entry).toBeDefined();
		expect(entry?.acl_status).toBe("scoped");
		expect(entry?.owner).toBe("alice@example.com");
		expect(entry?.members).toContain("carol@example.com");
	});

	it("returns all mailboxes in a mixed fleet (scoped and unscoped)", async () => {
		const store = {
			[aliceKey]: "{}",
			[aliceAclKey]: JSON.stringify(aliceAcl),
			[bobKey]: "{}",
			// no ACL for bob → unscoped
		};
		const { fetch } = makeAclOverviewApp(store);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as { mailboxes: Array<{ email: string; acl_status: string }> };
		expect(body.mailboxes).toHaveLength(2);
		const aliceEntry = body.mailboxes.find((e) => e.email === aliceId);
		const bobEntry = body.mailboxes.find((e) => e.email === bobId);
		expect(aliceEntry?.acl_status).toBe("scoped");
		expect(bobEntry?.acl_status).toBe("unscoped");
	});

	it("returns all-scoped fleet correctly", async () => {
		const bobAcl: MailboxAcl = { owner: "bob@example.com", members: ["bob@example.com"] };
		const store = {
			[aliceKey]: "{}",
			[aliceAclKey]: JSON.stringify(aliceAcl),
			[bobKey]: "{}",
			[`mailboxes-acl/${bobId}.json`]: JSON.stringify(bobAcl),
		};
		const { fetch } = makeAclOverviewApp(store);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as { mailboxes: Array<{ email: string; acl_status: string }> };
		expect(body.mailboxes).toHaveLength(2);
		for (const entry of body.mailboxes) {
			expect(entry.acl_status).toBe("scoped");
		}
	});

	it("returns all-unscoped fleet correctly", async () => {
		const store = { [aliceKey]: "{}", [bobKey]: "{}" };
		const { fetch } = makeAclOverviewApp(store);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as { mailboxes: Array<{ email: string; acl_status: string; owner: string | null }> };
		expect(body.mailboxes).toHaveLength(2);
		for (const entry of body.mailboxes) {
			expect(entry.acl_status).toBe("unscoped");
			expect(entry.owner).toBeNull();
		}
	});

	it("reflects ACL written by writeMailboxAcl", async () => {
		const store: Record<string, string> = { [aliceKey]: "{}" };
		const bucket = makeR2Stub(store);
		await writeMailboxAcl(
			{ BUCKET: bucket as unknown as R2Bucket },
			aliceId,
			{ owner: "alice@example.com", members: ["alice@example.com"] },
		);

		const { fetch } = makeAclOverviewApp(bucket._store);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as { mailboxes: Array<{ email: string; acl_status: string }> };
		const entry = body.mailboxes.find((e) => e.email === aliceId);
		expect(entry?.acl_status).toBe("scoped");
	});
});
