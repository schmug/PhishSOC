// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for issue #292: GET /api/v1/org/acl-overview.
 *
 * Authz model under test: any CF-Access-admitted caller receives the full
 * overview. Callers with no CF Access header (local dev) also receive data —
 * consistent with all other /api/v1/org/* endpoints. There is no 403 path on
 * this endpoint.
 *
 * Uses in-memory R2 stubs — same pattern as mailboxes-acl-status.test.ts.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { listMailboxes } from "../../workers/lib/email-helpers";
import { readMailboxAcl } from "../../workers/lib/mailbox-acl";

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
// Minimal app replicating the GET /api/v1/org/acl-overview handler
// ---------------------------------------------------------------------------

type StubEnv = { BUCKET: ReturnType<typeof makeR2Stub> };

function makeApp(bucketStore: Record<string, string>, callerEmail: string | null) {
	const bucket = makeR2Stub(bucketStore);
	const app = new Hono<{ Bindings: StubEnv }>();

	app.get("/api/v1/org/acl-overview", async (c) => {
		const mailboxes = await listMailboxes(c.env.BUCKET as unknown as R2Bucket);
		const acls = await Promise.all(
			mailboxes.map((m) => readMailboxAcl(c.env as unknown as { BUCKET: R2Bucket }, m.id)),
		);
		const result = mailboxes.map((m, i) => {
			const acl = acls[i];
			return {
				email: m.email,
				acl_status: acl ? ("scoped" as const) : ("unscoped" as const),
				owner: acl ? acl.owner : null,
				members: acl ? acl.members : [],
			};
		});
		return c.json(result);
	});

	return {
		fetch() {
			const hdrs: Record<string, string> = {};
			if (callerEmail) hdrs["cf-access-authenticated-user-email"] = callerEmail;
			return app.request(
				"/api/v1/org/acl-overview",
				{ headers: hdrs },
				{ BUCKET: bucket as unknown as R2Bucket },
			);
		},
		bucket,
	};
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function makeMailboxKey(email: string) {
	return `mailboxes/${email}.json`;
}

function makeAclKey(email: string) {
	return `mailboxes-acl/${email}.json`;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("GET /api/v1/org/acl-overview", () => {
	it("returns empty array for empty fleet", async () => {
		const { fetch } = makeApp({}, "admin@example.com");
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body).toEqual([]);
	});

	it("all-unscoped fleet: returns all mailboxes with acl_status=unscoped, owner=null, members=[]", async () => {
		const bucketStore: Record<string, string> = {
			[makeMailboxKey("alice@example.com")]: JSON.stringify({ id: "alice@example.com" }),
			[makeMailboxKey("bob@example.com")]: JSON.stringify({ id: "bob@example.com" }),
		};
		const { fetch } = makeApp(bucketStore, "admin@example.com");
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = (await res.json()) as Array<{
			email: string;
			acl_status: string;
			owner: null;
			members: string[];
		}>;
		expect(body).toHaveLength(2);
		for (const row of body) {
			expect(row.acl_status).toBe("unscoped");
			expect(row.owner).toBeNull();
			expect(row.members).toEqual([]);
		}
	});

	it("all-scoped fleet: returns owner and members for each mailbox", async () => {
		const alice = "alice@example.com";
		const bob = "bob@example.com";
		const bucketStore: Record<string, string> = {
			[makeMailboxKey(alice)]: JSON.stringify({ id: alice }),
			[makeMailboxKey(bob)]: JSON.stringify({ id: bob }),
			[makeAclKey(alice)]: JSON.stringify({ owner: alice, members: [alice, bob] }),
			[makeAclKey(bob)]: JSON.stringify({ owner: bob, members: [bob] }),
		};
		const { fetch } = makeApp(bucketStore, "admin@example.com");
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = (await res.json()) as Array<{
			email: string;
			acl_status: string;
			owner: string | null;
			members: string[];
		}>;
		expect(body).toHaveLength(2);
		const aliceRow = body.find((r) => r.email === alice)!;
		expect(aliceRow.acl_status).toBe("scoped");
		expect(aliceRow.owner).toBe(alice);
		expect(aliceRow.members).toEqual([alice, bob]);

		const bobRow = body.find((r) => r.email === bob)!;
		expect(bobRow.acl_status).toBe("scoped");
		expect(bobRow.owner).toBe(bob);
		expect(bobRow.members).toEqual([bob]);
	});

	it("mixed fleet: scoped and unscoped mailboxes all appear in the response", async () => {
		const scoped = "scoped@example.com";
		const unscoped = "unscoped@example.com";
		const bucketStore: Record<string, string> = {
			[makeMailboxKey(scoped)]: JSON.stringify({ id: scoped }),
			[makeMailboxKey(unscoped)]: JSON.stringify({ id: unscoped }),
			[makeAclKey(scoped)]: JSON.stringify({ owner: scoped, members: [scoped] }),
		};
		const { fetch } = makeApp(bucketStore, "admin@example.com");
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = (await res.json()) as Array<{ email: string; acl_status: string }>;
		expect(body).toHaveLength(2);
		expect(body.find((r) => r.email === scoped)?.acl_status).toBe("scoped");
		expect(body.find((r) => r.email === unscoped)?.acl_status).toBe("unscoped");
	});

	it("authz: no CF Access header (local dev) still returns 200 — no 403 on this endpoint", async () => {
		const bucketStore: Record<string, string> = {
			[makeMailboxKey("alice@example.com")]: JSON.stringify({ id: "alice@example.com" }),
		};
		// callerEmail = null simulates local dev (no CF Access in front)
		const { fetch } = makeApp(bucketStore, null);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = (await res.json()) as Array<{ email: string }>;
		expect(body).toHaveLength(1);
		expect(body[0].email).toBe("alice@example.com");
	});

	it("authz: authenticated CF Access user receives 200 with full data", async () => {
		const owner = "owner@example.com";
		const member = "member@example.com";
		const mb = "inbox@example.com";
		const bucketStore: Record<string, string> = {
			[makeMailboxKey(mb)]: JSON.stringify({ id: mb }),
			[makeAclKey(mb)]: JSON.stringify({ owner, members: [owner, member] }),
		};
		// callerEmail is a non-owner member — still gets full data
		const { fetch } = makeApp(bucketStore, member);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = (await res.json()) as Array<{
			email: string;
			acl_status: string;
			owner: string;
			members: string[];
		}>;
		expect(body).toHaveLength(1);
		expect(body[0].acl_status).toBe("scoped");
		expect(body[0].owner).toBe(owner);
		expect(body[0].members).toContain(member);
	});

	it("multi-domain fleet: mailboxes from different domains all appear", async () => {
		const bucketStore: Record<string, string> = {
			[makeMailboxKey("a@alpha.com")]: JSON.stringify({ id: "a@alpha.com" }),
			[makeMailboxKey("b@beta.com")]: JSON.stringify({ id: "b@beta.com" }),
			[makeAclKey("a@alpha.com")]: JSON.stringify({
				owner: "a@alpha.com",
				members: ["a@alpha.com"],
			}),
		};
		const { fetch } = makeApp(bucketStore, "admin@alpha.com");
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = (await res.json()) as Array<{ email: string; acl_status: string }>;
		expect(body.map((r) => r.email).sort()).toEqual(["a@alpha.com", "b@beta.com"]);
	});
});
