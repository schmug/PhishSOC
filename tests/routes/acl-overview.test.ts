// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for GET /api/v1/org/acl-overview (#292).
 *
 * Authz model: any CF-Access-admitted caller (non-null
 * `cf-access-authenticated-user-email`) may read the overview.
 * Callers with no CF Access header receive 403.
 *
 * Uses in-memory R2 stubs and a minimal Hono app — same pattern as
 * tests/routes/mailboxes-acl-status.test.ts.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { readMailboxAcl } from "../../workers/lib/mailbox-acl";
import { listMailboxes } from "../../workers/lib/email-helpers";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";
import type { MailboxContext } from "../../workers/lib/mailbox";

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
// Minimal ACL overview app (mirrors the production endpoint in workers/index.ts)
// ---------------------------------------------------------------------------

interface AclOverviewEntry {
	email: string;
	acl_status: "scoped" | "unscoped";
	owner: string | null;
	members: string[];
}

function makeOverviewApp(bucketStore: Record<string, string>) {
	const bucket = makeR2Stub(bucketStore);
	const MAILBOX = { idFromName: () => "fake-id", get: () => ({}) };

	const app = new Hono<MailboxContext>();

	app.get("/api/v1/org/acl-overview", async (c) => {
		const callerEmail =
			c.req.header("cf-access-authenticated-user-email") ?? null;
		if (!callerEmail) {
			return c.json({ error: "CF Access email required" }, 403);
		}

		const mailboxes = await listMailboxes(c.env.BUCKET as unknown as R2Bucket);
		const acls = await Promise.all(
			mailboxes.map((m) =>
				readMailboxAcl(c.env as unknown as { BUCKET: R2Bucket }, m.id),
			),
		);

		return c.json(
			mailboxes.map((m, i) => {
				const acl = acls[i];
				return {
					email: m.id,
					acl_status: acl ? "scoped" : "unscoped",
					owner: acl ? acl.owner : null,
					members: acl ? acl.members : [],
				};
			}),
		);
	});

	return {
		fetch(callerEmail: string | null) {
			const hdrs: Record<string, string> = {};
			if (callerEmail) hdrs["cf-access-authenticated-user-email"] = callerEmail;
			return app.request(
				"/api/v1/org/acl-overview",
				{ headers: hdrs },
				{
					BUCKET: bucket as unknown as R2Bucket,
					MAILBOX: MAILBOX as unknown as DurableObjectNamespace,
				},
			);
		},
		bucket,
	};
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const alice = "alice@example.com";
const bob = "bob@example.com";
const charlie = "charlie@other.com";

const aliceMailboxKey = `mailboxes/${alice}.json`;
const aliceAclKey = `mailboxes-acl/${alice}.json`;
const bobMailboxKey = `mailboxes/${bob}.json`;
const bobAclKey = `mailboxes-acl/${bob}.json`;
const charlieMailboxKey = `mailboxes/${charlie}.json`;

const scopedAlice: MailboxAcl = {
	owner: alice,
	members: [alice, bob],
};

const scopedBob: MailboxAcl = {
	owner: bob,
	members: [bob],
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("GET /api/v1/org/acl-overview — authz", () => {
	it("returns 403 when no CF Access email header is present", async () => {
		const { fetch } = makeOverviewApp({ [aliceMailboxKey]: "{}" });
		const res = await fetch(null);
		expect(res.status).toBe(403);
		const body = await res.json() as { error: string };
		expect(body.error).toBeTruthy();
	});

	it("returns 200 for a CF-Access-admitted caller", async () => {
		const { fetch } = makeOverviewApp({ [aliceMailboxKey]: "{}" });
		const res = await fetch("operator@example.com");
		expect(res.status).toBe(200);
	});
});

describe("GET /api/v1/org/acl-overview — empty fleet", () => {
	it("returns an empty array when there are no mailboxes", async () => {
		const { fetch } = makeOverviewApp({});
		const res = await fetch("operator@example.com");
		expect(res.status).toBe(200);
		const body = await res.json() as AclOverviewEntry[];
		expect(body).toEqual([]);
	});
});

describe("GET /api/v1/org/acl-overview — all unscoped fleet", () => {
	it("returns acl_status unscoped with null owner and empty members", async () => {
		const store = { [aliceMailboxKey]: "{}", [bobMailboxKey]: "{}" };
		const { fetch } = makeOverviewApp(store);
		const res = await fetch("operator@example.com");
		expect(res.status).toBe(200);
		const body = await res.json() as AclOverviewEntry[];
		expect(body).toHaveLength(2);
		for (const entry of body) {
			expect(entry.acl_status).toBe("unscoped");
			expect(entry.owner).toBeNull();
			expect(entry.members).toEqual([]);
		}
	});
});

describe("GET /api/v1/org/acl-overview — all scoped fleet", () => {
	it("returns acl_status scoped with correct owner and members", async () => {
		const store = {
			[aliceMailboxKey]: "{}",
			[aliceAclKey]: JSON.stringify(scopedAlice),
			[bobMailboxKey]: "{}",
			[bobAclKey]: JSON.stringify(scopedBob),
		};
		const { fetch } = makeOverviewApp(store);
		const res = await fetch("operator@example.com");
		expect(res.status).toBe(200);
		const body = await res.json() as AclOverviewEntry[];
		expect(body).toHaveLength(2);

		const aliceEntry = body.find((e) => e.email === alice);
		expect(aliceEntry).toBeDefined();
		expect(aliceEntry?.acl_status).toBe("scoped");
		expect(aliceEntry?.owner).toBe(alice);
		expect(aliceEntry?.members).toContain(alice);
		expect(aliceEntry?.members).toContain(bob);

		const bobEntry = body.find((e) => e.email === bob);
		expect(bobEntry).toBeDefined();
		expect(bobEntry?.acl_status).toBe("scoped");
		expect(bobEntry?.owner).toBe(bob);
		expect(bobEntry?.members).toEqual([bob]);
	});
});

describe("GET /api/v1/org/acl-overview — mixed fleet", () => {
	it("returns correct acl_status for scoped and unscoped mailboxes in same response", async () => {
		const store = {
			[aliceMailboxKey]: "{}",
			[aliceAclKey]: JSON.stringify(scopedAlice),
			[bobMailboxKey]: "{}",
			// bob's mailbox has no ACL blob → unscoped
			[charlieMailboxKey]: "{}",
			// charlie's mailbox has no ACL blob → unscoped
		};
		const { fetch } = makeOverviewApp(store);
		const res = await fetch("operator@example.com");
		expect(res.status).toBe(200);
		const body = await res.json() as AclOverviewEntry[];
		expect(body).toHaveLength(3);

		const aliceEntry = body.find((e) => e.email === alice);
		expect(aliceEntry?.acl_status).toBe("scoped");
		expect(aliceEntry?.owner).toBe(alice);
		expect(aliceEntry?.members).toContain(bob);

		const bobEntry = body.find((e) => e.email === bob);
		expect(bobEntry?.acl_status).toBe("unscoped");
		expect(bobEntry?.owner).toBeNull();
		expect(bobEntry?.members).toEqual([]);

		const charlieEntry = body.find((e) => e.email === charlie);
		expect(charlieEntry?.acl_status).toBe("unscoped");
		expect(charlieEntry?.owner).toBeNull();
		expect(charlieEntry?.members).toEqual([]);
	});

	it("includes every mailbox regardless of whether the caller is a member", async () => {
		// operator@example.com is NOT in alice's ACL but still sees all mailboxes
		const store = {
			[aliceMailboxKey]: "{}",
			[aliceAclKey]: JSON.stringify(scopedAlice),
			[bobMailboxKey]: "{}",
		};
		const { fetch } = makeOverviewApp(store);
		const res = await fetch("operator@example.com");
		expect(res.status).toBe(200);
		const body = await res.json() as AclOverviewEntry[];
		// Both alice (scoped) and bob (unscoped) appear even though operator
		// is not a member of alice's ACL.
		expect(body.some((e) => e.email === alice)).toBe(true);
		expect(body.some((e) => e.email === bob)).toBe(true);
	});
});
