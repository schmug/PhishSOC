// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for issue #292: GET /api/v1/org/acl-overview.
 *
 * Uses in-memory R2 stubs and a minimal Hono app — same pattern as
 * tests/routes/mailboxes-acl-status.test.ts.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { readMailboxAcl } from "../../workers/lib/mailbox-acl";
import { listMailboxes } from "../../workers/lib/email-helpers";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";

// ---------------------------------------------------------------------------
// In-memory R2 stub (supports head / get / put / delete / list)
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
// Minimal Hono app replicating GET /api/v1/org/acl-overview from index.ts
// ---------------------------------------------------------------------------

type AclOverviewEntry = {
	email: string;
	acl_status: "scoped" | "unscoped";
	owner: string | null;
	members: string[];
};

function makeOverviewApp(bucketStore: Record<string, string>) {
	const bucket = makeR2Stub(bucketStore);

	const app = new Hono<{ Bindings: { BUCKET: typeof bucket } }>();

	app.get("/api/v1/org/acl-overview", async (c) => {
		const allMailboxes = await listMailboxes(c.env.BUCKET as unknown as R2Bucket);
		const acls = await Promise.all(
			allMailboxes.map((m) => readMailboxAcl(c.env as unknown as { BUCKET: R2Bucket }, m.id)),
		);

		return c.json(
			allMailboxes.map((m, i) => {
				const acl = acls[i];
				return {
					email: m.id,
					acl_status: acl ? "scoped" : "unscoped",
					owner: acl?.owner ?? null,
					members: acl?.members ?? [],
				};
			}),
		);
	});

	return {
		fetch() {
			return app.request(
				"/api/v1/org/acl-overview",
				{},
				{ BUCKET: bucket as unknown as R2Bucket },
			);
		},
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
const bobAclKey = `mailboxes-acl/${bobId}.json`;

const charlieId = "charlie@other.com";
const charlieKey = `mailboxes/${charlieId}.json`;

const aliceAcl: MailboxAcl = {
	owner: "alice@example.com",
	members: ["alice@example.com", "bob@example.com"],
};

// ---------------------------------------------------------------------------
// GET /api/v1/org/acl-overview
// ---------------------------------------------------------------------------

describe("GET /api/v1/org/acl-overview (#292)", () => {
	it("returns an empty array when there are no mailboxes", async () => {
		const { fetch } = makeOverviewApp({});
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as AclOverviewEntry[];
		expect(body).toHaveLength(0);
	});

	it("returns acl_status: unscoped with null owner and empty members for a mailbox with no ACL", async () => {
		const { fetch } = makeOverviewApp({ [aliceKey]: "{}" });
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as AclOverviewEntry[];
		expect(body).toHaveLength(1);
		expect(body[0]).toEqual({
			email: aliceId,
			acl_status: "unscoped",
			owner: null,
			members: [],
		});
	});

	it("returns acl_status: scoped with owner and members for a mailbox that has an ACL", async () => {
		const store = {
			[aliceKey]: "{}",
			[aliceAclKey]: JSON.stringify(aliceAcl),
		};
		const { fetch } = makeOverviewApp(store);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as AclOverviewEntry[];
		expect(body).toHaveLength(1);
		expect(body[0]).toEqual({
			email: aliceId,
			acl_status: "scoped",
			owner: "alice@example.com",
			members: ["alice@example.com", "bob@example.com"],
		});
	});

	it("returns correct mixed fleet: scoped and unscoped mailboxes side by side", async () => {
		const store = {
			[aliceKey]: "{}",
			[aliceAclKey]: JSON.stringify(aliceAcl),
			[bobKey]: "{}",
			// bob has no ACL → unscoped
		};
		const { fetch } = makeOverviewApp(store);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as AclOverviewEntry[];
		expect(body).toHaveLength(2);

		const alice = body.find((e) => e.email === aliceId);
		expect(alice?.acl_status).toBe("scoped");
		expect(alice?.owner).toBe("alice@example.com");
		expect(alice?.members).toContain("bob@example.com");

		const bob = body.find((e) => e.email === bobId);
		expect(bob?.acl_status).toBe("unscoped");
		expect(bob?.owner).toBeNull();
		expect(bob?.members).toHaveLength(0);
	});

	it("returns all mailboxes regardless of caller email (any admitted caller sees the full fleet)", async () => {
		// Endpoint has no per-caller filter — scoped mailboxes appear for everyone.
		const store = {
			[aliceKey]: "{}",
			[aliceAclKey]: JSON.stringify(aliceAcl),
			[charlieKey]: "{}",
		};
		const { fetch } = makeOverviewApp(store);
		// No CF-Access header — simulates dev mode
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as AclOverviewEntry[];
		expect(body).toHaveLength(2);
		// Both alice (scoped) and charlie (unscoped) appear
		const emails = body.map((e) => e.email).sort();
		expect(emails).toEqual([aliceId, charlieId].sort());
	});

	it("includes multiple members correctly", async () => {
		const multiAcl: MailboxAcl = {
			owner: "alice@example.com",
			members: ["alice@example.com", "bob@example.com", "carol@example.com"],
		};
		const store = {
			[aliceKey]: "{}",
			[aliceAclKey]: JSON.stringify(multiAcl),
		};
		const { fetch } = makeOverviewApp(store);
		const res = await fetch();
		const body = await res.json() as AclOverviewEntry[];
		expect(body[0].members).toHaveLength(3);
		expect(body[0].members).toContain("carol@example.com");
	});

	it("backwards-compat: a mailbox added before #27 (no ACL blob) always appears as unscoped", async () => {
		// Three pre-#27 mailboxes, no ACL blobs written for any of them.
		const store = {
			[aliceKey]: "{}",
			[bobKey]: "{}",
			[charlieKey]: "{}",
		};
		const { fetch } = makeOverviewApp(store);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as AclOverviewEntry[];
		expect(body).toHaveLength(3);
		for (const entry of body) {
			expect(entry.acl_status).toBe("unscoped");
			expect(entry.owner).toBeNull();
			expect(entry.members).toHaveLength(0);
		}
	});

	// Suppress unused-import warning for bobAclKey (used implicitly via bucket state).
	it("does not include mailboxes-acl/ keys as mailboxes in the listing", async () => {
		// The R2 prefix scan for mailboxes uses `mailboxes/` prefix, so ACL blobs
		// stored at `mailboxes-acl/` must not appear in the output.
		const store = {
			[aliceKey]: "{}",
			[aliceAclKey]: JSON.stringify(aliceAcl),
		};
		const { fetch } = makeOverviewApp(store);
		const res = await fetch();
		const body = await res.json() as AclOverviewEntry[];
		// Only one mailbox entry, not two (the ACL blob must not leak as a mailbox).
		expect(body).toHaveLength(1);
		void bobAclKey;
	});
});
