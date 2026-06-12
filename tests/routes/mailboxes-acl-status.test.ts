// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for issue #241: acl_status field on GET /api/v1/mailboxes and
 * the POST /api/v1/mailboxes/:id/acl lock-down endpoint.
 *
 * Uses in-memory R2 stubs and minimal Hono apps — same pattern as
 * tests/routes/acl-members.test.ts.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { requireMailbox, type MailboxContext } from "../../workers/lib/mailbox";
import { aclMemberRoutes } from "../../workers/routes/acl-members";
import {
	readMailboxAcl,
	writeMailboxAcl,
	callerInAcl,
	callerEmailFromJwt,
} from "../../workers/lib/mailbox-acl";
import { listMailboxes } from "../../workers/lib/email-helpers";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";

// Helper: build a fake (unsigned) JWT carrying arbitrary claims. Identity is
// decoded from the cf-access-jwt-assertion token (f17), never from the
// cf-access-authenticated-user-email header.
function makeFakeJwt(claims: Record<string, unknown>): string {
	const b64url = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
	return `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify(claims))}.`;
}

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
// Minimal list-endpoint app (replicates GET /api/v1/mailboxes from index.ts)
// ---------------------------------------------------------------------------

function makeListApp(
	bucketStore: Record<string, string>,
	callerEmail: string | null,
	dev = true,
) {
	const bucket = makeR2Stub(bucketStore);
	const MAILBOX = { idFromName: () => "fake-id", get: () => ({}) };

	const app = new Hono<{ Bindings: { BUCKET: typeof bucket; MAILBOX: typeof MAILBOX } }>();

	app.get("/api/v1/mailboxes", async (c) => {
		// Mirror of the production handler in workers/index.ts (f17). Keep in
		// sync: the show-all branch is dev-only; production fails closed for a
		// missing caller email (scoped mailboxes hidden, unscoped still shown).
		const caller = callerEmail;
		const allMailboxes = await listMailboxes(c.env.BUCKET as unknown as R2Bucket);
		const acls = await Promise.all(
			allMailboxes.map((m) => readMailboxAcl(c.env as unknown as { BUCKET: R2Bucket }, m.id)),
		);

		if (!caller && dev) {
			return c.json(
				allMailboxes.map((m, i) => ({
					...m,
					name: m.id,
					acl_status: acls[i] ? "scoped" : "unscoped",
				})),
			);
		}

		const visible = allMailboxes
			.map((m, i) => ({ mailbox: m, acl: acls[i] }))
			.filter(({ acl }) => callerInAcl(acl, caller, [], dev));

		return c.json(
			visible.map(({ mailbox, acl }) => ({
				...mailbox,
				name: mailbox.id,
				acl_status: acl ? "scoped" : "unscoped",
			})),
		);
	});

	return {
		fetch() {
			return app.request(
				"/api/v1/mailboxes",
				{},
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
// Lock-down endpoint app
// ---------------------------------------------------------------------------

function makeLockDownApp(bucketStore: Record<string, string>, callerEmail: string | null) {
	const bucket = makeR2Stub(bucketStore);
	const MAILBOX = { idFromName: () => "fake-id", get: () => ({}) };

	const app = new Hono<MailboxContext>();
	app.use("/api/v1/mailboxes/:mailboxId/*", requireMailbox as Parameters<typeof app.use>[1]);
	app.route("/api/v1/mailboxes/:mailboxId/acl", aclMemberRoutes);

	return {
		post(mailboxId: string) {
			const hdrs: Record<string, string> = {};
			// Caller identity travels in the fake verified JWT (f17).
			if (callerEmail) hdrs["cf-access-jwt-assertion"] = makeFakeJwt({ email: callerEmail });
			return app.request(
				`/api/v1/mailboxes/${mailboxId}/acl`,
				{ method: "POST", headers: hdrs },
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

const mailboxId = "alice@example.com";
const mailboxKey = `mailboxes/${mailboxId}.json`;
const aclKey = `mailboxes-acl/${mailboxId}.json`;

const scopedAcl: MailboxAcl = {
	owner: "alice@example.com",
	members: ["alice@example.com"],
};

// ---------------------------------------------------------------------------
// acl_status on GET /api/v1/mailboxes
// ---------------------------------------------------------------------------

describe("GET /api/v1/mailboxes — acl_status field", () => {
	it("returns acl_status: unscoped for a mailbox with no ACL blob", async () => {
		const { fetch } = makeListApp({ [mailboxKey]: "{}" }, null);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as Array<{ id: string; acl_status: string }>;
		const mailbox = body.find((m) => m.id === mailboxId);
		expect(mailbox).toBeDefined();
		expect(mailbox?.acl_status).toBe("unscoped");
	});

	it("returns acl_status: scoped for a mailbox that has an ACL blob", async () => {
		const { fetch } = makeListApp(
			{ [mailboxKey]: "{}", [aclKey]: JSON.stringify(scopedAcl) },
			null,
		);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as Array<{ id: string; acl_status: string }>;
		const mailbox = body.find((m) => m.id === mailboxId);
		expect(mailbox?.acl_status).toBe("scoped");
	});

	it("includes acl_status when callerEmail is set and filters by ACL", async () => {
		const secondId = "bob@example.com";
		const secondKey = `mailboxes/${secondId}.json`;
		const secondAclKey = `mailboxes-acl/${secondId}.json`;
		// alice has an ACL (visible to alice); bob has no ACL (visible to everyone)
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(scopedAcl),
			[secondKey]: "{}",
			// no ACL for bob's mailbox → unscoped, visible to anyone
		};
		const { fetch } = makeListApp(store, "alice@example.com");
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as Array<{ id: string; acl_status: string }>;
		const aliceMailbox = body.find((m) => m.id === mailboxId);
		const bobMailbox = body.find((m) => m.id === secondId);
		expect(aliceMailbox?.acl_status).toBe("scoped");
		expect(bobMailbox?.acl_status).toBe("unscoped");

		// suppress unused import warning
		void secondAclKey;
	});
});

// ---------------------------------------------------------------------------
// POST /api/v1/mailboxes/:id/acl — lock-down endpoint
// ---------------------------------------------------------------------------

describe("POST /api/v1/mailboxes/:id/acl — lock down", () => {
	it("returns 201 and persists ACL with caller as owner for an unscoped mailbox", async () => {
		const { post, bucket } = makeLockDownApp({ [mailboxKey]: "{}" }, "alice@example.com");
		const res = await post(mailboxId);
		expect(res.status).toBe(201);
		const body = await res.json() as MailboxAcl;
		expect(body.owner).toBe("alice@example.com");
		expect(body.members).toContain("alice@example.com");
		// ACL was actually written to the stub
		const stored = JSON.parse(bucket._store[aclKey]) as MailboxAcl;
		expect(stored.owner).toBe("alice@example.com");
		expect(stored.members).toContain("alice@example.com");
	});

	it("returns 409 when the mailbox already has an ACL", async () => {
		const store = { [mailboxKey]: "{}", [aclKey]: JSON.stringify(scopedAcl) };
		const { post } = makeLockDownApp(store, "alice@example.com");
		const res = await post(mailboxId);
		expect(res.status).toBe(409);
		const body = await res.json() as { error: string };
		expect(body.error).toBeTruthy();
	});

	it("returns 400 when no CF Access email is present (dev mode)", async () => {
		const { post } = makeLockDownApp({ [mailboxKey]: "{}" }, null);
		const res = await post(mailboxId);
		expect(res.status).toBe(400);
	});

	it("returns 404 when the mailbox does not exist", async () => {
		const { post } = makeLockDownApp({}, "alice@example.com");
		const res = await post(mailboxId);
		expect(res.status).toBe(404);
	});

	it("normalises caller email to lower-case in the persisted ACL", async () => {
		const { post, bucket } = makeLockDownApp({ [mailboxKey]: "{}" }, "ALICE@EXAMPLE.COM");
		const res = await post(mailboxId);
		expect(res.status).toBe(201);
		const stored = JSON.parse(bucket._store[aclKey]) as MailboxAcl;
		expect(stored.owner).toBe("alice@example.com");
		expect(stored.members).toContain("alice@example.com");
	});

	it("subsequent GET /api/v1/mailboxes shows acl_status: scoped after lock-down", async () => {
		// Start unscoped
		const store: Record<string, string> = { [mailboxKey]: "{}" };
		const lockDown = makeLockDownApp(store, "alice@example.com");

		// Lock it down
		const lockRes = await lockDown.post(mailboxId);
		expect(lockRes.status).toBe(201);

		// Now query the list — the shared store now has the ACL blob
		const { fetch } = makeListApp(lockDown.bucket._store, "alice@example.com");
		const listRes = await fetch();
		expect(listRes.status).toBe(200);
		const body = await listRes.json() as Array<{ id: string; acl_status: string }>;
		const mailbox = body.find((m) => m.id === mailboxId);
		expect(mailbox?.acl_status).toBe("scoped");
	});
});

// ---------------------------------------------------------------------------
// Bulk lock-down endpoint app (#294)
// ---------------------------------------------------------------------------

function makeBulkLockDownApp(bucketStore: Record<string, string>, callerEmail: string | null) {
	const bucket = makeR2Stub(bucketStore);
	const MAILBOX = { idFromName: () => "fake-id", get: () => ({}) };

	const app = new Hono<{ Bindings: { BUCKET: typeof bucket; MAILBOX: typeof MAILBOX } }>();

	app.post("/api/v1/mailboxes/bulk-lockdown", async (c) => {
		// Mirror of the production handler in workers/index.ts (f17): owner
		// identity from the verified JWT, never the email header. Keep in sync.
		const caller =
			callerEmailFromJwt(c.req.header("cf-access-jwt-assertion"))?.toLowerCase() ?? null;

		if (!caller) {
			return c.json({ error: "CF Access email required" }, 400);
		}

		const allMailboxes = await listMailboxes(c.env.BUCKET as unknown as R2Bucket);
		const acls = await Promise.all(
			allMailboxes.map((m) => readMailboxAcl(c.env as unknown as { BUCKET: R2Bucket }, m.id)),
		);

		const unscoped = allMailboxes.filter((_m, i) => !acls[i]);

		let locked = 0;
		let skipped = 0;
		const errors: string[] = [];

		await Promise.all(
			unscoped.map(async (m) => {
				const existing = await readMailboxAcl(c.env as unknown as { BUCKET: R2Bucket }, m.id);
				if (existing) {
					skipped++;
					return;
				}
				try {
					const acl = { owner: caller, members: [caller] };
					await writeMailboxAcl(c.env as unknown as { BUCKET: R2Bucket }, m.id, acl);
					locked++;
				} catch (err) {
					errors.push(`${m.id}: ${(err as Error)?.message ?? "unknown error"}`);
				}
			}),
		);

		return c.json({ locked, skipped, errors });
	});

	return {
		post(extraHeaders: Record<string, string> = {}) {
			const hdrs: Record<string, string> = { ...extraHeaders };
			// Caller identity travels in the fake verified JWT (f17).
			if (callerEmail) hdrs["cf-access-jwt-assertion"] = makeFakeJwt({ email: callerEmail });
			return app.request(
				"/api/v1/mailboxes/bulk-lockdown",
				{ method: "POST", headers: hdrs },
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
// POST /api/v1/mailboxes/bulk-lockdown (#294)
// ---------------------------------------------------------------------------

describe("POST /api/v1/mailboxes/bulk-lockdown (#294)", () => {
	const aliceKey = `mailboxes/alice@example.com.json`;
	const aliceAclKey = `mailboxes-acl/alice@example.com.json`;
	const bobKey = `mailboxes/bob@example.com.json`;
	const bobAclKey = `mailboxes-acl/bob@example.com.json`;
	const charlieKey = `mailboxes/charlie@example.com.json`;

	it("locks all unscoped mailboxes in a mixed fleet", async () => {
		// alice is already scoped; bob and charlie are unscoped
		const aliceAcl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		const store = {
			[aliceKey]: "{}",
			[aliceAclKey]: JSON.stringify(aliceAcl),
			[bobKey]: "{}",
			[charlieKey]: "{}",
		};
		const { post, bucket } = makeBulkLockDownApp(store, "operator@example.com");
		const res = await post();
		expect(res.status).toBe(200);
		const body = await res.json() as { locked: number; skipped: number; errors: string[] };
		expect(body.locked).toBe(2);
		expect(body.skipped).toBe(0);
		expect(body.errors).toHaveLength(0);

		// bob and charlie now have ACLs with operator as owner
		const storedBob = JSON.parse(bucket._store[bobAclKey]) as MailboxAcl;
		expect(storedBob.owner).toBe("operator@example.com");
		expect(storedBob.members).toContain("operator@example.com");
		const charlieAclKey = `mailboxes-acl/charlie@example.com.json`;
		const storedCharlie = JSON.parse(bucket._store[charlieAclKey]) as MailboxAcl;
		expect(storedCharlie.owner).toBe("operator@example.com");
	});

	it("returns 0 locked, 0 skipped when all mailboxes are already scoped", async () => {
		const aliceAcl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		const store = {
			[aliceKey]: "{}",
			[aliceAclKey]: JSON.stringify(aliceAcl),
		};
		const { post } = makeBulkLockDownApp(store, "operator@example.com");
		const res = await post();
		expect(res.status).toBe(200);
		const body = await res.json() as { locked: number; skipped: number; errors: string[] };
		expect(body.locked).toBe(0);
		expect(body.skipped).toBe(0);
		expect(body.errors).toHaveLength(0);
	});

	it("returns 0/0 when there are no mailboxes at all", async () => {
		const { post } = makeBulkLockDownApp({}, "operator@example.com");
		const res = await post();
		expect(res.status).toBe(200);
		const body = await res.json() as { locked: number; skipped: number; errors: string[] };
		expect(body.locked).toBe(0);
		expect(body.skipped).toBe(0);
		expect(body.errors).toHaveLength(0);
	});

	it("after bulk lock-down, GET /api/v1/mailboxes shows all as scoped", async () => {
		const store: Record<string, string> = { [aliceKey]: "{}", [bobKey]: "{}" };
		const { post, bucket } = makeBulkLockDownApp(store, "operator@example.com");
		const lockRes = await post();
		expect(lockRes.status).toBe(200);
		const lockBody = await lockRes.json() as { locked: number };
		expect(lockBody.locked).toBe(2);

		const { fetch } = makeListApp(bucket._store, null);
		const listRes = await fetch();
		expect(listRes.status).toBe(200);
		const listBody = await listRes.json() as Array<{ id: string; acl_status: string }>;
		for (const m of listBody) {
			expect(m.acl_status).toBe("scoped");
		}
	});

	it("returns 400 when no CF Access email is present", async () => {
		const store = { [aliceKey]: "{}" };
		const { post } = makeBulkLockDownApp(store, null);
		const res = await post();
		expect(res.status).toBe(400);
	});

	it("does not abort when a mailbox is already scoped (partial-success idempotence)", async () => {
		// alice is already scoped; only bob is unscoped → 1 locked, 0 skipped
		const aliceAcl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		const store = {
			[aliceKey]: "{}",
			[aliceAclKey]: JSON.stringify(aliceAcl),
			[bobKey]: "{}",
		};
		const { post } = makeBulkLockDownApp(store, "operator@example.com");
		const res = await post();
		expect(res.status).toBe(200);
		const body = await res.json() as { locked: number; skipped: number; errors: string[] };
		expect(body.locked).toBe(1);
		expect(body.errors).toHaveLength(0);
	});
});

// ---------------------------------------------------------------------------
// f17 — fail-closed listing and JWT-derived bulk lock-down owner
// ---------------------------------------------------------------------------

describe("GET /api/v1/mailboxes — fail-closed in production (f17)", () => {
	const aliceKey = `mailboxes/alice@example.com.json`;
	const aliceAclKey = `mailboxes-acl/alice@example.com.json`;
	const bobKey = `mailboxes/bob@example.com.json`;
	const aliceAcl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };

	it("hides scoped mailboxes (but keeps unscoped) when no caller email exists in production", async () => {
		const store = {
			[aliceKey]: "{}",
			[aliceAclKey]: JSON.stringify(aliceAcl),
			[bobKey]: "{}", // unscoped — backwards-compat, stays visible
		};
		const { fetch } = makeListApp(store, null, /* dev */ false);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as Array<{ id: string }>;
		expect(body.map((m) => m.id)).toEqual(["bob@example.com"]);
	});

	it("still shows everything for a null caller in dev mode", async () => {
		const store = {
			[aliceKey]: "{}",
			[aliceAclKey]: JSON.stringify(aliceAcl),
			[bobKey]: "{}",
		};
		const { fetch } = makeListApp(store, null, /* dev */ true);
		const res = await fetch();
		const body = await res.json() as Array<{ id: string }>;
		expect(body).toHaveLength(2);
	});
});

describe("POST /api/v1/mailboxes/bulk-lockdown — owner from the verified JWT (f17)", () => {
	const aliceKey = `mailboxes/alice@example.com.json`;
	const aliceAclKey = `mailboxes-acl/alice@example.com.json`;

	it("a forged cf-access-authenticated-user-email header cannot seed ownership", async () => {
		const store = { [aliceKey]: "{}" };
		const { post, bucket } = makeBulkLockDownApp(store, null);
		// Forged header, no JWT email → 400, nothing written.
		const res = await post({ "cf-access-authenticated-user-email": "mallory@example.com" });
		expect(res.status).toBe(400);
		expect(bucket._store[aliceAclKey]).toBeUndefined();
	});

	it("owner comes from the JWT email even when a different header is forged", async () => {
		const store = { [aliceKey]: "{}" };
		const { post, bucket } = makeBulkLockDownApp(store, "operator@example.com");
		const res = await post({ "cf-access-authenticated-user-email": "mallory@example.com" });
		expect(res.status).toBe(200);
		const stored = JSON.parse(bucket._store[aliceAclKey]) as MailboxAcl;
		expect(stored.owner).toBe("operator@example.com");
		expect(stored.members).not.toContain("mallory@example.com");
	});
});
