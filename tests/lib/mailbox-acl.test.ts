// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { callerInAcl, callerGroupsFromJwt, readMailboxAcl, writeMailboxAcl, deleteMailboxAcl } from "../../workers/lib/mailbox-acl";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";
import { requireMailbox } from "../../workers/lib/mailbox";

// Helper: build a fake (unsigned) JWT carrying the given groups claim.
// decodeJwt from jose just base64url-decodes the payload — no sig check needed.
function makeFakeGroupJwt(groups: string[]): string {
	const b64url = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
	const header = b64url('{"alg":"none"}');
	const payload = b64url(JSON.stringify({ groups }));
	return `${header}.${payload}.`;
}

// ---------------------------------------------------------------------------
// callerInAcl — pure function, no mocking needed
// ---------------------------------------------------------------------------

describe("callerInAcl", () => {
	it("returns true when acl is null (backwards-compat, no ACL written yet)", () => {
		expect(callerInAcl(null, "alice@example.com")).toBe(true);
		expect(callerInAcl(null, null)).toBe(true);
	});

	it("returns true when callerEmail is falsy (dev mode, no Access in front)", () => {
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		expect(callerInAcl(acl, null)).toBe(true);
		expect(callerInAcl(acl, "")).toBe(true);
		expect(callerInAcl(acl, undefined)).toBe(true);
	});

	it("returns true when caller is in members list", () => {
		const acl: MailboxAcl = {
			owner: "alice@example.com",
			members: ["alice@example.com", "bob@example.com"],
		};
		expect(callerInAcl(acl, "alice@example.com")).toBe(true);
		expect(callerInAcl(acl, "bob@example.com")).toBe(true);
	});

	it("returns false when caller is not in members list", () => {
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		expect(callerInAcl(acl, "eve@example.com")).toBe(false);
	});

	it("comparison is case-insensitive", () => {
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		expect(callerInAcl(acl, "ALICE@EXAMPLE.COM")).toBe(true);
		expect(callerInAcl(acl, "Alice@Example.Com")).toBe(true);
		expect(callerInAcl(acl, "EVE@EXAMPLE.COM")).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// readMailboxAcl / writeMailboxAcl / deleteMailboxAcl — in-memory R2 stub
// ---------------------------------------------------------------------------

function makeR2Stub(initial: Record<string, string> = {}) {
	const store = { ...initial };
	return {
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
		_store: store,
	};
}

describe("readMailboxAcl", () => {
	it("returns null when no ACL blob exists", async () => {
		const bucket = makeR2Stub();
		const result = await readMailboxAcl({ BUCKET: bucket as unknown as R2Bucket }, "user@example.com");
		expect(result).toBeNull();
	});

	it("returns the parsed ACL when present", async () => {
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		const bucket = makeR2Stub({
			"mailboxes-acl/user@example.com.json": JSON.stringify(acl),
		});
		const result = await readMailboxAcl({ BUCKET: bucket as unknown as R2Bucket }, "user@example.com");
		expect(result).toEqual(acl);
	});

	it("returns null when the blob is malformed JSON", async () => {
		const bucket = makeR2Stub({ "mailboxes-acl/user@example.com.json": "not-json" });
		const result = await readMailboxAcl({ BUCKET: bucket as unknown as R2Bucket }, "user@example.com");
		expect(result).toBeNull();
	});
});

describe("writeMailboxAcl + deleteMailboxAcl", () => {
	it("writes then reads back the ACL", async () => {
		const bucket = makeR2Stub();
		const env = { BUCKET: bucket as unknown as R2Bucket };
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		await writeMailboxAcl(env, "alice@example.com", acl);
		const read = await readMailboxAcl(env, "alice@example.com");
		expect(read).toEqual(acl);
	});

	it("deleteMailboxAcl removes the blob so readMailboxAcl returns null", async () => {
		const bucket = makeR2Stub();
		const env = { BUCKET: bucket as unknown as R2Bucket };
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		await writeMailboxAcl(env, "alice@example.com", acl);
		await deleteMailboxAcl(env, "alice@example.com");
		const read = await readMailboxAcl(env, "alice@example.com");
		expect(read).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// requireMailbox — inline Hono app with stub R2 + DO namespace
// ---------------------------------------------------------------------------

function makeFullR2Stub(initial: Record<string, string> = {}) {
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
	};
}

function makeFakeMailboxApp(
	bucketStore: Record<string, string>,
	callerEmail: string | null,
) {
	const bucket = makeFullR2Stub(bucketStore);
	// Minimal DO namespace stub — just needs idFromName / get
	const mailboxStub = { id: "fake-do-id" };
	const MAILBOX = {
		idFromName: (_name: string) => "fake-id",
		get: (_id: unknown) => mailboxStub,
	};

	const app = new Hono<{ Bindings: { BUCKET: typeof bucket; MAILBOX: typeof MAILBOX } }>();

	app.use("/mailboxes/:mailboxId/*", requireMailbox as Parameters<typeof app.use>[1]);

	app.get("/mailboxes/:mailboxId/test", (c) => c.json({ ok: true }));

	return {
		fetch: (path: string) => {
			const headers: Record<string, string> = {};
			if (callerEmail) headers["cf-access-authenticated-user-email"] = callerEmail;
			return app.request(path, { headers }, { BUCKET: bucket as unknown as R2Bucket, MAILBOX: MAILBOX as unknown as DurableObjectNamespace });
		},
	};
}

describe("requireMailbox — ACL enforcement", () => {
	const mailboxKey = "mailboxes/alice@example.com.json";
	const aclKey = "mailboxes-acl/alice@example.com.json";
	const aliceAcl: MailboxAcl = {
		owner: "alice@example.com",
		members: ["alice@example.com"],
	};

	it("returns 404 when mailbox does not exist", async () => {
		const app = makeFakeMailboxApp({}, "alice@example.com");
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(404);
	});

	it("allows access when no ACL is set (backwards-compat)", async () => {
		const store = { [mailboxKey]: "{}" };
		const app = makeFakeMailboxApp(store, "anyone@example.com");
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(200);
	});

	it("allows access when callerEmail matches ACL", async () => {
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const app = makeFakeMailboxApp(store, "alice@example.com");
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(200);
	});

	it("returns 403 when callerEmail is not in ACL", async () => {
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const app = makeFakeMailboxApp(store, "eve@example.com");
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(403);
	});

	it("allows access in dev mode (no callerEmail) regardless of ACL", async () => {
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const app = makeFakeMailboxApp(store, null);
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(200);
	});

	it("ACL comparison is case-insensitive", async () => {
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const app = makeFakeMailboxApp(store, "ALICE@EXAMPLE.COM");
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(200);
	});
});

// ---------------------------------------------------------------------------
// callerInAcl — group-grant tests (#295)
// ---------------------------------------------------------------------------

describe("callerInAcl — group grants (#295)", () => {
	const aclWithGroups: MailboxAcl = {
		owner: "alice@example.com",
		members: ["alice@example.com"],
		groups: ["soc-analysts"],
	};

	it("grants access to a caller whose group is in acl.groups", () => {
		expect(callerInAcl(aclWithGroups, "bob@example.com", ["soc-analysts"])).toBe(true);
	});

	it("denies access to a caller not in members and not in any granted group", () => {
		expect(callerInAcl(aclWithGroups, "eve@example.com", ["other-group"])).toBe(false);
		expect(callerInAcl(aclWithGroups, "eve@example.com", [])).toBe(false);
	});

	it("email membership still works unchanged when groups are also present", () => {
		expect(callerInAcl(aclWithGroups, "alice@example.com", [])).toBe(true);
	});

	it("no-ACL backwards-compat path still allows anyone", () => {
		expect(callerInAcl(null, "bob@example.com", ["soc-analysts"])).toBe(true);
	});

	it("email-only ACL (no groups field) denies a caller not in members", () => {
		const emailOnly: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		expect(callerInAcl(emailOnly, "bob@example.com", ["soc-analysts"])).toBe(false);
	});

	it("empty groups array on ACL denies group callers", () => {
		const emptyGroups: MailboxAcl = {
			owner: "alice@example.com",
			members: ["alice@example.com"],
			groups: [],
		};
		expect(callerInAcl(emptyGroups, "bob@example.com", ["soc-analysts"])).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// callerGroupsFromJwt (#295)
// ---------------------------------------------------------------------------

describe("callerGroupsFromJwt (#295)", () => {
	it("returns [] for null/undefined/empty token", () => {
		expect(callerGroupsFromJwt(null)).toEqual([]);
		expect(callerGroupsFromJwt(undefined)).toEqual([]);
		expect(callerGroupsFromJwt("")).toEqual([]);
	});

	it("returns [] for a malformed token", () => {
		expect(callerGroupsFromJwt("not.a.jwt")).toEqual([]);
		expect(callerGroupsFromJwt("bad")).toEqual([]);
	});

	it("returns groups from a valid fake JWT", () => {
		const jwt = makeFakeGroupJwt(["soc-analysts", "admins"]);
		expect(callerGroupsFromJwt(jwt)).toEqual(["soc-analysts", "admins"]);
	});

	it("returns [] when JWT payload has no groups claim", () => {
		const jwt = makeFakeGroupJwt([]);
		expect(callerGroupsFromJwt(jwt)).toEqual([]);
	});

	it("filters out non-string group entries", () => {
		const b64url = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
		const header = b64url('{"alg":"none"}');
		const payload = b64url(JSON.stringify({ groups: ["soc", 42, null, "admins"] }));
		const jwt = `${header}.${payload}.`;
		expect(callerGroupsFromJwt(jwt)).toEqual(["soc", "admins"]);
	});
});

// ---------------------------------------------------------------------------
// requireMailbox — group-grant integration (#295)
// ---------------------------------------------------------------------------

function makeFakeMailboxAppWithJwt(
	bucketStore: Record<string, string>,
	callerEmail: string | null,
	jwtToken: string | null = null,
) {
	const bucket = makeFullR2Stub(bucketStore);
	const mailboxStub = { id: "fake-do-id" };
	const MAILBOX = {
		idFromName: (_name: string) => "fake-id",
		get: (_id: unknown) => mailboxStub,
	};

	const app = new Hono<{ Bindings: { BUCKET: typeof bucket; MAILBOX: typeof MAILBOX } }>();
	app.use("/mailboxes/:mailboxId/*", requireMailbox as Parameters<typeof app.use>[1]);
	app.get("/mailboxes/:mailboxId/test", (c) => c.json({ ok: true }));

	return {
		fetch: (path: string) => {
			const headers: Record<string, string> = {};
			if (callerEmail) headers["cf-access-authenticated-user-email"] = callerEmail;
			if (jwtToken) headers["cf-access-jwt-assertion"] = jwtToken;
			return app.request(
				path,
				{ headers },
				{ BUCKET: bucket as unknown as R2Bucket, MAILBOX: MAILBOX as unknown as DurableObjectNamespace },
			);
		},
	};
}

describe("requireMailbox — group-grant ACL (#295)", () => {
	const mailboxKey = "mailboxes/alice@example.com.json";
	const aclKey = "mailboxes-acl/alice@example.com.json";
	const groupAcl: MailboxAcl = {
		owner: "alice@example.com",
		members: ["alice@example.com"],
		groups: ["soc-analysts"],
	};

	it("allows a caller in a granted group (group membership from JWT)", async () => {
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(groupAcl),
		};
		const jwt = makeFakeGroupJwt(["soc-analysts"]);
		const app = makeFakeMailboxAppWithJwt(store, "bob@example.com", jwt);
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(200);
	});

	it("denies a caller not in members and not in any granted group", async () => {
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(groupAcl),
		};
		const jwt = makeFakeGroupJwt(["other-team"]);
		const app = makeFakeMailboxAppWithJwt(store, "eve@example.com", jwt);
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(403);
	});

	it("denies a caller with no JWT and not in members", async () => {
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(groupAcl),
		};
		const app = makeFakeMailboxAppWithJwt(store, "eve@example.com", null);
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(403);
	});
});
