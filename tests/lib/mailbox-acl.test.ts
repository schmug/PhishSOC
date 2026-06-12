// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Hono } from "hono";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	callerInAcl,
	callerGroupsFromJwt,
	callerEmailFromJwt,
	callerAllowedForMailbox,
	emailAgentMailboxIdFromPath,
	readMailboxAcl,
	writeMailboxAcl,
	deleteMailboxAcl,
} from "../../workers/lib/mailbox-acl";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";
import { requireMailbox } from "../../workers/lib/mailbox";

// Helper: build a fake (unsigned) JWT carrying arbitrary claims (email/groups).
// decodeJwt from jose just base64url-decodes the payload — no sig check needed.
function makeFakeJwt(claims: Record<string, unknown>): string {
	const b64url = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
	return `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify(claims))}.`;
}

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

	it("FAILS CLOSED on a falsy callerEmail in production (f17)", () => {
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		// Default isDev = false → production semantics: deny.
		expect(callerInAcl(acl, null)).toBe(false);
		expect(callerInAcl(acl, "")).toBe(false);
		expect(callerInAcl(acl, undefined)).toBe(false);
		expect(callerInAcl(acl, null, [], false)).toBe(false);
	});

	it("allows a falsy callerEmail only in dev mode (isDev = true, no Access in front)", () => {
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		expect(callerInAcl(acl, null, [], true)).toBe(true);
		expect(callerInAcl(acl, "", [], true)).toBe(true);
		expect(callerInAcl(acl, undefined, [], true)).toBe(true);
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
		// Identity travels in the fake CF Access JWT (f17) — requireMailbox no
		// longer reads the cf-access-authenticated-user-email header. Extra
		// headers (e.g. a forged email header) can be layered on top.
		fetch: (path: string, extraHeaders: Record<string, string> = {}) => {
			const headers: Record<string, string> = { ...extraHeaders };
			if (callerEmail) headers["cf-access-jwt-assertion"] = makeFakeJwt({ email: callerEmail });
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
		vi.stubEnv("DEV", true);
		try {
			const store = {
				[mailboxKey]: "{}",
				[aclKey]: JSON.stringify(aliceAcl),
			};
			const app = makeFakeMailboxApp(store, null);
			const res = await app.fetch("/mailboxes/alice@example.com/test");
			expect(res.status).toBe(200);
		} finally {
			vi.unstubAllEnvs();
		}
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
// requireMailbox — identity from the verified JWT, fail closed in prod (f17)
// ---------------------------------------------------------------------------

describe("requireMailbox — verified-JWT identity, fail-closed (f17)", () => {
	const mailboxKey = "mailboxes/alice@example.com.json";
	const aclKey = "mailboxes-acl/alice@example.com.json";
	const aliceAcl: MailboxAcl = {
		owner: "alice@example.com",
		members: ["alice@example.com"],
	};
	const scopedStore = () => ({
		[mailboxKey]: "{}",
		[aclKey]: JSON.stringify(aliceAcl),
	});

	afterEach(() => {
		vi.unstubAllEnvs();
	});

	it("DENIES in production when the JWT carries no email and an ACL exists (was fail-open)", async () => {
		vi.stubEnv("DEV", false);
		// Valid (middleware-verified) JWT, but no email claim — e.g. a service
		// token, or a caller that stripped the identity.
		const app = makeFakeMailboxApp(scopedStore(), null);
		const res = await app.fetch("/mailboxes/alice@example.com/test", {
			"cf-access-jwt-assertion": makeFakeJwt({ common_name: "svc-token" }),
		});
		expect(res.status).toBe(403);
	});

	it("DENIES in production when no JWT is present at all and an ACL exists", async () => {
		vi.stubEnv("DEV", false);
		const app = makeFakeMailboxApp(scopedStore(), null);
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(403);
	});

	it("ignores a forged cf-access-authenticated-user-email header when the JWT email differs", async () => {
		// Eve's JWT says eve@; the forged header claims the victim's identity.
		const app = makeFakeMailboxApp(scopedStore(), "eve@example.com");
		const res = await app.fetch("/mailboxes/alice@example.com/test", {
			"cf-access-authenticated-user-email": "alice@example.com",
		});
		expect(res.status).toBe(403);
	});

	it("ignores a forged cf-access-authenticated-user-email header when the JWT has no email (prod)", async () => {
		vi.stubEnv("DEV", false);
		const app = makeFakeMailboxApp(scopedStore(), null);
		const res = await app.fetch("/mailboxes/alice@example.com/test", {
			"cf-access-authenticated-user-email": "alice@example.com",
			"cf-access-jwt-assertion": makeFakeJwt({ common_name: "svc-token" }),
		});
		expect(res.status).toBe(403);
	});

	it("still allows anyone in production when no ACL exists (backwards-compat)", async () => {
		vi.stubEnv("DEV", false);
		const app = makeFakeMailboxApp({ [mailboxKey]: "{}" }, null);
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(200);
	});

	it("still allows in dev mode when no email can be derived (no CF Access in front)", async () => {
		vi.stubEnv("DEV", true);
		const app = makeFakeMailboxApp(scopedStore(), null);
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(200);
	});

	it("allows an ACL member identified by the verified-JWT email claim", async () => {
		vi.stubEnv("DEV", false);
		const app = makeFakeMailboxApp(scopedStore(), "alice@example.com");
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

	afterEach(() => {
		vi.unstubAllEnvs();
	});

	it("allows a caller in a granted group (email + group membership from JWT)", async () => {
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(groupAcl),
		};
		const jwt = makeFakeJwt({ email: "bob@example.com", groups: ["soc-analysts"] });
		const app = makeFakeMailboxAppWithJwt(store, jwt);
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(200);
	});

	it("denies a caller not in members and not in any granted group", async () => {
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(groupAcl),
		};
		const jwt = makeFakeJwt({ email: "eve@example.com", groups: ["other-team"] });
		const app = makeFakeMailboxAppWithJwt(store, jwt);
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(403);
	});

	it("denies a caller with no JWT in production", async () => {
		vi.stubEnv("DEV", false);
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(groupAcl),
		};
		const app = makeFakeMailboxAppWithJwt(store, null);
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(403);
	});
});

// ---------------------------------------------------------------------------
// callerEmailFromJwt — identity from the verified token, never a header (f17)
// ---------------------------------------------------------------------------

describe("callerEmailFromJwt", () => {
	it("returns null for absent/malformed tokens", () => {
		expect(callerEmailFromJwt(null)).toBeNull();
		expect(callerEmailFromJwt(undefined)).toBeNull();
		expect(callerEmailFromJwt("")).toBeNull();
		expect(callerEmailFromJwt("not.a.jwt")).toBeNull();
	});

	it("returns the email claim from a valid token", () => {
		expect(callerEmailFromJwt(makeFakeJwt({ email: "alice@example.com" }))).toBe("alice@example.com");
	});

	it("returns null when the token has no email claim (e.g. a service token)", () => {
		expect(callerEmailFromJwt(makeFakeJwt({ common_name: "svc-token" }))).toBeNull();
		expect(callerEmailFromJwt(makeFakeJwt({ groups: ["soc-analysts"] }))).toBeNull();
	});

	it("returns null for a non-string or empty email claim", () => {
		expect(callerEmailFromJwt(makeFakeJwt({ email: 42 }))).toBeNull();
		expect(callerEmailFromJwt(makeFakeJwt({ email: "" }))).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// emailAgentMailboxIdFromPath — only the per-mailbox EmailAgent path (f15)
// ---------------------------------------------------------------------------

describe("emailAgentMailboxIdFromPath", () => {
	it("extracts the mailboxId from an EmailAgent path", () => {
		expect(emailAgentMailboxIdFromPath("/agents/email-agent/alice@example.com")).toBe("alice@example.com");
	});

	it("extracts it for deeper sub-paths (chat / websocket endpoints)", () => {
		expect(emailAgentMailboxIdFromPath("/agents/email-agent/alice@example.com/get-messages")).toBe(
			"alice@example.com",
		);
	});

	it("URL-decodes the mailboxId segment", () => {
		expect(emailAgentMailboxIdFromPath("/agents/email-agent/alice%40example.com")).toBe("alice@example.com");
	});

	it("returns null for OrgAgent and other agents (not gated here)", () => {
		expect(emailAgentMailboxIdFromPath("/agents/org-agent/default")).toBeNull();
	});

	it("returns null for non-agent or incomplete paths", () => {
		expect(emailAgentMailboxIdFromPath("/api/v1/mailboxes/alice@example.com/emails")).toBeNull();
		expect(emailAgentMailboxIdFromPath("/agents/email-agent")).toBeNull();
		expect(emailAgentMailboxIdFromPath("/agents")).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// callerAllowedForMailbox — agent-path ACL core, fail-closed in prod (f15/f17)
// ---------------------------------------------------------------------------

describe("callerAllowedForMailbox", () => {
	const mailboxId = "alice@example.com";
	const aclKey = `mailboxes-acl/${mailboxId}.json`;
	const aliceAcl: MailboxAcl = { owner: mailboxId, members: [mailboxId], groups: ["soc-analysts"] };
	const env = (store: Record<string, string>) => ({ BUCKET: makeR2Stub(store) as unknown as R2Bucket });

	it("allows when no ACL blob exists (backwards-compat)", async () => {
		expect(await callerAllowedForMailbox(env({}), mailboxId, makeFakeJwt({ email: "eve@evil.com" }), false)).toBe(
			true,
		);
	});

	it("allows a member identified by the verified-JWT email", async () => {
		const e = env({ [aclKey]: JSON.stringify(aliceAcl) });
		expect(await callerAllowedForMailbox(e, mailboxId, makeFakeJwt({ email: mailboxId }), false)).toBe(true);
	});

	it("allows a caller in a granted group (groups from the JWT)", async () => {
		const e = env({ [aclKey]: JSON.stringify(aliceAcl) });
		expect(
			await callerAllowedForMailbox(e, mailboxId, makeFakeJwt({ email: "bob@example.com", groups: ["soc-analysts"] }), false),
		).toBe(true);
	});

	it("DENIES a non-member teammate (the f15 cross-tenant bypass)", async () => {
		const e = env({ [aclKey]: JSON.stringify(aliceAcl) });
		expect(await callerAllowedForMailbox(e, mailboxId, makeFakeJwt({ email: "eve@example.com" }), false)).toBe(false);
	});

	it("DENIES (fail-closed) in prod when the JWT carries no email — e.g. a service token", async () => {
		const e = env({ [aclKey]: JSON.stringify(aliceAcl) });
		expect(await callerAllowedForMailbox(e, mailboxId, makeFakeJwt({ common_name: "svc" }), false)).toBe(false);
		expect(await callerAllowedForMailbox(e, mailboxId, null, false)).toBe(false);
	});

	it("ignores a forged email header — identity comes only from the JWT", async () => {
		// No JWT email claim → denied, even though a caller could set any
		// cf-access-authenticated-user-email header on a direct-origin request.
		const e = env({ [aclKey]: JSON.stringify(aliceAcl) });
		expect(await callerAllowedForMailbox(e, mailboxId, makeFakeJwt({}), false)).toBe(false);
	});

	it("allows in dev mode (no CF Access in front) regardless of ACL", async () => {
		const e = env({ [aclKey]: JSON.stringify(aliceAcl) });
		expect(await callerAllowedForMailbox(e, mailboxId, null, true)).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Agent-route gate — wires emailAgentMailboxIdFromPath + callerAllowedForMailbox
// the same way workers/app.ts does, asserting the 403 the route returns (f15).
// ---------------------------------------------------------------------------

describe("agent-route ACL gate (f15)", () => {
	const mailboxId = "alice@example.com";
	const aclKey = `mailboxes-acl/${mailboxId}.json`;
	const aliceAcl: MailboxAcl = { owner: mailboxId, members: [mailboxId] };

	function makeAgentGateApp(store: Record<string, string>, jwt: string | null) {
		const bucket = makeR2Stub(store);
		const app = new Hono<{ Bindings: { BUCKET: typeof bucket } }>();
		// Mirror of the workers/app.ts "/agents/*" handler (isDev=false → prod).
		app.all("/agents/*", async (c) => {
			const id = emailAgentMailboxIdFromPath(new URL(c.req.url).pathname);
			if (id) {
				const allowed = await callerAllowedForMailbox(c.env, id, c.req.header("cf-access-jwt-assertion"), false);
				if (!allowed) return c.json({ error: "Forbidden" }, 403);
			}
			return c.json({ routed: true }); // stand-in for routeAgentRequest
		});
		return {
			fetch: (path: string) => {
				const headers: Record<string, string> = {};
				if (jwt) headers["cf-access-jwt-assertion"] = jwt;
				return app.request(path, { headers }, { BUCKET: bucket as unknown as R2Bucket });
			},
		};
	}

	it("returns 403 for a teammate not in the mailbox ACL (cross-tenant bypass closed)", async () => {
		const app = makeAgentGateApp({ [aclKey]: JSON.stringify(aliceAcl) }, makeFakeJwt({ email: "eve@example.com" }));
		const res = await app.fetch("/agents/email-agent/alice@example.com");
		expect(res.status).toBe(403);
	});

	it("returns 403 when the JWT has no email claim (header-strip / service token)", async () => {
		const app = makeAgentGateApp({ [aclKey]: JSON.stringify(aliceAcl) }, makeFakeJwt({ common_name: "svc" }));
		const res = await app.fetch("/agents/email-agent/alice@example.com");
		expect(res.status).toBe(403);
	});

	it("allows a member through the gate", async () => {
		const app = makeAgentGateApp({ [aclKey]: JSON.stringify(aliceAcl) }, makeFakeJwt({ email: mailboxId }));
		const res = await app.fetch("/agents/email-agent/alice@example.com");
		expect(res.status).toBe(200);
	});

	it("does not gate the OrgAgent path", async () => {
		const app = makeAgentGateApp({ [aclKey]: JSON.stringify(aliceAcl) }, makeFakeJwt({ email: "eve@example.com" }));
		const res = await app.fetch("/agents/org-agent/default");
		expect(res.status).toBe(200);
	});
});
