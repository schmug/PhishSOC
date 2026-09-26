// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";
import { encodeCursor } from "../../workers/lib/unified-inbox";
import { unifiedInboxRoutes } from "../../workers/routes/unified-inbox";

// Unsigned JWT carrying claims — identity is decoded from cf-access-jwt-assertion (f17).
function makeFakeJwt(claims: Record<string, unknown>): string {
	const b64url = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
	return `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify(claims))}.`;
}

function makeR2Stub(initial: Record<string, string>, throwOn: Set<string> = new Set()) {
	const store = { ...initial };
	return {
		async get(key: string) {
			if (throwOn.has(key)) throw new Error("r2 down");
			const val = store[key];
			if (val === undefined) return null;
			return { json: async <T>() => JSON.parse(val) as T };
		},
		async put(key: string, value: string) {
			store[key] = value;
		},
		async list({ prefix }: { prefix: string }) {
			return { objects: Object.keys(store).filter((k) => k.startsWith(prefix)).map((key) => ({ key })) };
		},
	};
}

type Row = { id: string; date: string; subject: string };
type Stub = { getThreadedEmails: ReturnType<typeof vi.fn> };

function stubReturning(rows: Row[]): Stub {
	return { getThreadedEmails: vi.fn(async ({ limit }: { limit: number }) => rows.slice(0, limit)) };
}

function makeApp(bucket: ReturnType<typeof makeR2Stub>, stubs: Record<string, Stub>) {
	const MAILBOX = { idFromName: (name: string) => name, get: (id: string) => stubs[id] };
	const app = new Hono();
	app.route("/api/v1/inbox", unifiedInboxRoutes as unknown as Hono);
	return (path: string, caller = "alice@corp.test") =>
		app.request(path, { headers: { "cf-access-jwt-assertion": makeFakeJwt({ email: caller }) } }, {
			BUCKET: bucket,
			MAILBOX,
		});
}

const ALICE_ACL = JSON.stringify({ owner: "alice@corp.test", members: ["alice@corp.test"] });
const BOB_ACL = JSON.stringify({ owner: "bob@corp.test", members: ["bob@corp.test"] });

function baseStore(): Record<string, string> {
	return {
		"mailboxes/ops@a.test.json": JSON.stringify({}),
		"mailboxes/ops@b.test.json": JSON.stringify({}),
		"mailboxes/pot@a.test.json": JSON.stringify({ honeypot: { enabled: true } }),
		"mailboxes/quiet@b.test.json": JSON.stringify({ hideFromAllInboxes: true }),
		"mailboxes/bob@b.test.json": JSON.stringify({}),
		"mailboxes-acl/ops@a.test.json": ALICE_ACL,
		"mailboxes-acl/bob@b.test.json": BOB_ACL,
	};
}

function baseStubs(): Record<string, Stub> {
	return {
		"ops@a.test": stubReturning([{ id: "a1", date: "2026-09-01T10:00:00.000Z", subject: "A" }]),
		"ops@b.test": stubReturning([{ id: "b1", date: "2026-09-01T12:00:00.000Z", subject: "B" }]),
		"pot@a.test": stubReturning([{ id: "p1", date: "2026-09-02T00:00:00.000Z", subject: "lure" }]),
		"quiet@b.test": stubReturning([{ id: "q1", date: "2026-09-02T00:00:00.000Z", subject: "quiet" }]),
		"bob@b.test": stubReturning([{ id: "x1", date: "2026-09-02T00:00:00.000Z", subject: "bob only" }]),
	};
}

describe("GET /api/v1/inbox", () => {
	it("merges visible mailboxes newest first and drops honeypot, hidden and ACL-denied mailboxes", async () => {
		const stubs = baseStubs();
		const res = await makeApp(makeR2Stub(baseStore()), stubs)("/api/v1/inbox");
		expect(res.status).toBe(200);
		const body = (await res.json()) as { emails: Array<{ id: string; mailbox_id: string }>; nextCursor: string | null; failed: string[]; mailboxCount: number };
		expect(body.emails.map((e) => [e.mailbox_id, e.id])).toEqual([
			["ops@b.test", "b1"],
			["ops@a.test", "a1"],
		]);
		expect(body.failed).toEqual([]);
		expect(body.mailboxCount).toBe(2);
		expect(body.nextCursor).toBeNull();
		expect(stubs["pot@a.test"].getThreadedEmails).not.toHaveBeenCalled();
		expect(stubs["quiet@b.test"].getThreadedEmails).not.toHaveBeenCalled();
		expect(stubs["bob@b.test"].getThreadedEmails).not.toHaveBeenCalled();
		expect(stubs["ops@a.test"].getThreadedEmails).toHaveBeenCalledWith({ folder: "inbox", limit: 26, before: undefined });
	});

	it("returns the other mailboxes and lists a failing one in failed", async () => {
		const stubs = baseStubs();
		stubs["ops@a.test"].getThreadedEmails.mockRejectedValue(new Error("DO reset"));
		const res = await makeApp(makeR2Stub(baseStore()), stubs)("/api/v1/inbox");
		const body = (await res.json()) as { emails: Array<{ id: string }>; failed: string[] };
		expect(body.emails.map((e) => e.id)).toEqual(["b1"]);
		expect(body.failed).toEqual(["ops@a.test"]);
	});

	it("excludes a mailbox whose settings read throws and lists it in failed", async () => {
		const stubs = baseStubs();
		const bucket = makeR2Stub(baseStore(), new Set(["mailboxes/ops@b.test.json"]));
		const res = await makeApp(bucket, stubs)("/api/v1/inbox");
		const body = (await res.json()) as { emails: Array<{ id: string }>; failed: string[] };
		expect(body.emails.map((e) => e.id)).toEqual(["a1"]);
		expect(body.failed).toEqual(["ops@b.test"]);
		expect(stubs["ops@b.test"].getThreadedEmails).not.toHaveBeenCalled();
	});

	it("excludes a honeypot whose settings blob cannot be read and lists it in failed", async () => {
		const stubs = baseStubs();
		const bucket = makeR2Stub(baseStore(), new Set(["mailboxes/pot@a.test.json"]));
		const res = await makeApp(bucket, stubs)("/api/v1/inbox");
		const body = (await res.json()) as { emails: Array<{ id: string }>; failed: string[] };
		expect(body.emails.map((e) => e.id)).not.toContain("p1");
		expect(body.failed).toEqual(["pot@a.test"]);
		expect(stubs["pot@a.test"].getThreadedEmails).not.toHaveBeenCalled();
	});

	it("treats a malformed settings blob as unreadable, not as empty settings", async () => {
		const stubs = baseStubs();
		const store = { ...baseStore(), "mailboxes/quiet@b.test.json": "{not json" };
		const res = await makeApp(makeR2Stub(store), stubs)("/api/v1/inbox");
		const body = (await res.json()) as { emails: Array<{ id: string }>; failed: string[] };
		expect(body.emails.map((e) => e.id)).not.toContain("q1");
		expect(body.failed).toEqual(["quiet@b.test"]);
	});

	it("never lists a mailbox the caller cannot see in failed", async () => {
		const bucket = makeR2Stub(baseStore(), new Set(["mailboxes/bob@b.test.json"]));
		const res = await makeApp(bucket, baseStubs())("/api/v1/inbox");
		const body = (await res.json()) as { failed: string[] };
		expect(body.failed).not.toContain("bob@b.test");
	});

	it("passes a decoded cursor through and pages with limit + 1", async () => {
		const stubs = baseStubs();
		const before = { date: "2026-09-01T12:00:00.000Z", id: "b1" };
		await makeApp(makeR2Stub(baseStore()), stubs)(`/api/v1/inbox?limit=5&before=${encodeCursor(before)}`);
		expect(stubs["ops@b.test"].getThreadedEmails).toHaveBeenCalledWith({ folder: "inbox", limit: 6, before });
	});

	it("rejects a malformed cursor with 400", async () => {
		const res = await makeApp(makeR2Stub(baseStore()), baseStubs())("/api/v1/inbox?before=%25%25%25");
		expect(res.status).toBe(400);
	});

	it.each([
		["abc", 26],
		["-5", 2],
		["9999", 51],
	])("clamps limit=%s", async (raw, expectedDoLimit) => {
		const stubs = baseStubs();
		const res = await makeApp(makeR2Stub(baseStore()), stubs)(`/api/v1/inbox?limit=${raw}`);
		expect(res.status).toBe(200);
		expect(stubs["ops@b.test"].getThreadedEmails).toHaveBeenCalledWith({ folder: "inbox", limit: expectedDoLimit, before: undefined });
	});
});
