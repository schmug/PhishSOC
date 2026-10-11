// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sender blocklist endpoints (spec 2026-09-27-sender-blocklist, API section):
 * validation, stripDefaultEqual on every write, same-match replace, delete,
 * blocked-log read, and the org/domain tiers through the real app.
 */

import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { beforeEach, describe, expect, it, vi } from "vitest";

// requireMailbox → no-op so the parent middleware below can inject the fake
// DO stub (same pattern as tests/routes/cases.test.ts).
vi.mock("../../workers/lib/mailbox", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/mailbox")>();
	return {
		...original,
		requireMailbox: createMiddleware(async (_c, next) => {
			await next();
		}),
	};
});

import { app } from "../../workers/index";
import { mailboxBlocklistRoutes } from "../../workers/routes/blocklist";
import type { MailboxContext } from "../../workers/lib/mailbox";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";

function makeR2(initial: Record<string, string> = {}) {
	const store = new Map<string, string>(Object.entries(initial));
	return {
		async get(key: string) {
			if (!store.has(key)) return null;
			const val = store.get(key)!;
			return { etag: `etag-${val.length}`, async json() { return JSON.parse(val); } };
		},
		async head(key: string) { return store.has(key) ? { key } : null; },
		async put(key: string, val: string) { store.set(key, val); },
		read(key: string) { return store.get(key); },
	};
}

function makeMailboxApp(stub: Record<string, unknown>) {
	const a = new Hono<MailboxContext>();
	a.use("*", async (c, next) => {
		c.set("mailboxStub", stub as unknown as DurableObjectStub<never>);
		await next();
	});
	a.route("/api/v1/mailboxes/:mailboxId", mailboxBlocklistRoutes);
	return a;
}

beforeEach(() => {
	clearDomainSettingsCache();
	clearOrgSettingsCache();
});

describe("blocklist endpoints", () => {
	// mailbox tier
	it("POST appends a validated rule, strips defaults, moves existing mail", async () => {
		const bucket = makeR2({ "mailboxes/a@x.com.json": JSON.stringify({ agentModel: "custom" }) });
		const stub = { moveEmailsFromSender: vi.fn().mockResolvedValue(3), listBlockedLog: vi.fn() };
		const res = await makeMailboxApp(stub).request(
			"/api/v1/mailboxes/a%40x.com/blocklist",
			{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ match: "NoReply@Res.PodView.com", action: "spam", move_existing: true }) },
			{ BUCKET: bucket },
		);
		expect(res.status).toBe(201);
		const body = await res.json();
		expect(body.moved).toBe(3);
		expect(body.rule).toMatchObject({ match: "noreply@res.podview.com", action: "spam" });
		const saved = JSON.parse(bucket.read("mailboxes/a@x.com.json")!);
		expect(saved.agentModel).toBe("custom");
		expect(saved.blocklist).toHaveLength(1);
		expect(stub.moveEmailsFromSender).toHaveBeenCalledWith("noreply@res.podview.com", "spam");
	});

	const post = (app: { request: Function }, path: string, body: unknown, env: unknown) =>
		app.request(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }, env);

	it("POST with the same match replaces the old rule's action", async () => {
		const bucket = makeR2({ "mailboxes/a@x.com.json": "{}" });
		const app = makeMailboxApp({ moveEmailsFromSender: vi.fn(), listBlockedLog: vi.fn() });
		await post(app, "/api/v1/mailboxes/a%40x.com/blocklist", { match: "podview.com", action: "drop" }, { BUCKET: bucket });
		await post(app, "/api/v1/mailboxes/a%40x.com/blocklist", { match: "podview.com", action: "spam" }, { BUCKET: bucket });
		const saved = JSON.parse(bucket.read("mailboxes/a@x.com.json")!);
		expect(saved.blocklist).toHaveLength(1);
		expect(saved.blocklist[0].action).toBe("spam");
	});

	it("POST rejects a public suffix with 400 code public_suffix", async () => {
		const bucket = makeR2({ "mailboxes/a@x.com.json": "{}" });
		const res = await post(makeMailboxApp({}), "/api/v1/mailboxes/a%40x.com/blocklist", { match: "co.uk", action: "drop" }, { BUCKET: bucket });
		expect(res.status).toBe(400);
		expect((await res.json()).code).toBe("public_suffix");
		expect(JSON.parse(bucket.read("mailboxes/a@x.com.json")!).blocklist).toBeUndefined();
	});

	it("POST shared domain without confirm → 400; with confirm → 201", async () => {
		const bucket = makeR2({ "mailboxes/a@x.com.json": "{}" });
		const app = makeMailboxApp({ moveEmailsFromSender: vi.fn() });
		const no = await post(app, "/api/v1/mailboxes/a%40x.com/blocklist", { match: "gmail.com", action: "drop" }, { BUCKET: bucket });
		expect(no.status).toBe(400);
		expect((await no.json()).code).toBe("shared_domain_unconfirmed");
		const yes = await post(app, "/api/v1/mailboxes/a%40x.com/blocklist", { match: "gmail.com", action: "drop", confirm_shared_domain: true }, { BUCKET: bucket });
		expect(yes.status).toBe(201);
	});

	it("DELETE removes by id; unknown id → 404; last rule removed → blocklist key stripped", async () => {
		const rule = { id: "r1", match: "podview.com", action: "drop", created_at: "t" };
		const bucket = makeR2({ "mailboxes/a@x.com.json": JSON.stringify({ agentModel: "custom", blocklist: [rule] }) });
		const app = makeMailboxApp({});
		const missing = await app.request("/api/v1/mailboxes/a%40x.com/blocklist/nope", { method: "DELETE" }, { BUCKET: bucket });
		expect(missing.status).toBe(404);
		const ok = await app.request("/api/v1/mailboxes/a%40x.com/blocklist/r1", { method: "DELETE" }, { BUCKET: bucket });
		expect(ok.status).toBe(204);
		expect(JSON.parse(bucket.read("mailboxes/a@x.com.json")!)).toEqual({ agentModel: "custom" });
	});

	it("GET blocked-log passes limit through", async () => {
		const listBlockedLog = vi.fn().mockResolvedValue([{ id: 1, sender: "x@podview.com" }]);
		const res = await makeMailboxApp({ listBlockedLog }).request("/api/v1/mailboxes/a%40x.com/blocked-log?limit=7", {}, { BUCKET: makeR2() });
		expect(res.status).toBe(200);
		expect((await res.json()).rows).toHaveLength(1);
		expect(listBlockedLog).toHaveBeenCalledWith(7);
	});

	// org tier (via the real app)
	it("org POST writes the org blocklist and a later org settings PUT keeps it", async () => {
		const bucket = makeR2({ "org/settings.json": JSON.stringify({ agentModel: "custom" }) });
		const env = { BUCKET: bucket, DOMAINS: "" };
		const res = await post(app, "/api/v1/org/blocklist", { match: "podview.com", action: "reject", reason: "Stop" }, env);
		expect(res.status).toBe(201);
		await app.request("/api/v1/org/settings", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ settings: { agentModel: "other" } }) }, env);
		const saved = JSON.parse(bucket.read("org/settings.json")!);
		expect(saved.agentModel).toBe("other");
		expect(saved.blocklist).toHaveLength(1);
		expect(saved.blocklist[0]).toMatchObject({ match: "podview.com", action: "reject", reason: "Stop" });
	});

	// domain tier
	it("domain POST for a non-owned domain → 403", async () => {
		const bucket = makeR2();
		const res = await post(app, "/api/v1/domains/not-owned.example/blocklist", { match: "podview.com", action: "drop" }, { BUCKET: bucket, DOMAINS: "example.com" });
		expect(res.status).toBe(403);
		expect(bucket.read("domains/not-owned.example.json")).toBeUndefined();
	});

	it("POST past the 1000-rule cap → 400 blocklist_full and nothing written (mailbox + org)", async () => {
		const full = Array.from({ length: 1000 }, (_, i) => ({ id: `r${i}`, match: `s${i}.example`, action: "drop", created_at: "t" }));
		const before = JSON.stringify({ agentModel: "custom", blocklist: full });
		const bucket = makeR2({ "mailboxes/a@x.com.json": before, "org/settings.json": JSON.stringify({ blocklist: full }) });
		const res = await post(makeMailboxApp({}), "/api/v1/mailboxes/a%40x.com/blocklist", { match: "podview.com", action: "drop" }, { BUCKET: bucket });
		expect(res.status).toBe(400);
		expect((await res.json()).code).toBe("blocklist_full");
		expect(bucket.read("mailboxes/a@x.com.json")).toBe(before);
		const org = await post(app, "/api/v1/org/blocklist", { match: "podview.com", action: "drop" }, { BUCKET: bucket, DOMAINS: "" });
		expect(org.status).toBe(400);
		// Re-blocking an existing match replaces in place, so it is allowed at the cap.
		const replace = await post(makeMailboxApp({}), "/api/v1/mailboxes/a%40x.com/blocklist", { match: "s1.example", action: "spam" }, { BUCKET: bucket });
		expect(replace.status).toBe(201);
	});
});
