// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/** Route tests for POST /cases/:id/submit-cloudflare (issue #755). Synthetic data only. */

import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../../workers/lib/mailbox", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/mailbox")>();
	return {
		...original,
		requireMailbox: createMiddleware(async (_c, next) => {
			await next();
		}),
	};
});

import { caseRoutes } from "../../workers/routes/cases";
import type { MailboxContext } from "../../workers/lib/mailbox";

function makeKv() {
	const store = new Map<string, string>();
	return {
		store,
		async get(key: string, type?: string) {
			const v = store.get(key);
			if (v === undefined) return null;
			return type === "json" ? JSON.parse(v) : v;
		},
		async put(key: string, value: string) {
			store.set(key, value);
		},
	};
}

function makeApp(opts: {
	domains?: string[];
	status?: string;
	notPhish?: boolean;
	configured?: boolean;
	cap?: string;
	kv?: ReturnType<typeof makeKv>;
}) {
	const kv = opts.kv ?? makeKv();
	const stub = {
		async getCase(id: string) {
			if (id !== "case_1") return null;
			return {
				id,
				status: opts.status ?? "closed-tp",
				emails: [{ case_id: id, email_id: "e1" }],
				observables: (opts.domains ?? ["login.evil-example.test"]).map((value, i) => ({
					id: String(i), case_id: id, kind: "domain", value,
				})),
			};
		},
		async getEmail() {
			return { id: "e1", feedback: opts.notPhish ? { label: "not_phish" } : null };
		},
	};
	const app = new Hono<MailboxContext>();
	app.use("*", async (c, next) => {
		c.set("mailboxStub", stub as never);
		await next();
	});
	app.route("/api/v1/mailboxes/:mailboxId/cases", caseRoutes);
	const env =
		opts.configured === false
			? { BLOOM_KV: kv }
			: {
				BLOOM_KV: kv,
				CLOUDFLARE_INTEL_API_TOKEN: "tok",
				CLOUDFLARE_INTEL_ACCOUNT_ID: "acct1",
				CF_CATEGORIZE_MONTHLY_CAP: opts.cap,
			};
	const post = (body: unknown, caseId = "case_1") =>
		app.request(
			`/api/v1/mailboxes/box%40a.test/cases/${caseId}/submit-cloudflare`,
			{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) },
			env,
		);
	return { post, kv };
}

function stubFetch() {
	const calls: Array<{ url: URL; body: unknown }> = [];
	vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
		const url = new URL(String(input));
		calls.push({ url, body: JSON.parse(String(init?.body ?? "null")) });
		if (url.hostname === "api.cloudflare.com") {
			return new Response(JSON.stringify({ result: "", success: true }), { status: 200 });
		}
		return new Response("unexpected", { status: 500 });
	});
	return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe("POST /cases/:id/submit-cloudflare", () => {
	it("sends exactly one request with security_adds [131] for the registrable domain", async () => {
		const calls = stubFetch();
		const { post } = makeApp({});
		const res = await post({ domain: "login.evil-example.test" });
		expect(res.status).toBe(201);
		expect(calls).toHaveLength(1);
		expect(calls[0].url.hostname).toBe("api.cloudflare.com");
		expect(calls[0].url.pathname).toBe("/client/v4/accounts/acct1/intel/miscategorization");
		expect(calls[0].body).toEqual({
			indicator_type: "domain",
			url: "evil-example.test",
			security_adds: [131],
		});
	});

	it("returns 409 on resubmit with no second outbound call", async () => {
		const calls = stubFetch();
		const { post } = makeApp({});
		expect((await post({ domain: "evil-example.test" })).status).toBe(201);
		expect((await post({ domain: "login.evil-example.test" })).status).toBe(409);
		expect(calls).toHaveLength(1);
	});

	it("refuses once the monthly cap is reached", async () => {
		const calls = stubFetch();
		const { post } = makeApp({ cap: "0" });
		expect((await post({ domain: "evil-example.test" })).status).toBe(429);
		expect(calls).toHaveLength(0);
	});

	it("refuses when a linked email is labeled Not phish", async () => {
		const calls = stubFetch();
		const { post } = makeApp({ notPhish: true });
		expect((await post({ domain: "evil-example.test" })).status).toBe(422);
		expect(calls).toHaveLength(0);
	});

	it("refuses shared-platform domains", async () => {
		const calls = stubFetch();
		const { post } = makeApp({ domains: ["evil.sharepoint.com", "forms.gle", "docs.google.com"] });
		for (const d of ["evil.sharepoint.com", "forms.gle", "docs.google.com"]) {
			expect((await post({ domain: d })).status).toBe(422);
		}
		expect(calls).toHaveLength(0);
	});

	it("refuses a domain that is not an observable of the case", async () => {
		const calls = stubFetch();
		const { post } = makeApp({});
		expect((await post({ domain: "other-example.test" })).status).toBe(400);
		expect(calls).toHaveLength(0);
	});

	it("refuses a case that is not a confirmed threat", async () => {
		const calls = stubFetch();
		const { post } = makeApp({ status: "open" });
		expect((await post({ domain: "evil-example.test" })).status).toBe(422);
		expect(calls).toHaveLength(0);
	});

	it("returns 501 when the token is unset", async () => {
		const calls = stubFetch();
		const { post } = makeApp({ configured: false });
		expect((await post({ domain: "evil-example.test" })).status).toBe(501);
		expect(calls).toHaveLength(0);
	});

	it("does not record a submission when Cloudflare rejects the request", async () => {
		vi.stubGlobal("fetch", async () => new Response("no", { status: 403 }));
		const { post, kv } = makeApp({});
		expect((await post({ domain: "evil-example.test" })).status).toBe(502);
		expect(kv.store.size).toBe(0);
	});

	it("exposes the record on GET /:caseId", async () => {
		stubFetch();
		const { post, kv } = makeApp({});
		await post({ domain: "evil-example.test" });
		const rec = JSON.parse(kv.store.get("cf-cat:case:case_1")!);
		expect(rec).toHaveLength(1);
		expect(rec[0]).toMatchObject({ domain: "evil-example.test", case_id: "case_1" });
	});
});
