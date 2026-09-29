// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Route-level tests for GET /api/v1/mailboxes/:mailboxId/link-domains (#740):
 * `requireMailbox` parity with `/dashboard` (same harness as
 * tests/routes/mailbox-root-acl.test.ts), `days` bounds validation, and the
 * response shape from `computeLinkDomainRollup`.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { requireMailbox, type MailboxContext } from "../../workers/lib/mailbox";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";
import { computeLinkDomainRollup, type LinkDomainUrlRow } from "../../workers/lib/dashboard-aggregation";

// Helper: build a fake (unsigned) JWT carrying arbitrary claims. Identity is
// decoded from the cf-access-jwt-assertion token (f17), never from the
// cf-access-authenticated-user-email header.
function makeFakeJwt(claims: Record<string, unknown>): string {
	const b64url = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
	return `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify(claims))}.`;
}

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
	};
}

interface FakeMailboxStub {
	getDashboardSummary: () => Promise<unknown>;
	getLinkDomains: (opts: { days: number }) => Promise<LinkDomainUrlRow[]>;
}

/**
 * Mirrors the production `/dashboard` and `/link-domains` handlers in
 * workers/index.ts closely enough to exercise the shared `requireMailbox`
 * middleware and the rollup response shape, without pulling in the full
 * app's DO/R2/hub dependencies.
 */
function makeApp(
	bucketStore: Record<string, string>,
	callerEmail: string | null,
	mailboxStub: FakeMailboxStub,
) {
	const bucket = makeR2Stub(bucketStore);
	const MAILBOX = {
		idFromName: (_: string) => "fake-id",
		get: (_: unknown) => mailboxStub,
	};

	const app = new Hono<MailboxContext>();
	app.use("/api/v1/mailboxes/:mailboxId/*", requireMailbox as Parameters<typeof app.use>[1]);

	app.get("/api/v1/mailboxes/:mailboxId/dashboard", async (c) => {
		await c.var.mailboxStub.getDashboardSummary();
		return c.json({ ok: true });
	});

	app.get("/api/v1/mailboxes/:mailboxId/link-domains", async (c) => {
		const daysParam = c.req.query("days");
		let days = 30;
		if (daysParam !== undefined) {
			const parsed = Number(daysParam);
			if (!Number.isInteger(parsed) || parsed < 1 || parsed > 90) {
				return c.json({ error: "days must be an integer between 1 and 90" }, 400);
			}
			days = parsed;
		}
		const rows = await c.var.mailboxStub.getLinkDomains({ days });
		return c.json(computeLinkDomainRollup(rows, days));
	});

	return {
		fetch(path: string) {
			const hdrs = new Headers();
			if (callerEmail) hdrs.set("cf-access-jwt-assertion", makeFakeJwt({ email: callerEmail }));
			return app.request(
				path,
				{ headers: hdrs },
				{
					BUCKET: bucket as unknown as R2Bucket,
					MAILBOX: MAILBOX as unknown as DurableObjectNamespace,
				},
			);
		},
	};
}

const mailboxId = "alice@example.com";
const mailboxKey = `mailboxes/${mailboxId}.json`;
const aclKey = `mailboxes-acl/${mailboxId}.json`;
const aliceAcl: MailboxAcl = {
	owner: "alice@example.com",
	members: ["alice@example.com"],
};

const noopStub: FakeMailboxStub = {
	getDashboardSummary: async () => ({}),
	getLinkDomains: async () => [],
};

describe("GET /api/v1/mailboxes/:mailboxId/link-domains", () => {
	it("returns the same requireMailbox response /dashboard gives for a caller outside the ACL", async () => {
		const store = {
			[mailboxKey]: JSON.stringify({ agentModel: "gpt-4" }),
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const { fetch } = makeApp(store, "eve@example.com", noopStub);

		const dashboardRes = await fetch(`/api/v1/mailboxes/${mailboxId}/dashboard`);
		const linkDomainsRes = await fetch(`/api/v1/mailboxes/${mailboxId}/link-domains`);

		expect(linkDomainsRes.status).toBe(403);
		expect(linkDomainsRes.status).toBe(dashboardRes.status);
		expect(await linkDomainsRes.json()).toEqual(await dashboardRes.json());
	});

	it("returns 404 for an unknown mailbox, same as /dashboard", async () => {
		const { fetch } = makeApp({}, "alice@example.com", noopStub);

		const dashboardRes = await fetch(`/api/v1/mailboxes/${mailboxId}/dashboard`);
		const linkDomainsRes = await fetch(`/api/v1/mailboxes/${mailboxId}/link-domains`);

		expect(linkDomainsRes.status).toBe(404);
		expect(linkDomainsRes.status).toBe(dashboardRes.status);
	});

	it("rejects days outside 1-90, and non-integer days, with 400", async () => {
		const store = {
			[mailboxKey]: JSON.stringify({}),
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const { fetch } = makeApp(store, "alice@example.com", noopStub);

		for (const days of ["0", "91", "abc", "1.5"]) {
			const res = await fetch(`/api/v1/mailboxes/${mailboxId}/link-domains?days=${days}`);
			expect(res.status, `days=${days}`).toBe(400);
		}
	});

	it("defaults to a 30-day window and returns the rollup for an ACL member", async () => {
		const store = {
			[mailboxKey]: JSON.stringify({}),
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const rows: LinkDomainUrlRow[] = [
			{ hostname: "evil.example.com", email_id: "e1", security_verdict: JSON.stringify({ action: "block", classification: { label: "phishing" } }) },
			{ hostname: "evil.example.com", email_id: "e2", security_verdict: JSON.stringify({ action: "block", classification: { label: "phishing" } }) },
			{ hostname: "evil.example.com", email_id: "e3", security_verdict: JSON.stringify({ action: "allow", classification: { label: "safe" } }) },
		];
		let requestedDays: number | undefined;
		const stub: FakeMailboxStub = {
			getDashboardSummary: async () => ({}),
			getLinkDomains: async (opts) => {
				requestedDays = opts.days;
				return rows;
			},
		};
		const { fetch } = makeApp(store, "alice@example.com", stub);

		const res = await fetch(`/api/v1/mailboxes/${mailboxId}/link-domains`);
		expect(res.status).toBe(200);
		expect(requestedDays).toBe(30);
		const body = (await res.json()) as ReturnType<typeof computeLinkDomainRollup>;
		expect(body.window_days).toBe(30);
		expect(body.hosts).toEqual([
			{ name: "evil.example.com", emails: 3, flagged: 2, phishing: 2, spam: 0 },
		]);
		expect(body.domains).toEqual([
			{ name: "example.com", emails: 3, flagged: 2, phishing: 2, spam: 0 },
		]);
	});

	it("honors a valid custom days value", async () => {
		const store = {
			[mailboxKey]: JSON.stringify({}),
			[aclKey]: JSON.stringify(aliceAcl),
		};
		let requestedDays: number | undefined;
		const stub: FakeMailboxStub = {
			getDashboardSummary: async () => ({}),
			getLinkDomains: async (opts) => {
				requestedDays = opts.days;
				return [];
			},
		};
		const { fetch } = makeApp(store, "alice@example.com", stub);

		const res = await fetch(`/api/v1/mailboxes/${mailboxId}/link-domains?days=7`);
		expect(res.status).toBe(200);
		expect(requestedDays).toBe(7);
		expect((await res.json()).window_days).toBe(7);
	});
});
