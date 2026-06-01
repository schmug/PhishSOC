// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Route-level tests for `workers/routes/dmarc.ts` — `/summary` endpoint.
 *
 * Verifies that `getDmarcSummary` is called with a `sinceIso` that corresponds
 * to a 90-day window so reports older than the window are excluded and reports
 * inside the window are included (acceptance criteria for issue #380).
 *
 * The MailboxDO stub captures the `sinceIso` argument passed by the route so
 * the test can assert: (a) the argument is present and (b) it is ≥ 90 days
 * ago, matching the "last 90 days" copy in `app/routes/dmarc.tsx`.
 */

import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { describe, expect, it, vi } from "vitest";

vi.mock("../../workers/lib/mailbox", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/mailbox")>();
	return {
		...original,
		requireMailbox: createMiddleware(async (_c, next) => {
			await next();
		}),
	};
});

import { dmarcRoutes } from "../../workers/routes/dmarc";
import type { MailboxContext } from "../../workers/lib/mailbox";

interface FakeSource {
	source_ip: string;
	total_count: number;
	pass_count: number;
	quarantine_count: number;
	reject_count: number;
	first_seen: string;
	last_seen: string;
}

/**
 * Build a fake MailboxDO stub that records the arguments passed to
 * `getDmarcSummary` and returns a configurable set of rows filtered by the
 * given `sinceIso` cutoff.
 *
 * Each row in `allRows` has a `received_at` field (ISO string). The stub
 * mirrors the real DO behaviour: it only returns rows whose report's
 * `received_at >= sinceIso`. This lets the test verify that an old row is
 * excluded and a recent row is included.
 */
function makeStub(
	allRows: Array<FakeSource & { received_at: string }>,
) {
	const calls: Array<{ domain: string; sinceIso: string }> = [];

	const stub = {
		async getDmarcSummary(domain: string, sinceIso: string) {
			calls.push({ domain, sinceIso });
			// Simulate the DO's date filter — only return rows in-window
			return allRows
				.filter((r) => r.received_at >= sinceIso)
				.map(({ received_at: _unused, ...rest }) => rest);
		},
	};

	return { stub, calls };
}

function makeApp(stub: ReturnType<typeof makeStub>["stub"]) {
	const app = new Hono<MailboxContext>();
	app.use("*", async (c, next) => {
		c.set("mailboxStub", stub as unknown as DurableObjectStub<never>);
		await next();
	});
	app.route("/api/v1/mailboxes/:mailboxId/dmarc", dmarcRoutes);
	return app;
}

const fakeEnv = {
	BUCKET: {
		async get() { return null; },
		async head() { return { key: "mailboxes/m1.json" }; },
		async put() { /* no-op */ },
	},
	MAILBOX: {
		idFromName() { return {}; },
		get() { return {}; },
	},
} as unknown as Parameters<Hono["request"]>[2];

const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

describe("workers/routes/dmarc — /summary 90-day window (issue #380)", () => {
	it("passes a sinceIso ~90 days ago to getDmarcSummary", async () => {
		const { stub, calls } = makeStub([]);
		const app = makeApp(stub);
		const before = Date.now();

		const res = await app.request(
			"/api/v1/mailboxes/m1/dmarc/summary?domain=example.com",
			{ method: "GET" },
			fakeEnv,
		);
		expect(res.status).toBe(200);

		// The route must have called getDmarcSummary exactly once
		expect(calls).toHaveLength(1);
		expect(calls[0].domain).toBe("example.com");

		// sinceIso must be a parseable ISO date
		const sinceMs = new Date(calls[0].sinceIso).getTime();
		expect(Number.isNaN(sinceMs)).toBe(false);

		// sinceIso must be approximately 90 days before the call
		const expectedMs = before - NINETY_DAYS_MS;
		// Allow ±5 s of wall-clock drift in CI
		expect(sinceMs).toBeGreaterThanOrEqual(expectedMs - 5_000);
		expect(sinceMs).toBeLessThanOrEqual(expectedMs + 5_000);
	});

	it("excludes reports older than 90 days and includes recent ones", async () => {
		const now = Date.now();
		const recentIso = new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();  // 30 days ago
		const oldIso    = new Date(now - 120 * 24 * 60 * 60 * 1000).toISOString(); // 120 days ago

		const recentRow: FakeSource & { received_at: string } = {
			source_ip: "203.0.113.1",
			total_count: 10,
			pass_count: 8,
			quarantine_count: 1,
			reject_count: 1,
			first_seen: recentIso,
			last_seen: recentIso,
			received_at: recentIso,
		};
		const oldRow: FakeSource & { received_at: string } = {
			source_ip: "198.51.100.42",
			total_count: 99,
			pass_count: 0,
			quarantine_count: 50,
			reject_count: 49,
			first_seen: oldIso,
			last_seen: oldIso,
			received_at: oldIso,
		};

		const { stub } = makeStub([recentRow, oldRow]);
		const app = makeApp(stub);

		const res = await app.request(
			"/api/v1/mailboxes/m1/dmarc/summary?domain=example.com",
			{ method: "GET" },
			fakeEnv,
		);
		expect(res.status).toBe(200);
		const body = await res.json() as { domain: string; sources: FakeSource[] };

		// Only the recent row should be returned; the old one must be absent
		expect(body.sources).toHaveLength(1);
		expect(body.sources[0].source_ip).toBe("203.0.113.1");

		// The stale forger's IP must NOT appear
		const staleIp = body.sources.find((s) => s.source_ip === "198.51.100.42");
		expect(staleIp).toBeUndefined();
	});

	it("returns 400 when domain query param is missing", async () => {
		const { stub } = makeStub([]);
		const app = makeApp(stub);

		const res = await app.request(
			"/api/v1/mailboxes/m1/dmarc/summary",
			{ method: "GET" },
			fakeEnv,
		);
		expect(res.status).toBe(400);
		const body = await res.json() as { error: string };
		expect(body.error).toMatch(/domain/i);
	});
});
