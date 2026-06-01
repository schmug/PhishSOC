// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Route-level tests for the DMARC sending-sources summary endpoint (#380).
 *
 * Verifies that:
 *   1. The route passes a `sinceIso` parameter to `getDmarcSummary` that
 *      represents approximately the last 90 days.
 *   2. Sources returned by the DO (i.e. within the window) appear in the
 *      response; the stub simulates the DO's date-filtered SQL result.
 *   3. Missing `domain` param yields 400.
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

interface DmarcSource {
	source_ip: string;
	total_count: number;
	pass_count: number;
	quarantine_count: number;
	reject_count: number;
	first_seen: string;
	last_seen: string;
}

function makeStub(sources: DmarcSource[] = []) {
	return {
		getDmarcSummary: vi.fn().mockResolvedValue(sources),
	};
}

function makeApp(stub: ReturnType<typeof makeStub>) {
	const app = new Hono<MailboxContext>();
	app.use("*", async (c, next) => {
		c.set("mailboxStub", stub as unknown as import("@cloudflare/workers-types").DurableObjectStub<never>);
		await next();
	});
	app.route("/api/v1/mailboxes/:mailboxId/dmarc", dmarcRoutes);
	return app;
}

describe("GET /dmarc/summary", () => {
	it("returns 400 when domain query param is missing", async () => {
		const stub = makeStub();
		const app = makeApp(stub);
		const res = await app.request("/api/v1/mailboxes/mb-1/dmarc/summary");
		expect(res.status).toBe(400);
		const body = await res.json() as { error: string };
		expect(body.error).toMatch(/domain/i);
	});

	it("calls getDmarcSummary with domain and a sinceIso ~90 days ago", async () => {
		const stub = makeStub([]);
		const app = makeApp(stub);
		const before = Date.now();
		await app.request("/api/v1/mailboxes/mb-1/dmarc/summary?domain=example.com");
		const after = Date.now();

		expect(stub.getDmarcSummary).toHaveBeenCalledOnce();
		const [calledDomain, calledSinceIso] = stub.getDmarcSummary.mock.calls[0] as [string, string];
		expect(calledDomain).toBe("example.com");

		const sinceMs = new Date(calledSinceIso).getTime();
		const expectedWindowMs = 90 * 24 * 60 * 60 * 1000;
		// sinceIso must be between (before - 90d) and (after - 90d), within 1s slack
		expect(sinceMs).toBeGreaterThanOrEqual(before - expectedWindowMs - 1000);
		expect(sinceMs).toBeLessThanOrEqual(after - expectedWindowMs + 1000);
	});

	it("returns sources from within the window in the response body", async () => {
		const windowSources: DmarcSource[] = [
			{
				source_ip: "192.0.2.1",
				total_count: 50,
				pass_count: 48,
				quarantine_count: 1,
				reject_count: 1,
				first_seen: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
				last_seen: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
			},
		];
		const stub = makeStub(windowSources);
		const app = makeApp(stub);
		const res = await app.request("/api/v1/mailboxes/mb-1/dmarc/summary?domain=example.com");
		expect(res.status).toBe(200);
		const body = await res.json() as { domain: string; sources: DmarcSource[] };
		expect(body.domain).toBe("example.com");
		expect(body.sources).toHaveLength(1);
		expect(body.sources[0].source_ip).toBe("192.0.2.1");
	});

	it("returns empty sources when the stub filters out all stale records", async () => {
		// Simulates the DO returning no rows because all reports pre-date sinceIso.
		const stub = makeStub([]);
		const app = makeApp(stub);
		const res = await app.request("/api/v1/mailboxes/mb-1/dmarc/summary?domain=stale.example");
		expect(res.status).toBe(200);
		const body = await res.json() as { domain: string; sources: DmarcSource[] };
		expect(body.domain).toBe("stale.example");
		expect(body.sources).toHaveLength(0);
	});
});
