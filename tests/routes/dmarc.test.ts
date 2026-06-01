// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

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

const fakeEnv = {
	BUCKET: {
		async get() { return null; },
		async head() { return { key: "mailboxes/m1.json" }; },
		async put() {},
	},
	MAILBOX: {
		idFromName() { return {}; },
		get() { return {}; },
	},
} as unknown as Parameters<Hono["request"]>[2];

const fakeCtx = {
	waitUntil: () => {},
	passThroughOnException: () => {},
} as unknown as ExecutionContext;

interface SummaryCall { domain: string; sinceIso: string }

function makeApp(summaryCalls: SummaryCall[]) {
	const stub = {
		async getDmarcSummary(domain: string, sinceIso: string) {
			summaryCalls.push({ domain, sinceIso });
			return [];
		},
	};
	const app = new Hono<MailboxContext>();
	app.use("*", async (c, next) => {
		c.set("mailboxStub", stub as unknown as DurableObjectStub<never>);
		await next();
	});
	app.route("/api/v1/mailboxes/:mailboxId/dmarc", dmarcRoutes);
	return app;
}

describe("workers/routes/dmarc — /summary date windowing (#382)", () => {
	it("defaults to 90 days when days param is omitted", async () => {
		const calls: SummaryCall[] = [];
		const app = makeApp(calls);
		const before = Date.now();
		const res = await app.request(
			"/api/v1/mailboxes/m1/dmarc/summary?domain=example.com",
			{},
			fakeEnv,
			fakeCtx,
		);
		const after = Date.now();
		expect(res.status).toBe(200);
		expect(calls).toHaveLength(1);
		expect(calls[0].domain).toBe("example.com");
		const sinceMs = new Date(calls[0].sinceIso).getTime();
		const expectedMs90 = before - 90 * 24 * 60 * 60 * 1000;
		const expectedMs7 = before - 7 * 24 * 60 * 60 * 1000;
		expect(sinceMs).toBeGreaterThanOrEqual(expectedMs90 - 1000);
		expect(sinceMs).toBeLessThan(expectedMs7);
		void after;
	});

	it("passes the requested days window to getDmarcSummary", async () => {
		const calls: SummaryCall[] = [];
		const app = makeApp(calls);
		const before = Date.now();
		const res = await app.request(
			"/api/v1/mailboxes/m1/dmarc/summary?domain=example.com&days=30",
			{},
			fakeEnv,
			fakeCtx,
		);
		expect(res.status).toBe(200);
		expect(calls).toHaveLength(1);
		const sinceMs = new Date(calls[0].sinceIso).getTime();
		const expected30 = before - 30 * 24 * 60 * 60 * 1000;
		const expected7 = before - 7 * 24 * 60 * 60 * 1000;
		expect(sinceMs).toBeGreaterThanOrEqual(expected30 - 1000);
		expect(sinceMs).toBeLessThan(expected7);
	});

	it("clamps days=0 up to 1", async () => {
		const calls: SummaryCall[] = [];
		const app = makeApp(calls);
		const before = Date.now();
		await app.request(
			"/api/v1/mailboxes/m1/dmarc/summary?domain=example.com&days=0",
			{},
			fakeEnv,
			fakeCtx,
		);
		expect(calls).toHaveLength(1);
		const sinceMs = new Date(calls[0].sinceIso).getTime();
		const expected1 = before - 1 * 24 * 60 * 60 * 1000;
		expect(sinceMs).toBeGreaterThanOrEqual(expected1 - 1000);
		expect(sinceMs).toBeLessThanOrEqual(before);
	});

	it("clamps days=999 down to 365", async () => {
		const calls: SummaryCall[] = [];
		const app = makeApp(calls);
		const before = Date.now();
		await app.request(
			"/api/v1/mailboxes/m1/dmarc/summary?domain=example.com&days=999",
			{},
			fakeEnv,
			fakeCtx,
		);
		expect(calls).toHaveLength(1);
		const sinceMs = new Date(calls[0].sinceIso).getTime();
		const expected365 = before - 365 * 24 * 60 * 60 * 1000;
		const expected364 = before - 364 * 24 * 60 * 60 * 1000;
		expect(sinceMs).toBeGreaterThanOrEqual(expected365 - 1000);
		expect(sinceMs).toBeLessThan(expected364);
	});

	it("returns 400 when domain param is missing", async () => {
		const calls: SummaryCall[] = [];
		const app = makeApp(calls);
		const res = await app.request(
			"/api/v1/mailboxes/m1/dmarc/summary?days=30",
			{},
			fakeEnv,
			fakeCtx,
		);
		expect(res.status).toBe(400);
		expect(calls).toHaveLength(0);
	});
});
