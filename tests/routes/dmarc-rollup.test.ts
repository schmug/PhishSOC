// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

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

interface RollupRow {
	domain: string;
	total: number;
	aligned: number;
	failing: number;
}

function makeStub(rows: RollupRow[]) {
	const calls: Array<{ sinceIso: string }> = [];
	const stub = {
		async getDmarcRollup(sinceIso: string) {
			calls.push({ sinceIso });
			return rows;
		},
	};
	return { stub, calls };
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

const fakeCtx = {
	waitUntil: () => {},
	passThroughOnException: () => {},
} as unknown as ExecutionContext;

function makeApp(stub: ReturnType<typeof makeStub>["stub"]) {
	const app = new Hono<MailboxContext>();
	app.use("*", async (c, next) => {
		c.set("mailboxStub", stub as unknown as DurableObjectStub<never>);
		await next();
	});
	app.route("/api/v1/mailboxes/:mailboxId/dmarc", dmarcRoutes);
	return app;
}

describe("GET /dmarc/rollup — issue #383 cross-domain RUA rollup", () => {
	it("returns rollup rows for multiple domains sorted by caller-provided order", async () => {
		const { stub } = makeStub([
			{ domain: "evil.example", total: 100, aligned: 10, failing: 90 },
			{ domain: "good.example", total: 200, aligned: 195, failing: 2 },
		]);
		const app = makeApp(stub);

		const res = await app.request(
			"/api/v1/mailboxes/m1/dmarc/rollup",
			{},
			fakeEnv,
			fakeCtx,
		);
		expect(res.status).toBe(200);

		const body = (await res.json()) as {
			window_days: number;
			since: string;
			domains: RollupRow[];
		};
		expect(body.window_days).toBe(90);
		expect(typeof body.since).toBe("string");
		expect(body.domains).toHaveLength(2);
		expect(body.domains[0].domain).toBe("evil.example");
		expect(body.domains[1].domain).toBe("good.example");
	});

	it("respects the days query param and clamps to 365", async () => {
		const { stub, calls } = makeStub([]);
		const app = makeApp(stub);

		// days=30
		const res30 = await app.request(
			"/api/v1/mailboxes/m1/dmarc/rollup?days=30",
			{},
			fakeEnv,
			fakeCtx,
		);
		expect(res30.status).toBe(200);
		const body30 = (await res30.json()) as { window_days: number };
		expect(body30.window_days).toBe(30);

		// days=9999 → clamped to 365
		const res999 = await app.request(
			"/api/v1/mailboxes/m1/dmarc/rollup?days=9999",
			{},
			fakeEnv,
			fakeCtx,
		);
		expect(res999.status).toBe(200);
		const body999 = (await res999.json()) as { window_days: number };
		expect(body999.window_days).toBe(365);

		expect(calls).toHaveLength(2);
		// The sinceIso passed to getDmarcRollup must be a valid ISO timestamp
		for (const call of calls) {
			expect(() => new Date(call.sinceIso)).not.toThrow();
			expect(new Date(call.sinceIso).getTime()).toBeLessThan(Date.now());
		}
	});

	it("falls back to 90-day default for invalid days param", async () => {
		const { stub } = makeStub([]);
		const app = makeApp(stub);

		const res = await app.request(
			"/api/v1/mailboxes/m1/dmarc/rollup?days=notanumber",
			{},
			fakeEnv,
			fakeCtx,
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { window_days: number };
		expect(body.window_days).toBe(90);
	});

	it("returns empty domains array when no RUA reports are in scope", async () => {
		const { stub } = makeStub([]);
		const app = makeApp(stub);

		const res = await app.request(
			"/api/v1/mailboxes/m1/dmarc/rollup",
			{},
			fakeEnv,
			fakeCtx,
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { domains: RollupRow[] };
		expect(body.domains).toHaveLength(0);
	});
});
