// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for shadow-IT / legitimate-source flagging (issue #385):
 *   - PATCH /dmarc/sources/:sourceIp: validates IP, accepts boolean, writes to stub
 *   - GET /dmarc/summary: propagates the `legitimate` field from getDmarcSummary
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

function makeStub(overrides: Partial<{
	getDmarcSummary: (domain: string) => Promise<unknown[]>;
	setSourceLegitimate: (ip: string, legitimate: boolean, notes: string | null) => Promise<void>;
}> = {}) {
	return {
		getDmarcSummary: vi.fn().mockResolvedValue([]),
		setSourceLegitimate: vi.fn().mockResolvedValue(undefined),
		...overrides,
	};
}

function makeApp(stub: ReturnType<typeof makeStub>) {
	const app = new Hono<MailboxContext>();
	app.use("*", async (c, next) => {
		c.set("mailboxStub", stub as unknown as Parameters<typeof c.set>[1]);
		await next();
	});
	app.route("/", dmarcRoutes);
	return app;
}

// ── PATCH /sources/:sourceIp ──────────────────────────────────────────────────

describe("PATCH /dmarc/sources/:sourceIp", () => {
	it("calls setSourceLegitimate with the right args when marking legitimate", async () => {
		const stub = makeStub();
		const app = makeApp(stub);
		const res = await app.request("/sources/1.2.3.4", {
			method: "PATCH",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ legitimate: true }),
		});
		expect(res.status).toBe(200);
		const body = await res.json();
		expect((body as { ok: boolean }).ok).toBe(true);
		expect(stub.setSourceLegitimate).toHaveBeenCalledWith("1.2.3.4", true, null);
	});

	it("calls setSourceLegitimate with false when marking unknown", async () => {
		const stub = makeStub();
		const app = makeApp(stub);
		const res = await app.request("/sources/203.0.113.42", {
			method: "PATCH",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ legitimate: false }),
		});
		expect(res.status).toBe(200);
		expect(stub.setSourceLegitimate).toHaveBeenCalledWith("203.0.113.42", false, null);
	});

	it("forwards optional notes to setSourceLegitimate", async () => {
		const stub = makeStub();
		const app = makeApp(stub);
		const res = await app.request("/sources/10.0.0.1", {
			method: "PATCH",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ legitimate: true, notes: "our mail relay" }),
		});
		expect(res.status).toBe(200);
		expect(stub.setSourceLegitimate).toHaveBeenCalledWith("10.0.0.1", true, "our mail relay");
	});

	it("returns 400 for a non-IP sourceIp parameter", async () => {
		const stub = makeStub();
		const app = makeApp(stub);
		const res = await app.request("/sources/not-an-ip", {
			method: "PATCH",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ legitimate: true }),
		});
		expect(res.status).toBe(400);
		const body = await res.json();
		expect((body as { error: string }).error).toMatch(/invalid source_ip/);
		expect(stub.setSourceLegitimate).not.toHaveBeenCalled();
	});

	it("returns 400 when an octet exceeds 255", async () => {
		const stub = makeStub();
		const app = makeApp(stub);
		const res = await app.request("/sources/1.2.3.999", {
			method: "PATCH",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ legitimate: true }),
		});
		expect(res.status).toBe(400);
		expect(stub.setSourceLegitimate).not.toHaveBeenCalled();
	});

	it("returns 400 when legitimate is a string, not boolean", async () => {
		const stub = makeStub();
		const app = makeApp(stub);
		const res = await app.request("/sources/1.2.3.4", {
			method: "PATCH",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ legitimate: "yes" }),
		});
		expect(res.status).toBe(400);
		const body = await res.json();
		expect((body as { error: string }).error).toMatch(/boolean/);
		expect(stub.setSourceLegitimate).not.toHaveBeenCalled();
	});

	it("accepts a valid IPv6 address", async () => {
		const stub = makeStub();
		const app = makeApp(stub);
		const ipv6 = "2001:db8::1";
		const res = await app.request(`/sources/${encodeURIComponent(ipv6)}`, {
			method: "PATCH",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ legitimate: true }),
		});
		expect(res.status).toBe(200);
		expect(stub.setSourceLegitimate).toHaveBeenCalledWith(ipv6, true, null);
	});
});

// ── GET /summary — legitimate field propagation ───────────────────────────────

describe("GET /dmarc/summary", () => {
	it("includes legitimate field in summary source rows", async () => {
		const sourceRows = [
			{
				source_ip: "1.2.3.4",
				total_count: 100,
				pass_count: 90,
				quarantine_count: 5,
				reject_count: 5,
				first_seen: "2026-01-01",
				last_seen: "2026-01-31",
				legitimate: 1,
			},
			{
				source_ip: "5.6.7.8",
				total_count: 50,
				pass_count: 10,
				quarantine_count: 20,
				reject_count: 20,
				first_seen: "2026-01-05",
				last_seen: "2026-01-30",
				legitimate: 0,
			},
		];
		const stub = makeStub({ getDmarcSummary: vi.fn().mockResolvedValue(sourceRows) });
		const app = makeApp(stub);
		const res = await app.request("/summary?domain=example.com");
		expect(res.status).toBe(200);
		const body = await res.json() as { domain: string; sources: typeof sourceRows };
		expect(body.domain).toBe("example.com");
		expect(body.sources).toHaveLength(2);
		expect(body.sources[0].legitimate).toBe(1);
		expect(body.sources[1].legitimate).toBe(0);
	});

	it("returns 400 when domain query param is missing", async () => {
		const stub = makeStub();
		const app = makeApp(stub);
		const res = await app.request("/summary");
		expect(res.status).toBe(400);
	});
});
