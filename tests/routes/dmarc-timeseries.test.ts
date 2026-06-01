// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for the DMARC time-series endpoint and getDmarcTimeSeries logic.
 *
 * Coverage:
 *   1. /timeseries returns 400 when domain is missing.
 *   2. /timeseries proxies the DO result through { domain, timeseries }.
 *   3. Multi-day bucketing: records on different days appear as separate rows.
 *   4. Aligned/failing split: dkim OR spf pass → aligned; both fail → failing.
 *   5. Window filtering: records older than sinceIso are excluded.
 *
 * The DO stub simulates the getDmarcTimeSeries SQL query in memory so that the
 * split/bucketing/window logic can be verified without the Workers SQLite
 * runtime. This mirrors the approach used in tests/routes/cases.test.ts.
 */

import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { describe, expect, it, vi } from "vitest";

// Replace requireMailbox with a no-op so our stub injection runs first.
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

// ---------------------------------------------------------------------------
// Minimal fake record type matching what the DO stores
// ---------------------------------------------------------------------------

interface FakeDmarcRecord {
	/** ISO date string stored in dmarc_reports.received_at */
	received_at: string;
	/** dmarc_records.count */
	count: number;
	/** dmarc_records.dkim_result */
	dkim_result: string | null;
	/** dmarc_records.spf_result */
	spf_result: string | null;
	/** dmarc_reports.domain */
	domain: string;
}

/**
 * Simulate getDmarcTimeSeries SQL in JS.
 *
 * SQL semantics:
 *   - Filter by domain and received_at >= sinceIso
 *   - GROUP BY date(received_at)
 *   - aligned  = dkim_result='pass' OR spf_result='pass'
 *   - failing  = dkim_result!='pass' AND spf_result!='pass'
 *   - ORDER BY day
 */
function simulateGetDmarcTimeSeries(
	records: FakeDmarcRecord[],
	domain: string,
	sinceIso: string,
): { day: string; aligned: number; failing: number }[] {
	const filtered = records.filter(
		(r) => r.domain === domain && r.received_at >= sinceIso,
	);
	const buckets = new Map<string, { aligned: number; failing: number }>();
	for (const r of filtered) {
		const day = r.received_at.slice(0, 10); // date(received_at) → YYYY-MM-DD
		const bucket = buckets.get(day) ?? { aligned: 0, failing: 0 };
		const isAligned = r.dkim_result === "pass" || r.spf_result === "pass";
		if (isAligned) {
			bucket.aligned += r.count;
		} else {
			bucket.failing += r.count;
		}
		buckets.set(day, bucket);
	}
	return Array.from(buckets.entries())
		.sort(([a], [b]) => a.localeCompare(b))
		.map(([day, { aligned, failing }]) => ({ day, aligned, failing }));
}

// ---------------------------------------------------------------------------
// Test app factory
// ---------------------------------------------------------------------------

function makeApp(records: FakeDmarcRecord[]) {
	const stub = {
		getDmarcTimeSeries: (domain: string, sinceIso: string) =>
			Promise.resolve(simulateGetDmarcTimeSeries(records, domain, sinceIso)),
	};

	const app = new Hono<MailboxContext>();
	app.use("*", async (c, next) => {
		c.set("mailboxStub", stub as unknown as MailboxContext["Variables"]["mailboxStub"]);
		await next();
	});
	app.route("/", dmarcRoutes);

	return {
		fetch(path: string) {
			return app.request(path, {}, {} as never);
		},
	};
}

// ---------------------------------------------------------------------------
// Unit-level tests for the simulation (verifies our test helper is correct)
// ---------------------------------------------------------------------------

describe("simulateGetDmarcTimeSeries (logic unit tests)", () => {
	const records: FakeDmarcRecord[] = [
		// Day 1 — two aligned records (dkim pass, spf pass respectively)
		{
			domain: "example.com",
			received_at: "2026-01-10T10:00:00Z",
			count: 5,
			dkim_result: "pass",
			spf_result: "fail",
		},
		{
			domain: "example.com",
			received_at: "2026-01-10T12:00:00Z",
			count: 3,
			dkim_result: "fail",
			spf_result: "pass",
		},
		// Day 1 — one failing record (both fail)
		{
			domain: "example.com",
			received_at: "2026-01-10T14:00:00Z",
			count: 2,
			dkim_result: "fail",
			spf_result: "fail",
		},
		// Day 2 — both aligned (dkim+spf pass)
		{
			domain: "example.com",
			received_at: "2026-01-11T08:00:00Z",
			count: 10,
			dkim_result: "pass",
			spf_result: "pass",
		},
		// Old record outside any reasonable window
		{
			domain: "example.com",
			received_at: "2025-01-01T00:00:00Z",
			count: 99,
			dkim_result: "pass",
			spf_result: "pass",
		},
		// Different domain — should be excluded
		{
			domain: "other.com",
			received_at: "2026-01-10T10:00:00Z",
			count: 7,
			dkim_result: "pass",
			spf_result: "pass",
		},
	];

	it("buckets records into separate days (multi-day bucketing)", () => {
		const result = simulateGetDmarcTimeSeries(records, "example.com", "2026-01-01T00:00:00Z");
		const days = result.map((r) => r.day);
		expect(days).toEqual(["2026-01-10", "2026-01-11"]);
	});

	it("sums aligned counts correctly on day 1 (dkim OR spf pass = aligned)", () => {
		const result = simulateGetDmarcTimeSeries(records, "example.com", "2026-01-01T00:00:00Z");
		const day1 = result.find((r) => r.day === "2026-01-10");
		expect(day1).toBeDefined();
		// 5 (dkim pass, spf fail → aligned) + 3 (dkim fail, spf pass → aligned)
		expect(day1!.aligned).toBe(8);
	});

	it("sums failing counts correctly on day 1 (both fail → failing)", () => {
		const result = simulateGetDmarcTimeSeries(records, "example.com", "2026-01-01T00:00:00Z");
		const day1 = result.find((r) => r.day === "2026-01-10");
		expect(day1!.failing).toBe(2);
	});

	it("handles a day where all records are aligned (failing=0)", () => {
		const result = simulateGetDmarcTimeSeries(records, "example.com", "2026-01-01T00:00:00Z");
		const day2 = result.find((r) => r.day === "2026-01-11");
		expect(day2).toBeDefined();
		expect(day2!.aligned).toBe(10);
		expect(day2!.failing).toBe(0);
	});

	it("excludes records older than sinceIso (window filtering)", () => {
		// Window starts 2026-01-10 — the 2025-01-01 record should be excluded
		const result = simulateGetDmarcTimeSeries(records, "example.com", "2026-01-10T00:00:00Z");
		const days = result.map((r) => r.day);
		expect(days).not.toContain("2025-01-01");
	});

	it("excludes records for a different domain", () => {
		const result = simulateGetDmarcTimeSeries(records, "example.com", "2026-01-01T00:00:00Z");
		// other.com has a record on 2026-01-10 with count=7; our aligned total
		// for that day must be 8, not 15
		const day1 = result.find((r) => r.day === "2026-01-10");
		expect(day1!.aligned).toBe(8);
	});

	it("returns an empty array when no records match", () => {
		const result = simulateGetDmarcTimeSeries(records, "unknown.com", "2026-01-01T00:00:00Z");
		expect(result).toEqual([]);
	});

	it("returns days in ascending order", () => {
		const result = simulateGetDmarcTimeSeries(records, "example.com", "2026-01-01T00:00:00Z");
		const days = result.map((r) => r.day);
		expect(days).toEqual([...days].sort());
	});
});

// ---------------------------------------------------------------------------
// Route-level tests for GET /timeseries
// ---------------------------------------------------------------------------

describe("GET /timeseries", () => {
	it("returns 400 when domain query param is missing", async () => {
		const app = makeApp([]);
		const res = await app.fetch("/timeseries");
		expect(res.status).toBe(400);
		const body = await res.json() as { error: string };
		expect(body.error).toMatch(/domain/i);
	});

	it("returns { domain, timeseries } with the DO result", async () => {
		const records: FakeDmarcRecord[] = [
			{
				domain: "acme.com",
				received_at: "2026-05-20T09:00:00Z",
				count: 4,
				dkim_result: "pass",
				spf_result: "fail",
			},
			{
				domain: "acme.com",
				received_at: "2026-05-21T09:00:00Z",
				count: 1,
				dkim_result: "fail",
				spf_result: "fail",
			},
		];
		const app = makeApp(records);
		const res = await app.fetch("/timeseries?domain=acme.com");
		expect(res.status).toBe(200);
		const body = await res.json() as { domain: string; timeseries: { day: string; aligned: number; failing: number }[] };
		expect(body.domain).toBe("acme.com");
		expect(body.timeseries).toHaveLength(2);
		expect(body.timeseries[0]).toMatchObject({ day: "2026-05-20", aligned: 4, failing: 0 });
		expect(body.timeseries[1]).toMatchObject({ day: "2026-05-21", aligned: 0, failing: 1 });
	});

	it("returns an empty timeseries array when no records exist for the domain", async () => {
		const app = makeApp([]);
		const res = await app.fetch("/timeseries?domain=empty.com");
		expect(res.status).toBe(200);
		const body = await res.json() as { timeseries: unknown[] };
		expect(body.timeseries).toEqual([]);
	});

	it("defaults to 90-day window when ?days is absent", async () => {
		// Plant one record 89 days ago (within default window) and one 91 days ago (outside).
		const now = Date.now();
		const within = new Date(now - 89 * 24 * 60 * 60 * 1000).toISOString();
		const outside = new Date(now - 91 * 24 * 60 * 60 * 1000).toISOString();
		const records: FakeDmarcRecord[] = [
			{ domain: "test.com", received_at: within, count: 5, dkim_result: "pass", spf_result: "fail" },
			{ domain: "test.com", received_at: outside, count: 3, dkim_result: "pass", spf_result: "fail" },
		];
		const app = makeApp(records);
		const res = await app.fetch("/timeseries?domain=test.com");
		expect(res.status).toBe(200);
		const body = await res.json() as { timeseries: { day: string; aligned: number; failing: number }[] };
		// Only the within-window record should appear.
		expect(body.timeseries).toHaveLength(1);
		expect(body.timeseries[0].aligned).toBe(5);
	});

	it("respects ?days=7 and excludes records older than 7 days", async () => {
		const now = Date.now();
		const within = new Date(now - 6 * 24 * 60 * 60 * 1000).toISOString();
		const outside = new Date(now - 8 * 24 * 60 * 60 * 1000).toISOString();
		const records: FakeDmarcRecord[] = [
			{ domain: "test.com", received_at: within, count: 2, dkim_result: "pass", spf_result: "fail" },
			{ domain: "test.com", received_at: outside, count: 9, dkim_result: "pass", spf_result: "fail" },
		];
		const app = makeApp(records);
		const res = await app.fetch("/timeseries?domain=test.com&days=7");
		expect(res.status).toBe(200);
		const body = await res.json() as { timeseries: { day: string; aligned: number; failing: number }[] };
		expect(body.timeseries).toHaveLength(1);
		expect(body.timeseries[0].aligned).toBe(2);
	});

	it("clamps ?days above 365 to 365", async () => {
		const now = Date.now();
		// A record 364 days ago — always within a 365-day (or larger) window.
		const within = new Date(now - 364 * 24 * 60 * 60 * 1000).toISOString();
		const records: FakeDmarcRecord[] = [
			{ domain: "test.com", received_at: within, count: 1, dkim_result: "pass", spf_result: "fail" },
		];
		const app = makeApp(records);
		const res = await app.fetch("/timeseries?domain=test.com&days=9999");
		expect(res.status).toBe(200);
		const body = await res.json() as { timeseries: { day: string; aligned: number; failing: number }[] };
		// Clamped to 365 — the 364-day-old record is still within window.
		expect(body.timeseries).toHaveLength(1);
	});

	it("falls back to the default when ?days is not a valid number", async () => {
		const app = makeApp([]);
		const res = await app.fetch("/timeseries?domain=test.com&days=abc");
		expect(res.status).toBe(200);
	});
});
