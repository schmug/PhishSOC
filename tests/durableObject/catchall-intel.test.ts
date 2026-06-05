// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Unit tests for CatchallIntelDO (issue #425).
 *
 * The Workers runtime is not available in the Node pool, so we use the
 * vi.mock("cloudflare:workers") + prototype-call pattern (same as
 * tests/dmarc/source-enrichment.test.ts) combined with a real in-memory
 * SQLite database (better-sqlite3) to validate SQL correctness.
 *
 * The DO uses ?NNN positional params (correct Workers runtime syntax).
 * better-sqlite3 binds positional params differently, so normalizeSql()
 * expands ?NNN references into sequential anonymous ? placeholders with
 * repeated argument values — this allows the same SQL to run unchanged
 * in production while the test helper adapts it for better-sqlite3.
 *
 * Each test constructs a fresh in-memory DB, runs the migration DDL, and
 * wraps it in a fake ctx.storage.sql compatible with the DO's exec() calls.
 */

import Database from "better-sqlite3";
import { describe, expect, it, vi } from "vitest";

vi.mock("cloudflare:workers", () => ({ DurableObject: class {} }));

import { CatchallIntelDO, type CatchallProbeEvent } from "../../workers/durableObject/catchall-intel";
import { catchallIntelMigrations } from "../../workers/durableObject/migrations";

// ── Test infrastructure ────────────────────────────────────────────────────

/**
 * Expand ?NNN positional references into sequential anonymous ? placeholders,
 * repeating argument values when the same index appears multiple times.
 *
 * Workers DO SQL uses ?1/?2/.../?N positional params; better-sqlite3 binds
 * anonymous ? in left-to-right order. This adapter lets the DO's SQL run
 * unchanged in production while the test helper normalises it for the driver.
 *
 * Example: `WHERE a = ?1 AND b = ?2 AND a = ?1`, params [x, y]
 *   → SQL:    `WHERE a = ?  AND b = ?  AND a = ?`
 *   → params: [x, y, x]
 */
function normalizeSql(sqlStr: string, params: unknown[]): { sql: string; args: unknown[] } {
	const args: unknown[] = [];
	const sql = sqlStr.replace(/\?(\d+)/g, (_, n: string) => {
		args.push(params[parseInt(n, 10) - 1]);
		return "?";
	});
	return { sql, args };
}

/**
 * Build a fake ctx.storage.sql backed by a real in-memory SQLite database.
 * SELECT / WITH → .all() (returns rows); everything else → .run() (no rows).
 */
function makeFakeSql(db: InstanceType<typeof Database>) {
	return {
		exec(sqlStr: string, ...params: unknown[]) {
			const trimmed = sqlStr.trim();
			const { sql, args } = normalizeSql(trimmed, params);
			if (/^\s*(SELECT|WITH)/i.test(sql)) {
				return db.prepare(sql).all(...args);
			}
			db.prepare(sql).run(...args);
			return [];
		},
	};
}

/**
 * Initialise a fresh in-memory DB with the catchall schema and return a fake
 * `this` suitable for CatchallIntelDO prototype calls.
 */
function makeTestCtx() {
	const db = new Database(":memory:");

	// Strip BEGIN TRANSACTION / COMMIT so db.exec() can run multi-statement DDL
	for (const migration of catchallIntelMigrations) {
		const raw = migration.sql
			.replace(/^\s*BEGIN TRANSACTION\s*;?\s*/i, "")
			.replace(/\s*COMMIT\s*;?\s*$/i, "");
		db.exec(raw);
	}

	const fakeSql = makeFakeSql(db);
	return { ctx: { storage: { sql: fakeSql } } };
}

const BASE_EVENT: CatchallProbeEvent = {
	source_ip: "1.2.3.4",
	sender_domain: "evil.example",
	localpart: "alice",
	sender: "alice@evil.example",
	subject_snippet: "You won a prize",
	score: 72,
	band: "suspicious",
	signals_json: "{}",
};

function call(
	method: "recordCatchallProbe" | "getCatchallSummary",
	ctx: ReturnType<typeof makeTestCtx>,
	...args: unknown[]
) {
	return (CatchallIntelDO.prototype as unknown as Record<string, (...a: unknown[]) => unknown>)[method].call(ctx, ...args);
}

// ── Tests ─────────────────────────────────────────────────────────────────

describe("recordCatchallProbe — rollup upsert", () => {
	it("inserts a new rollup row on first probe", async () => {
		const ctx = makeTestCtx();
		await call("recordCatchallProbe", ctx, BASE_EVENT, {
			retention_days: 30,
			sample_limit: 100,
			now: "2026-01-01T00:00:00.000Z",
		});

		const rows = ctx.ctx.storage.sql.exec(
			"SELECT * FROM probe_rollup",
		) as Array<Record<string, unknown>>;
		expect(rows).toHaveLength(1);
		expect(rows[0].source_ip).toBe("1.2.3.4");
		expect(rows[0].sender_domain).toBe("evil.example");
		expect(Number(rows[0].count)).toBe(1);
		expect(Number(rows[0].max_score)).toBe(72);
		expect(rows[0].first_seen).toBe("2026-01-01T00:00:00.000Z");
		expect(rows[0].last_seen).toBe("2026-01-01T00:00:00.000Z");
	});

	it("increments count and updates max_score and last_seen on subsequent probes", async () => {
		const ctx = makeTestCtx();
		const opts = { retention_days: 30, sample_limit: 100 };

		await call("recordCatchallProbe", ctx, { ...BASE_EVENT, score: 50 }, {
			...opts,
			now: "2026-01-01T00:00:00.000Z",
		});
		await call("recordCatchallProbe", ctx, { ...BASE_EVENT, score: 90 }, {
			...opts,
			now: "2026-01-02T00:00:00.000Z",
		});
		await call("recordCatchallProbe", ctx, { ...BASE_EVENT, score: 60 }, {
			...opts,
			now: "2026-01-03T00:00:00.000Z",
		});

		const rows = ctx.ctx.storage.sql.exec(
			"SELECT * FROM probe_rollup",
		) as Array<Record<string, unknown>>;
		expect(rows).toHaveLength(1);
		expect(Number(rows[0].count)).toBe(3);
		expect(Number(rows[0].max_score)).toBe(90);
		expect(rows[0].first_seen).toBe("2026-01-01T00:00:00.000Z");
		expect(rows[0].last_seen).toBe("2026-01-03T00:00:00.000Z");
	});

	it("updates distinct_localparts to reflect unique localparts tracked", async () => {
		const ctx = makeTestCtx();
		const opts = { retention_days: 30, sample_limit: 100 };

		await call("recordCatchallProbe", ctx, { ...BASE_EVENT, localpart: "alice" }, {
			...opts,
			now: "2026-01-01T00:00:00.000Z",
		});
		await call("recordCatchallProbe", ctx, { ...BASE_EVENT, localpart: "bob" }, {
			...opts,
			now: "2026-01-01T00:01:00.000Z",
		});
		// alice again — should not increment distinct
		await call("recordCatchallProbe", ctx, { ...BASE_EVENT, localpart: "alice" }, {
			...opts,
			now: "2026-01-01T00:02:00.000Z",
		});

		const rows = ctx.ctx.storage.sql.exec(
			"SELECT * FROM probe_rollup",
		) as Array<Record<string, unknown>>;
		expect(Number(rows[0].count)).toBe(3);
		expect(Number(rows[0].distinct_localparts)).toBe(2);
	});
});

describe("recordCatchallProbe — recent ring cap", () => {
	it("never exceeds sample_limit; oldest entry is evicted on overflow", async () => {
		const ctx = makeTestCtx();
		const sampleLimit = 3;
		const opts = { retention_days: 30, sample_limit: sampleLimit };

		for (let i = 0; i < 5; i++) {
			const ts = `2026-01-0${i + 1}T00:00:00.000Z`;
			await call(
				"recordCatchallProbe",
				ctx,
				{ ...BASE_EVENT, localpart: `user${i}`, subject_snippet: `msg ${i}` },
				{ ...opts, now: ts },
			);
		}

		const recent = ctx.ctx.storage.sql.exec(
			"SELECT * FROM probe_recent ORDER BY ts ASC",
		) as Array<Record<string, unknown>>;

		// Ring must not exceed sample_limit
		expect(recent.length).toBe(sampleLimit);
		// Oldest two (msg 0, msg 1) must have been evicted
		const snippets = recent.map((r) => r.subject_snippet as string);
		expect(snippets).not.toContain("msg 0");
		expect(snippets).not.toContain("msg 1");
		expect(snippets).toContain("msg 4");
	});
});

describe("recordCatchallProbe — lazy GC", () => {
	it("deletes rollup and recent rows older than retention_days on write", async () => {
		const ctx = makeTestCtx();
		const opts = { retention_days: 7, sample_limit: 100 };

		// Write an old probe (15 days ago)
		await call(
			"recordCatchallProbe",
			ctx,
			{ ...BASE_EVENT, source_ip: "10.0.0.1" },
			{ ...opts, now: "2026-01-01T00:00:00.000Z" },
		);

		// Write a fresh probe (now); the GC cutoff is 7 days before now
		await call(
			"recordCatchallProbe",
			ctx,
			{ ...BASE_EVENT, source_ip: "10.0.0.2" },
			{ ...opts, now: "2026-01-16T00:00:00.000Z" },
		);

		const rollup = ctx.ctx.storage.sql.exec(
			"SELECT source_ip FROM probe_rollup ORDER BY source_ip",
		) as Array<{ source_ip: string }>;
		// Old rollup row should have been GC'd
		expect(rollup.map((r) => r.source_ip)).not.toContain("10.0.0.1");
		expect(rollup.map((r) => r.source_ip)).toContain("10.0.0.2");

		const recent = ctx.ctx.storage.sql.exec(
			"SELECT source_ip FROM probe_recent",
		) as Array<{ source_ip: string }>;
		expect(recent.map((r) => r.source_ip)).not.toContain("10.0.0.1");
		expect(recent.map((r) => r.source_ip)).toContain("10.0.0.2");
	});

	it("also GCs probe_localparts rows older than retention_days", async () => {
		const ctx = makeTestCtx();
		const opts = { retention_days: 7, sample_limit: 100 };

		await call(
			"recordCatchallProbe",
			ctx,
			{ ...BASE_EVENT, localpart: "stale" },
			{ ...opts, now: "2026-01-01T00:00:00.000Z" },
		);
		await call(
			"recordCatchallProbe",
			ctx,
			{ ...BASE_EVENT, localpart: "fresh" },
			{ ...opts, now: "2026-01-16T00:00:00.000Z" },
		);

		const lp = ctx.ctx.storage.sql.exec(
			"SELECT localpart FROM probe_localparts",
		) as Array<{ localpart: string }>;
		expect(lp.map((r) => r.localpart)).not.toContain("stale");
		expect(lp.map((r) => r.localpart)).toContain("fresh");
	});
});

describe("getCatchallSummary", () => {
	it("returns zero totals and empty arrays when no data", async () => {
		const ctx = makeTestCtx();
		const summary = (await call("getCatchallSummary", ctx, { limit: 10 })) as Awaited<ReturnType<CatchallIntelDO["getCatchallSummary"]>>;

		expect(summary.totals.total_probes).toBe(0);
		expect(summary.totals.source_count).toBe(0);
		expect(summary.totals.distinct_localparts).toBe(0);
		expect(summary.topSources).toHaveLength(0);
		expect(summary.recent).toHaveLength(0);
	});

	it("returns correct totals, topSources, and recent after probes", async () => {
		const ctx = makeTestCtx();
		const opts = { retention_days: 30, sample_limit: 100 };

		// Source A: 3 probes, 2 distinct localparts
		for (let i = 0; i < 3; i++) {
			await call(
				"recordCatchallProbe",
				ctx,
				{ ...BASE_EVENT, source_ip: "1.1.1.1", localpart: i < 2 ? "alice" : "bob" },
				{ ...opts, now: `2026-01-0${i + 1}T00:00:00.000Z` },
			);
		}
		// Source B: 1 probe
		await call(
			"recordCatchallProbe",
			ctx,
			{ ...BASE_EVENT, source_ip: "2.2.2.2", localpart: "charlie" },
			{ ...opts, now: "2026-01-04T00:00:00.000Z" },
		);

		const summary = (await call("getCatchallSummary", ctx, { limit: 10 })) as Awaited<ReturnType<CatchallIntelDO["getCatchallSummary"]>>;

		expect(summary.totals.total_probes).toBe(4);
		expect(summary.totals.source_count).toBe(2);

		// topSources ordered by count DESC: source A first
		expect(summary.topSources).toHaveLength(2);
		expect(summary.topSources[0].source_ip).toBe("1.1.1.1");
		expect(summary.topSources[0].count).toBe(3);
		expect(summary.topSources[1].source_ip).toBe("2.2.2.2");

		// recent ordered by ts DESC: latest first
		expect(summary.recent).toHaveLength(4);
		expect(summary.recent[0].source_ip).toBe("2.2.2.2");
	});

	it("respects the limit parameter", async () => {
		const ctx = makeTestCtx();
		const opts = { retention_days: 30, sample_limit: 100 };

		for (let i = 0; i < 5; i++) {
			await call(
				"recordCatchallProbe",
				ctx,
				{ ...BASE_EVENT, source_ip: `10.0.0.${i + 1}` },
				{ ...opts, now: `2026-01-0${i + 1}T00:00:00.000Z` },
			);
		}

		const summary = (await call("getCatchallSummary", ctx, { limit: 2 })) as Awaited<ReturnType<CatchallIntelDO["getCatchallSummary"]>>;
		expect(summary.topSources).toHaveLength(2);
		expect(summary.recent).toHaveLength(2);
	});
});
