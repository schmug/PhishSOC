// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Unit tests for `CatchallIntelDO` business logic (issue #425).
 *
 * Drives `_recordProbeImpl` and `_getSummaryImpl` directly through a Node
 * `node:sqlite.DatabaseSync` adapter — no Workers runtime required.
 *
 * The `cloudflare:workers` import in catchall-intel.ts (used only by the DO
 * class, not the impl functions) is mocked so the module loads in Node.
 *
 * Covers:
 *   - Rollup upsert: count, distinct_localparts, max_score, last_seen
 *   - Ring buffer never exceeds sampleLimit; oldest evicted on overflow
 *   - Lazy GC deletes rows older than retentionDays (injected clock via `ts`)
 *   - getCatchallSummary shape
 */

import { DatabaseSync } from "node:sqlite";
import { describe, expect, it, beforeEach, vi } from "vitest";

// Mock cloudflare:workers so the module can be imported in Node.
vi.mock("cloudflare:workers", () => ({
	DurableObject: class {
		ctx: unknown;
		env: unknown;
		constructor(state: unknown, env: unknown) { this.ctx = state; this.env = env; }
	},
}));

import {
	_recordProbeImpl,
	_getSummaryImpl,
	_updateProbeDeepScanImpl,
	_checkHarvestAlertImpl,
	type SqlLike,
	type CatchallProbeEvent,
} from "../../workers/durableObject/catchall-intel";

// ---------------------------------------------------------------------------
// node:sqlite adapter — adapts DatabaseSync to our SqlLike interface
// ---------------------------------------------------------------------------

function makeSqlLike(): SqlLike {
	const db = new DatabaseSync(":memory:");

	db.exec(`
        CREATE TABLE probe_rollup (
            source_ip   TEXT NOT NULL,
            sender_domain TEXT NOT NULL,
            count       INTEGER NOT NULL DEFAULT 1,
            distinct_localparts INTEGER NOT NULL DEFAULT 1,
            max_score   INTEGER NOT NULL DEFAULT 0,
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            PRIMARY KEY (source_ip, sender_domain)
        );
        CREATE TABLE probe_localparts (
            source_ip     TEXT NOT NULL,
            sender_domain TEXT NOT NULL,
            localpart     TEXT NOT NULL,
            last_seen     TEXT NOT NULL,
            PRIMARY KEY (source_ip, sender_domain, localpart)
        );
        CREATE TABLE probe_recent (
            id             TEXT PRIMARY KEY,
            ts             TEXT NOT NULL,
            source_ip      TEXT NOT NULL,
            sender_domain  TEXT NOT NULL,
            sender         TEXT NOT NULL,
            localpart      TEXT NOT NULL,
            subject_snippet TEXT NOT NULL,
            score          INTEGER NOT NULL,
            band           TEXT NOT NULL,
            signals_json   TEXT NOT NULL,
            resolved_url          TEXT,
            domain_age_days       INTEGER,
            redirect_chain_length INTEGER
        );
        CREATE INDEX idx_probe_recent_ts ON probe_recent(ts DESC);
        CREATE TABLE harvest_alert_log (
            source_ip      TEXT NOT NULL,
            sender_domain  TEXT NOT NULL,
            alerted_at     TEXT NOT NULL,
            distinct_count INTEGER NOT NULL
        );
        CREATE INDEX idx_harvest_alert_log_lookup
            ON harvest_alert_log(source_ip, sender_domain, alerted_at DESC);
    `);

	return {
		exec<T = Record<string, unknown>>(query: string, ...params: unknown[]): Iterable<T> {
			const trimmed = query.trim();
			const upper = trimmed.toUpperCase();
			if (upper.startsWith("SELECT") || upper.startsWith("WITH")) {
				const stmt = db.prepare(trimmed);
				return stmt.all(...params) as T[];
			}
			const stmt = db.prepare(trimmed);
			stmt.run(...params);
			return [] as T[];
		},
	};
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeEvent(overrides: Partial<CatchallProbeEvent> = {}): CatchallProbeEvent {
	return {
		ts: "2026-06-05T10:00:00.000Z",
		sourceIp: "1.2.3.4",
		senderDomain: "attacker.example",
		sender: "probe@attacker.example",
		localpart: "admin",
		subjectSnippet: "Hello",
		score: 45,
		band: "medium",
		signals: ["dmarc-fail"],
		retentionDays: 30,
		sampleLimit: 50,
		...overrides,
	};
}

// ---------------------------------------------------------------------------
// Tests: rollup upsert
// ---------------------------------------------------------------------------

describe("_recordProbeImpl — rollup upsert", () => {
	let sql: SqlLike;
	beforeEach(() => { sql = makeSqlLike(); });

	it("creates a rollup row on first probe", () => {
		_recordProbeImpl(sql, makeEvent());
		const rows = [...sql.exec<{ count: number; max_score: number }>(
			"SELECT count, max_score FROM probe_rollup WHERE source_ip=? AND sender_domain=?",
			"1.2.3.4", "attacker.example",
		)];
		expect(rows).toHaveLength(1);
		expect(rows[0].count).toBe(1);
		expect(rows[0].max_score).toBe(45);
	});

	it("increments count on subsequent probes from same (ip, domain)", () => {
		_recordProbeImpl(sql, makeEvent());
		_recordProbeImpl(sql, makeEvent({ ts: "2026-06-05T11:00:00.000Z", score: 70 }));
		const rows = [...sql.exec<{ count: number; max_score: number }>(
			"SELECT count, max_score FROM probe_rollup WHERE source_ip=? AND sender_domain=?",
			"1.2.3.4", "attacker.example",
		)];
		expect(rows[0].count).toBe(2);
		expect(rows[0].max_score).toBe(70);
	});

	it("counts distinct localparts correctly", () => {
		_recordProbeImpl(sql, makeEvent({ localpart: "admin" }));
		_recordProbeImpl(sql, makeEvent({ localpart: "admin" })); // same — no increment
		_recordProbeImpl(sql, makeEvent({ localpart: "root" }));  // new — increments
		const rows = [...sql.exec<{ distinct_localparts: number }>(
			"SELECT distinct_localparts FROM probe_rollup WHERE source_ip=? AND sender_domain=?",
			"1.2.3.4", "attacker.example",
		)];
		expect(rows[0].distinct_localparts).toBe(2);
	});
});

// ---------------------------------------------------------------------------
// Tests: ring buffer cap
// ---------------------------------------------------------------------------

describe("_recordProbeImpl — ring buffer cap", () => {
	let sql: SqlLike;
	beforeEach(() => { sql = makeSqlLike(); });

	it("never exceeds sampleLimit rows in probe_recent", () => {
		const limit = 5;
		for (let i = 0; i < 10; i++) {
			_recordProbeImpl(sql, makeEvent({
				ts: `2026-06-05T${String(i).padStart(2, "0")}:00:00.000Z`,
				localpart: `user${i}`,
				sampleLimit: limit,
			}));
		}
		const rows = [...sql.exec<{ cnt: number }>("SELECT COUNT(*) as cnt FROM probe_recent")];
		expect(rows[0].cnt).toBe(limit);
	});

	it("keeps the most recent samples (oldest evicted)", () => {
		const limit = 3;
		for (let i = 0; i < 5; i++) {
			_recordProbeImpl(sql, makeEvent({
				ts: `2026-06-05T0${i}:00:00.000Z`,
				localpart: `user${i}`,
				subjectSnippet: `msg-${i}`,
				sampleLimit: limit,
			}));
		}
		// Only the last 3 (by ts) should remain
		const recent = [...sql.exec<{ subject_snippet: string; ts: string }>(
			"SELECT subject_snippet, ts FROM probe_recent ORDER BY ts ASC",
		)];
		expect(recent).toHaveLength(limit);
		expect(recent[0].subject_snippet).toBe("msg-2");
		expect(recent[2].subject_snippet).toBe("msg-4");
	});
});

// ---------------------------------------------------------------------------
// Tests: lazy GC
// ---------------------------------------------------------------------------

describe("_recordProbeImpl — lazy GC", () => {
	let sql: SqlLike;
	beforeEach(() => { sql = makeSqlLike(); });

	it("deletes rollup rows older than retentionDays (injected clock via ts)", () => {
		// Insert an old probe (31 days ago)
		const oldTs = new Date(Date.now() - 31 * 86_400_000).toISOString();
		_recordProbeImpl(sql, makeEvent({ ts: oldTs, retentionDays: 30 }));

		// Insert a new probe (triggers GC at current time)
		_recordProbeImpl(sql, makeEvent({ ts: new Date().toISOString(), retentionDays: 30 }));

		// Old row should be gone (GC uses ts-based cutoff from the new probe's ts)
		// The new probe's upsert will re-create the same (ip, domain) row.
		// What matters is that the OLD distinct row from before retention is gone.
		// Since both use the same (ip, domain), we verify via probe_recent count.
		const recentRows = [...sql.exec<{ cnt: number }>("SELECT COUNT(*) as cnt FROM probe_recent")];
		// GC only keeps the recent probe; the old one was deleted
		expect(recentRows[0].cnt).toBe(1);
	});

	it("preserves rows within the retention window", () => {
		const recentTs = new Date(Date.now() - 5 * 86_400_000).toISOString(); // 5 days ago
		_recordProbeImpl(sql, makeEvent({ ts: recentTs, sourceIp: "2.3.4.5", retentionDays: 30 }));
		// New probe with current ts — GC should NOT remove the 5-day-old probe
		_recordProbeImpl(sql, makeEvent({ ts: new Date().toISOString(), sourceIp: "5.6.7.8", retentionDays: 30 }));
		const rows = [...sql.exec<{ cnt: number }>("SELECT COUNT(*) as cnt FROM probe_rollup")];
		expect(rows[0].cnt).toBe(2);
	});
});

// ---------------------------------------------------------------------------
// Tests: getCatchallSummary
// ---------------------------------------------------------------------------

describe("_getSummaryImpl", () => {
	let sql: SqlLike;
	beforeEach(() => { sql = makeSqlLike(); });

	it("returns totals, topSources, and recent shaped correctly", () => {
		_recordProbeImpl(sql, makeEvent({ sourceIp: "1.1.1.1", localpart: "admin" }));
		_recordProbeImpl(sql, makeEvent({ sourceIp: "1.1.1.1", localpart: "root" }));
		_recordProbeImpl(sql, makeEvent({ sourceIp: "2.2.2.2", localpart: "info" }));

		const summary = _getSummaryImpl(sql, { limit: 10 });
		expect(summary.totals.distinct_sources).toBe(2);
		expect(summary.totals.probe_count).toBe(3);
		expect(summary.totals.distinct_localparts).toBe(3);
		expect(summary.topSources[0].source_ip).toBe("1.1.1.1");
		expect(summary.topSources[0].count).toBe(2);
		expect(summary.topSources[0].distinct_localparts).toBe(2);
		expect(summary.recent).toHaveLength(3);
		// recent is ordered newest first; signals_json is the stored JSON blob
		expect(typeof summary.recent[0].signals_json).toBe("string");
	});
});

// ---------------------------------------------------------------------------
// Tests: deep-scan write-back (#438)
// ---------------------------------------------------------------------------

describe("_recordProbeImpl — returns the new sample id", () => {
	it("returns the id of the inserted probe_recent row", () => {
		const sql = makeSqlLike();
		const id = _recordProbeImpl(sql, makeEvent());
		expect(typeof id).toBe("string");
		expect(id.length).toBeGreaterThan(0);
		const rows = [...sql.exec<{ id: string }>("SELECT id FROM probe_recent")];
		expect(rows.map((r) => r.id)).toContain(id);
	});
});

describe("_updateProbeDeepScanImpl — writes deep-scan results to the sample row", () => {
	let sql: SqlLike;
	beforeEach(() => { sql = makeSqlLike(); });

	it("sets resolved_url, domain_age_days and redirect_chain_length on the matching row", () => {
		const id = _recordProbeImpl(sql, makeEvent());
		_updateProbeDeepScanImpl(sql, id, {
			resolved_url: "https://phish.example/final",
			domain_age_days: 4,
			redirect_chain_length: 3,
		});
		const [row] = [...sql.exec<{
			resolved_url: string | null; domain_age_days: number | null; redirect_chain_length: number | null;
		}>("SELECT resolved_url, domain_age_days, redirect_chain_length FROM probe_recent WHERE id = ?", id)];
		expect(row.resolved_url).toBe("https://phish.example/final");
		expect(row.domain_age_days).toBe(4);
		expect(row.redirect_chain_length).toBe(3);
	});

	it("is a no-op for an unknown sample id (e.g. evicted before the scan completed)", () => {
		_recordProbeImpl(sql, makeEvent());
		_updateProbeDeepScanImpl(sql, "no-such-id", {
			resolved_url: "https://x.example", domain_age_days: 1, redirect_chain_length: 1,
		});
		const rows = [...sql.exec<{ resolved_url: string | null }>("SELECT resolved_url FROM probe_recent")];
		// The only existing row is untouched (still NULL).
		expect(rows.every((r) => r.resolved_url === null)).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Tests: directory-harvest alerting (#436)
// ---------------------------------------------------------------------------

describe("_checkHarvestAlertImpl — directory-harvest debounce (#436)", () => {
	let sql: SqlLike;
	beforeEach(() => { sql = makeSqlLike(); });

	// Crossing metric is distinct_localparts (NOT raw probe count); 24h window.
	const config = { threshold: 3, window_minutes: 1440 };
	const now = new Date("2026-06-05T12:00:00.000Z");

	/** Record `n` probes from one (ip, domain) pair, each a distinct local-part. */
	function recordDistinctLocalparts(n: number) {
		for (let i = 0; i < n; i++) {
			_recordProbeImpl(sql, makeEvent({ localpart: `user${i}`, ts: now.toISOString() }));
		}
	}

	it("emits no alert when distinct_localparts is below threshold", async () => {
		recordDistinctLocalparts(2); // threshold is 3
		const alerts = await _checkHarvestAlertImpl(sql, makeEvent(), config, now);
		expect(alerts).toHaveLength(0);
		expect([...sql.exec("SELECT * FROM harvest_alert_log")]).toHaveLength(0);
	});

	it("emits exactly one alert when distinct_localparts crosses the threshold", async () => {
		recordDistinctLocalparts(3);
		const alerts = await _checkHarvestAlertImpl(sql, makeEvent(), config, now);
		expect(alerts).toHaveLength(1);
		expect(alerts[0].source_ip).toBe("1.2.3.4");
		expect(alerts[0].sender_domain).toBe("attacker.example");
		expect(alerts[0].distinct_localpart_count).toBe(3);
		// The alert is recorded in the debounce log.
		expect([...sql.exec("SELECT * FROM harvest_alert_log")]).toHaveLength(1);
	});

	it("does not emit a second alert when the pair re-crosses within the 24h window", async () => {
		recordDistinctLocalparts(3);
		const first = await _checkHarvestAlertImpl(sql, makeEvent(), config, now);
		expect(first).toHaveLength(1);

		// 6h later — still inside the 24h debounce window — even though the pair
		// is still over threshold, no second alert fires.
		const sixHoursLater = new Date(now.getTime() + 6 * 60 * 60_000);
		const second = await _checkHarvestAlertImpl(sql, makeEvent(), config, sixHoursLater);
		expect(second).toHaveLength(0);
		expect([...sql.exec("SELECT * FROM harvest_alert_log")]).toHaveLength(1);
	});

	it("emits again once the debounce window has elapsed", async () => {
		recordDistinctLocalparts(3);
		await _checkHarvestAlertImpl(sql, makeEvent(), config, now);

		const afterWindow = new Date(now.getTime() + (config.window_minutes + 1) * 60_000);
		const again = await _checkHarvestAlertImpl(sql, makeEvent(), config, afterWindow);
		expect(again).toHaveLength(1);
		expect([...sql.exec("SELECT * FROM harvest_alert_log")]).toHaveLength(2);
	});
});
