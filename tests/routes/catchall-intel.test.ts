// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Route-level tests for `GET /api/v1/domains/:domain/catchall-intel` (#427).
 *
 * Mirrors the handler in `workers/index.ts` (same pattern as me.test.ts /
 * config.test.ts): builds a minimal Hono app with just the handler under test
 * so the full worker graph isn't loaded. The DO is stubbed inline.
 */

import { DatabaseSync } from "node:sqlite";
import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";

vi.mock("cloudflare:workers", () => ({
	DurableObject: class {
		ctx: unknown;
		env: unknown;
		constructor(state: unknown, env: unknown) { this.ctx = state; this.env = env; }
	},
}));
import {
	_getSummaryImpl,
	_recordProbeImpl,
	type SqlLike,
} from "../../workers/durableObject/catchall-intel";

// ---------------------------------------------------------------------------
// Types (mirrors workers/index.ts definitions)
// ---------------------------------------------------------------------------

interface CatchallSourceRollup {
	source_ip: string;
	sender_domain: string;
	count: number;
	distinct_localparts: number;
	max_score: number;
	first_seen: string;
	last_seen: string;
}

interface CatchallRecentSample {
	id: string;
	ts: string;
	source_ip: string;
	sender_domain: string;
	sender: string;
	localpart: string;
	subject_snippet: string;
	score: number;
	band: string;
	signals_json: string;
}

interface CatchallSummary {
	totals: { probe_count: number; distinct_sources: number; distinct_localparts: number };
	topSources: CatchallSourceRollup[];
	recent: CatchallRecentSample[];
}

// ---------------------------------------------------------------------------
// DO stub
// ---------------------------------------------------------------------------

function makeCatchallIntelDO(
	response: CatchallSummary | "throw",
): {
	idFromName: (name: string) => { id: string };
	get: (id: { id: string }) => { getCatchallSummary: (opts: { limit: number }) => Promise<CatchallSummary> };
} {
	return {
		idFromName: (name: string) => ({ id: `do-id:${name}` }),
		get: (_id) => ({
			getCatchallSummary: async (_opts) => {
				if (response === "throw") throw new Error("DO unavailable");
				return response;
			},
		}),
	};
}

// ---------------------------------------------------------------------------
// Handler mirror (keep in sync with workers/index.ts)
// ---------------------------------------------------------------------------

const DOMAIN_REGEX =
	/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

function emptyCatchallSummary(): CatchallSummary {
	return { totals: { probe_count: 0, distinct_sources: 0, distinct_localparts: 0 }, topSources: [], recent: [] };
}

type CatchallIntelDONamespace = ReturnType<typeof makeCatchallIntelDO>;

function makeApp(catchallIntel: CatchallIntelDONamespace) {
	const app = new Hono<{ Bindings: { CATCHALL_INTEL: CatchallIntelDONamespace } }>();

	app.get("/api/v1/domains/:domain/catchall-intel", async (c) => {
		const raw = c.req.param("domain") ?? "";
		const domain = decodeURIComponent(raw).toLowerCase();
		if (!DOMAIN_REGEX.test(domain)) return c.json({ error: "Malformed domain" }, 400);

		const limit = Math.min(parseInt(c.req.query("limit") ?? "20", 10) || 20, 100);

		try {
			const doId = c.env.CATCHALL_INTEL.idFromName(domain);
			const stub = c.env.CATCHALL_INTEL.get(doId) as unknown as {
				getCatchallSummary(opts: { limit: number }): Promise<CatchallSummary>;
			};
			const summary = await stub.getCatchallSummary({ limit });
			return c.json(summary);
		} catch {
			return c.json(emptyCatchallSummary());
		}
	});

	return app;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const populated: CatchallSummary = {
	totals: { probe_count: 42, distinct_sources: 3, distinct_localparts: 17 },
	topSources: [
		{
			source_ip: "198.51.100.5",
			sender_domain: "evil.example",
			count: 30,
			distinct_localparts: 12,
			max_score: 85,
			first_seen: "2026-06-01T00:00:00Z",
			last_seen: "2026-06-05T12:00:00Z",
		},
	],
	recent: [
		{
			id: "sample-1",
			ts: "2026-06-05T12:00:00Z",
			source_ip: "198.51.100.5",
			sender_domain: "evil.example",
			sender: "probe@evil.example",
			localpart: "admin",
			subject_snippet: "Test",
			score: 75,
			band: "high",
			signals_json: "[]",
		},
	],
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Auth boundary: the handler is mounted in `apiApp` (`workers/index.ts`) and
// `workers/app.ts` wraps the whole `apiApp` under the CF-Access JWT middleware
// (same boundary as /api/v1/org/overview). The handler itself adds no auth —
// the middleware is the gate. These tests exercise the handler contract only.

describe("GET /api/v1/domains/:domain/catchall-intel (#427)", () => {
	it("returns the real CatchallIntelDO summary shape (not a mocked API-only stub)", async () => {
		const db = new DatabaseSync(":memory:");
		db.exec(`
			CREATE TABLE probe_rollup (
				source_ip TEXT NOT NULL, sender_domain TEXT NOT NULL,
				count INTEGER NOT NULL DEFAULT 1,
				distinct_localparts INTEGER NOT NULL DEFAULT 0,
				max_score INTEGER NOT NULL DEFAULT 0,
				first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
				PRIMARY KEY (source_ip, sender_domain)
			);
			CREATE TABLE probe_localparts (
				source_ip TEXT NOT NULL, sender_domain TEXT NOT NULL,
				localpart TEXT NOT NULL, last_seen TEXT NOT NULL,
				PRIMARY KEY (source_ip, sender_domain, localpart)
			);
			CREATE TABLE probe_recent (
				id TEXT PRIMARY KEY, ts TEXT NOT NULL,
				source_ip TEXT NOT NULL, sender_domain TEXT NOT NULL,
				sender TEXT NOT NULL, localpart TEXT NOT NULL,
				subject_snippet TEXT NOT NULL, score INTEGER NOT NULL,
				band TEXT NOT NULL, signals_json TEXT NOT NULL
			);
		`);
		const sql: SqlLike = {
			exec<T = Record<string, unknown>>(query: string, ...params: unknown[]) {
				return db.prepare(query).all(...params) as Iterable<T>;
			},
		};
		_recordProbeImpl(sql, {
			ts: "2026-06-05T12:00:00Z",
			sourceIp: "198.51.100.5",
			senderDomain: "evil.example",
			sender: "probe@evil.example",
			localpart: "admin",
			subjectSnippet: "Test",
			score: 75,
			band: "high",
			signals: ["spf=fail"],
			retentionDays: 30,
			sampleLimit: 50,
		});

		const do_ = {
			idFromName: (name: string) => ({ id: name }),
			get: (_id: { id: string }) => ({
				getCatchallSummary: async (opts: { limit: number }) => _getSummaryImpl(sql, opts),
			}),
		};
		const app = makeApp(do_);
		const res = await app.request(
			"/api/v1/domains/acme.com/catchall-intel",
			{},
			{ CATCHALL_INTEL: do_ },
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as CatchallSummary;
		expect(body.totals.probe_count).toBe(1);
		expect(body.totals.distinct_sources).toBe(1);
		expect(body.totals.distinct_localparts).toBe(1);
		expect(body.topSources[0].source_ip).toBe("198.51.100.5");
		expect(body.recent[0].localpart).toBe("admin");
		expect(body.recent[0].signals_json).toBe(JSON.stringify(["spf=fail"]));
	});

	it("returns { totals, topSources, recent } for a domain with probe data", async () => {
		const do_ = makeCatchallIntelDO(populated);
		const app = makeApp(do_);
		const res = await app.request(
			"/api/v1/domains/acme.com/catchall-intel",
			{},
			{ CATCHALL_INTEL: do_ },
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as CatchallSummary;
		expect(body.totals.probe_count).toBe(42);
		expect(body.totals.distinct_sources).toBe(3);
		expect(body.totals.distinct_localparts).toBe(17);
		expect(body.topSources).toHaveLength(1);
		expect(body.topSources[0].source_ip).toBe("198.51.100.5");
		expect(body.recent).toHaveLength(1);
		expect(body.recent[0].localpart).toBe("admin");
	});

	it("returns an empty summary when the DO has no probe data", async () => {
		const empty = emptyCatchallSummary();
		const do_ = makeCatchallIntelDO(empty);
		const app = makeApp(do_);
		const res = await app.request(
			"/api/v1/domains/quiet.example/catchall-intel",
			{},
			{ CATCHALL_INTEL: do_ },
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as CatchallSummary;
		expect(body.totals.probe_count).toBe(0);
		expect(body.topSources).toEqual([]);
		expect(body.recent).toEqual([]);
	});

	it("returns an empty summary when the DO throws (graceful degradation)", async () => {
		const do_ = makeCatchallIntelDO("throw");
		const app = makeApp(do_);
		const res = await app.request(
			"/api/v1/domains/acme.com/catchall-intel",
			{},
			{ CATCHALL_INTEL: do_ },
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as CatchallSummary;
		expect(body.totals.probe_count).toBe(0);
		expect(body.topSources).toEqual([]);
	});

	it("returns 400 for a malformed domain", async () => {
		const do_ = makeCatchallIntelDO(emptyCatchallSummary());
		const app = makeApp(do_);
		// Empty string produces /domains//catchall-intel which Hono routes as 404
		// (the param never reaches the handler), so it's excluded from this list.
		for (const bad of ["no-tld", "has@at.com", "has%2Fpath.com", "https%3A%2F%2Fevil.com"]) {
			const res = await app.request(
				`/api/v1/domains/${bad}/catchall-intel`,
				{},
				{ CATCHALL_INTEL: do_ },
			);
			expect(res.status, `expected 400 for "${bad}"`).toBe(400);
		}
	});

	it("caps limit at 100 and defaults to 20", async () => {
		let capturedLimit = 0;
		const do_: CatchallIntelDONamespace = {
			idFromName: (name) => ({ id: name }),
			get: (_id) => ({
				getCatchallSummary: async (opts) => {
					capturedLimit = opts.limit;
					return emptyCatchallSummary();
				},
			}),
		};
		const app = makeApp(do_);

		await app.request("/api/v1/domains/acme.com/catchall-intel", {}, { CATCHALL_INTEL: do_ });
		expect(capturedLimit).toBe(20);

		await app.request(
			"/api/v1/domains/acme.com/catchall-intel?limit=999",
			{},
			{ CATCHALL_INTEL: do_ },
		);
		expect(capturedLimit).toBe(100);

		await app.request(
			"/api/v1/domains/acme.com/catchall-intel?limit=50",
			{},
			{ CATCHALL_INTEL: do_ },
		);
		expect(capturedLimit).toBe(50);
	});
});
