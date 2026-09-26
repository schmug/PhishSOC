// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Outbound LLM verdict cache (migration 33): hit, miss, expiry, overwrite and
 * pruning, driven through node:sqlite (pattern: recipient-graph.test.ts).
 */

import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import type { SqlLike } from "../../workers/durableObject/catchall-intel";
import { mailboxMigrations } from "../../workers/durableObject/migrations";
import {
	SEND_RISK_LLM_CACHE_TTL_MS as TTL,
	_getSendRiskLlmCacheImpl as get,
	_putSendRiskLlmCacheImpl as put,
} from "../../workers/durableObject/send-risk-llm-cache";

const MIGRATION_33 = mailboxMigrations.find((m) => m.name === "33_send_risk_llm_cache")!;
const T0 = 1_800_000_000_000;

function makeDb(): { sql: SqlLike; db: DatabaseSync } {
	const db = new DatabaseSync(":memory:");
	db.exec(MIGRATION_33.sql);
	const sql: SqlLike = {
		exec<T = Record<string, unknown>>(query: string, ...params: unknown[]): Iterable<T> {
			return db.prepare(query.trim()).all(...(params as never[])) as T[];
		},
	};
	return { sql, db };
}

describe("send-risk LLM cache", () => {
	it("migration 33 is the last mailbox migration", () => {
		expect(mailboxMigrations.at(-1)?.name).toBe("33_send_risk_llm_cache");
	});

	it("misses on an unknown key", () => {
		expect(get(makeDb().sql, "k", T0)).toBeNull();
	});

	it("hits within the TTL", () => {
		const { sql } = makeDb();
		put(sql, "k", { label: "victim_response", confidence: 0.87 }, T0);
		expect(get(sql, "k", T0 + TTL - 1)).toEqual({ label: "victim_response", confidence: 0.87 });
	});

	it("expires at the TTL", () => {
		const { sql } = makeDb();
		put(sql, "k", { label: "safe", confidence: 0.9 }, T0);
		expect(get(sql, "k", T0 + TTL)).toBeNull();
	});

	it("overwrites a key and restarts its TTL", () => {
		const { sql } = makeDb();
		put(sql, "k", { label: "safe", confidence: 0.9 }, T0);
		put(sql, "k", { label: "suspicious", confidence: 0.5 }, T0 + TTL - 1);
		expect(get(sql, "k", T0 + TTL + 1)).toEqual({ label: "suspicious", confidence: 0.5 });
	});

	it("prunes expired rows on write", () => {
		const { sql, db } = makeDb();
		put(sql, "old", { label: "safe", confidence: 0.9 }, T0);
		put(sql, "new", { label: "safe", confidence: 0.9 }, T0 + TTL);
		const keys = db.prepare("SELECT key FROM send_risk_llm_cache").all().map((r) => (r as { key: string }).key);
		expect(keys).toEqual(["new"]);
	});

	it("never stores or returns a label outside the outbound set", () => {
		const { sql, db } = makeDb();
		put(sql, "k", { label: "unavailable" as never, confidence: 0 }, T0);
		expect(db.prepare("SELECT COUNT(*) AS n FROM send_risk_llm_cache").get()).toEqual({ n: 0 });
		db.prepare("INSERT INTO send_risk_llm_cache VALUES ('bad', 'error', 0, ?)").run(T0);
		expect(get(sql, "bad", T0)).toBeNull();
	});
});
