// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

/**
 * D1 compatibility lint over the migration files.
 *
 * `tests/helpers/d1.ts` applies these migrations through better-sqlite3, which
 * is stock SQLite and MORE PERMISSIVE than D1. Verified 2026-09-22 on SQLite
 * 3.53.0: `ALTER TABLE t ADD COLUMN c INTEGER NOT NULL DEFAULT (unixepoch() *
 * 1000)` is accepted locally but D1 rejects it with
 *   Cannot add a column with non-constant default: SQLITE_ERROR [code: 7500]
 *
 * So a migration can pass the whole hub suite and still be impossible to apply
 * to production. `0005_corroboration_contributors_first_seen.sql` did exactly
 * that and blocked 0006/0007 for months. Nothing in a better-sqlite3-backed
 * test can catch this — it has to be a lint over the SQL text.
 *
 * To add a column with a computed initial value, use a constant DEFAULT and
 * backfill with a following UPDATE.
 */
const MIGRATIONS_DIR = resolve(__dirname, "../migrations");

function migrationFiles(): string[] {
	return readdirSync(MIGRATIONS_DIR)
		.filter((f) => f.endsWith(".sql"))
		.sort();
}

// ADD COLUMN ... DEFAULT followed by "(" (a parenthesised expression) or by one
// of the CURRENT_* keywords. Both are non-constant and both are rejected by D1.
const NON_CONSTANT_DEFAULT =
	/ADD\s+COLUMN\b[^;]*?\bDEFAULT\s*(\(|CURRENT_TIME\b|CURRENT_DATE\b|CURRENT_TIMESTAMP\b)/is;

describe("migrations are D1-applicable", () => {
	it("finds migration files to check", () => {
		expect(migrationFiles().length).toBeGreaterThan(0);
	});

	it.each(migrationFiles())(
		"%s has no ADD COLUMN with a non-constant DEFAULT",
		(file) => {
			const sql = readFileSync(resolve(MIGRATIONS_DIR, file), "utf-8");
			// Strip line comments so a `-- DEFAULT (...)` note cannot trip the lint.
			const stripped = sql.replace(/^\s*--.*$/gm, "");
			const statements = stripped.split(";").filter((s) => /ADD\s+COLUMN/i.test(s));
			for (const stmt of statements) {
				expect(
					NON_CONSTANT_DEFAULT.test(stmt),
					`${file}: D1 rejects a non-constant ADD COLUMN default (SQLITE_ERROR 7500). ` +
						`Use a constant DEFAULT plus a backfill UPDATE. Offending statement:\n${stmt.trim()}`,
				).toBe(false);
			}
		},
	);
});

/**
 * The flip side of the constant-default rule: because 0005 can only declare
 * `DEFAULT 0`, any INSERT that omits first_seen would write 0 and silently
 * drop out of the `other.first_seen >= sinceMs` window in
 * src/routes/corroboration.ts. Guard that the insert supplies it.
 */
describe("corroboration_contributors inserts supply first_seen", () => {
	it("does not rely on the column default", () => {
		const src = readFileSync(
			resolve(__dirname, "../src/lib/aggregate.ts"),
			"utf-8",
		);
		const insert = src.match(
			/INSERT\s+OR\s+IGNORE\s+INTO\s+corroboration_contributors\s*\(([^)]*)\)/i,
		);
		expect(insert, "insert into corroboration_contributors not found").not.toBeNull();
		expect(
			insert![1].toLowerCase(),
			"INSERT must name first_seen — migration 0005's constant DEFAULT 0 would " +
				"otherwise put every new contributor outside every recency window.",
		).toContain("first_seen");
	});
});
