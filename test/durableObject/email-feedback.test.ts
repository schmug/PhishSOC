// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * "Not phish" label store (issue #751). Real migration SQL on node:sqlite.
 * Synthetic mail only.
 */

import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import type { SqlLike } from "../../workers/durableObject/catchall-intel";
import { _getEmailFeedbackImpl, _markNotPhishImpl } from "../../workers/durableObject/email-feedback";
import { mailboxMigrations } from "../../workers/durableObject/migrations";

function makeDb() {
	const db = new DatabaseSync(":memory:");
	db.exec(`CREATE TABLE emails (id TEXT PRIMARY KEY, security_verdict TEXT, security_score INTEGER)`);
	db.exec(mailboxMigrations.find((m) => m.name === "36_email_feedback")!.sql);
	const sql: SqlLike = {
		exec(q: string, ...params: unknown[]) {
			const stmt = db.prepare(q);
			return /^\s*select/i.test(q) ? (stmt.all(...(params as never[])) as never) : (stmt.run(...(params as never[])), [] as never);
		},
	};
	return { db, sql };
}

const verdict = JSON.stringify({ action: "quarantine", score: 72 });

describe("email_feedback", () => {
	it("persists label with timestamp and the verdict snapshot", () => {
		const { db, sql } = makeDb();
		db.prepare(`INSERT INTO emails VALUES ('e1', ?, 72)`).run(verdict);
		const fb = _markNotPhishImpl(sql, "e1", "2026-10-04T12:00:00.000Z");
		expect(fb).toEqual({
			email_id: "e1", label: "not_phish", created_at: "2026-10-04T12:00:00.000Z",
			verdict_action: "quarantine", verdict_score: 72,
		});
		expect(_getEmailFeedbackImpl(sql, "e1")).toEqual(fb);
	});

	it("is idempotent: a second click keeps one row and the first timestamp", () => {
		const { db, sql } = makeDb();
		db.prepare(`INSERT INTO emails VALUES ('e1', ?, 72)`).run(verdict);
		_markNotPhishImpl(sql, "e1", "2026-10-04T12:00:00.000Z");
		const again = _markNotPhishImpl(sql, "e1", "2026-10-04T13:00:00.000Z");
		expect(again?.created_at).toBe("2026-10-04T12:00:00.000Z");
		expect(db.prepare(`SELECT COUNT(*) AS n FROM email_feedback`).get()).toEqual({ n: 1 });
	});

	it("returns null for an unknown email and writes nothing", () => {
		const { db, sql } = makeDb();
		expect(_markNotPhishImpl(sql, "nope", "2026-10-04T12:00:00.000Z")).toBeNull();
		expect(db.prepare(`SELECT COUNT(*) AS n FROM email_feedback`).get()).toEqual({ n: 0 });
	});

	it("tolerates a missing or malformed verdict and leaves the email row untouched", () => {
		const { db, sql } = makeDb();
		db.prepare(`INSERT INTO emails VALUES ('e1', 'not json', NULL)`).run();
		const fb = _markNotPhishImpl(sql, "e1", "2026-10-04T12:00:00.000Z");
		expect(fb).toMatchObject({ verdict_action: null, verdict_score: null });
		expect(db.prepare(`SELECT * FROM emails`).get()).toEqual({ id: "e1", security_verdict: "not json", security_score: null });
	});

	it("returns null feedback for an unlabeled email", () => {
		const { db, sql } = makeDb();
		db.prepare(`INSERT INTO emails VALUES ('e1', ?, 72)`).run(verdict);
		expect(_getEmailFeedbackImpl(sql, "e1")).toBeNull();
	});
});
