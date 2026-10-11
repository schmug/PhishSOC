// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Threaded folder query + unified-inbox keyset cursor. Drives
 * _getThreadedEmailsImpl through a node:sqlite adapter (pattern:
 * test/durableObject/sidecar-state.test.ts).
 */

import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import type { SqlLike } from "../../workers/durableObject/catchall-intel";
import { _getThreadedEmailsImpl } from "../../workers/durableObject/threaded-emails";

type Seed = { id: string; date: string; thread_id?: string; folder_id?: string; read?: number; subject?: string };

function makeDb(rows: Seed[]): SqlLike {
	const db = new DatabaseSync(":memory:");
	db.exec(`
		CREATE TABLE folders (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, is_deletable INTEGER NOT NULL DEFAULT 1);
		INSERT INTO folders (id, name, is_deletable) VALUES ('inbox','Inbox',0), ('sent','Sent',0), ('draft','Drafts',0);
		CREATE TABLE emails (
			id TEXT PRIMARY KEY, folder_id TEXT NOT NULL, subject TEXT, sender TEXT, recipient TEXT,
			date TEXT, read INTEGER DEFAULT 0, starred INTEGER DEFAULT 0, body TEXT,
			in_reply_to TEXT, email_references TEXT, thread_id TEXT
		);
	`);
	const ins = db.prepare(
		`INSERT INTO emails (id, folder_id, subject, sender, recipient, date, read, starred, body, in_reply_to, email_references, thread_id)
		 VALUES (?, ?, ?, 'x@ext.test', 'me@a.test', ?, ?, 0, 'body', NULL, NULL, ?)`,
	);
	for (const r of rows) {
		ins.run(r.id, r.folder_id ?? "inbox", r.subject ?? `subject ${r.id}`, r.date, r.read ?? 0, r.thread_id ?? null);
	}
	return {
		exec<T = Record<string, unknown>>(query: string, ...params: unknown[]): Iterable<T> {
			return db.prepare(query.trim()).all(...(params as never[])) as T[];
		},
	};
}

const T10 = "2026-09-01T10:00:00.000Z";
const T12 = "2026-09-01T12:00:00.000Z";

describe("_getThreadedEmailsImpl", () => {
	const flat = () => makeDb([{ id: "e-a", date: T10 }, { id: "e-b", date: T12 }, { id: "e-c", date: T12 }]);

	it("orders by date DESC then id DESC and honours offset without a cursor", () => {
		const sql = flat();
		expect(_getThreadedEmailsImpl(sql, { folder: "inbox", limit: 2, offset: 0 }).map((r) => r.id)).toEqual(["e-c", "e-b"]);
		expect(_getThreadedEmailsImpl(sql, { folder: "inbox", limit: 2, offset: 2 }).map((r) => r.id)).toEqual(["e-a"]);
	});

	it("returns only rows strictly after the cursor", () => {
		const sql = flat();
		const q = (date: string, id: string) =>
			_getThreadedEmailsImpl(sql, { folder: "inbox", limit: 10, offset: 0, before: { date, id } }).map((r) => r.id);
		expect(q(T12, "e-c")).toEqual(["e-b", "e-a"]);
		expect(q(T12, "e-b")).toEqual(["e-a"]);
		expect(q(T10, "e-a")).toEqual([]);
	});

	it("ignores offset when a cursor is given", () => {
		const sql = flat();
		const rows = _getThreadedEmailsImpl(sql, { folder: "inbox", limit: 10, offset: 5, before: { date: T12, id: "e-c" } });
		expect(rows.map((r) => r.id)).toEqual(["e-b", "e-a"]);
	});

	it("keys the cursor on the conversation's latest in-folder message", () => {
		const sql = makeDb([
			{ id: "m1", date: "2026-09-01T09:00:00.000Z", thread_id: "t1", subject: "Hello" },
			{ id: "m2", date: "2026-09-01T11:00:00.000Z", thread_id: "t1", subject: "Re: Hello" },
			{ id: "x", date: T10 },
		]);
		const head = _getThreadedEmailsImpl(sql, { folder: "inbox", limit: 10, offset: 0 });
		expect(head.map((r) => [r.id, r.thread_count])).toEqual([["m2", 2], ["x", 1]]);
		const next = _getThreadedEmailsImpl(sql, {
			folder: "inbox",
			limit: 10,
			offset: 0,
			before: { date: "2026-09-01T11:00:00.000Z", id: "m2" },
		});
		expect(next.map((r) => r.id)).toEqual(["x"]);
	});
});
