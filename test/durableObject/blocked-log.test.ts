// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import type { SqlLike } from "../../workers/durableObject/catchall-intel";
import {
	BLOCKED_LOG_MAX_ROWS,
	_appendBlockedLogImpl,
	_listBlockedLogImpl,
	_moveEmailsFromSenderImpl,
} from "../../workers/durableObject/blocked-log";
import { mailboxMigrations } from "../../workers/durableObject/migrations";

function makeSqlLike(): SqlLike {
	const db = new DatabaseSync(":memory:");
	const blocked = mailboxMigrations.find((m) => m.name === "34_blocked_log")!;
	db.exec(blocked.sql);
	db.exec(`CREATE TABLE emails (id TEXT PRIMARY KEY, folder_id TEXT NOT NULL, sender TEXT)`);
	return {
		exec(sql: string, ...params: unknown[]) {
			const stmt = db.prepare(sql);
			return /^\s*select/i.test(sql) ? (stmt.all(...(params as never[])) as never) : (stmt.run(...(params as never[])), [] as never);
		},
	};
}

const row = (i: number, over: Partial<Parameters<typeof _appendBlockedLogImpl>[1]> = {}) => ({
	ts: new Date(Date.UTC(2026, 8, 27, 0, 0, i)).toISOString(),
	rule_id: "r1", tier: "mailbox", action: "drop" as const,
	sender: "x@podview.com", subject: "s", message_id: `m${i}@x`, ...over,
});

describe("blocked_log", () => {
	it("appends, lists newest first, truncates subject to 120", () => {
		const sql = makeSqlLike();
		_appendBlockedLogImpl(sql, row(1, { subject: "y".repeat(300) }), Date.UTC(2026, 8, 27));
		_appendBlockedLogImpl(sql, row(2), Date.UTC(2026, 8, 27));
		const rows = _listBlockedLogImpl(sql, 10);
		expect(rows.map((r) => r.message_id)).toEqual(["m2@x", "m1@x"]);
		expect(rows[1].subject).toHaveLength(120);
	});
	it("dedupes on message_id (sidecar replay) but keeps null ids", () => {
		const sql = makeSqlLike();
		_appendBlockedLogImpl(sql, row(1), Date.UTC(2026, 8, 27));
		_appendBlockedLogImpl(sql, row(1), Date.UTC(2026, 8, 27));
		_appendBlockedLogImpl(sql, row(2, { message_id: null }), Date.UTC(2026, 8, 27));
		_appendBlockedLogImpl(sql, row(3, { message_id: null }), Date.UTC(2026, 8, 27));
		expect(_listBlockedLogImpl(sql, 10)).toHaveLength(3);
	});
	it("prunes beyond the row cap and older than 30 days", () => {
		const sql = makeSqlLike();
		const now = Date.UTC(2026, 8, 27);
		_appendBlockedLogImpl(sql, row(0, { ts: new Date(now - 31 * 86_400_000).toISOString() }), now);
		for (let i = 1; i <= BLOCKED_LOG_MAX_ROWS + 5; i++) _appendBlockedLogImpl(sql, row(i), now);
		const rows = _listBlockedLogImpl(sql, 1000);
		expect(rows).toHaveLength(BLOCKED_LOG_MAX_ROWS);
		expect(rows.some((r) => r.message_id === "m0@x")).toBe(false);
	});
});

describe("_moveEmailsFromSenderImpl", () => {
	it("moves matching senders from the listed folders only", () => {
		const sql = makeSqlLike();
		sql.exec(`INSERT INTO emails VALUES ('1','inbox','noreply@res.podview.com'), ('2','archive','a@podview.com'), ('3','sent','a@podview.com'), ('4','inbox','a@notpodview.com')`);
		expect(_moveEmailsFromSenderImpl(sql, "podview.com", ["inbox", "archive"], "spam")).toBe(2);
		const folders = [...sql.exec<{ id: string; folder_id: string }>(`SELECT id, folder_id FROM emails ORDER BY id`)];
		expect(folders.map((f) => f.folder_id)).toEqual(["spam", "spam", "sent", "inbox"]);
	});
});
