// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Unit tests for sidecar poll-state, audit, dedupe, and retention-reap logic
 * (issue #31).
 *
 * Drives the `_xImpl` functions directly through a Node `node:sqlite.DatabaseSync`
 * adapter — no Workers runtime required. Mirrors the adapter pattern in
 * test/durableObject/catchall-intel.test.ts.
 */

import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import type { SqlLike } from "../../workers/durableObject/catchall-intel";
import {
	_getSidecarStateImpl,
	_putSidecarStateImpl,
	_appendSidecarAuditImpl,
	_findEmailIdByMessageIdImpl,
	_listReapableEmailsImpl,
	_markBodiesReapedImpl,
} from "../../workers/durableObject/sidecar-state";

// ---------------------------------------------------------------------------
// node:sqlite adapter — adapts DatabaseSync to our SqlLike interface
// ---------------------------------------------------------------------------

function makeSqlLike(): SqlLike {
	const db = new DatabaseSync(":memory:");

	db.exec(`
        CREATE TABLE sidecar_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            history_cursor TEXT,
            access_token TEXT,
            token_expires_at INTEGER,
            label_ids TEXT,
            last_poll_at INTEGER,
            last_error TEXT,
            consecutive_failures INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE sidecar_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            gmail_message_id TEXT NOT NULL,
            email_id TEXT NOT NULL,
            action TEXT NOT NULL,
            score INTEGER,
            labels_applied TEXT NOT NULL,
            mode TEXT NOT NULL
        );
        CREATE INDEX idx_sidecar_audit_ts ON sidecar_audit(ts DESC);

        CREATE TABLE emails (
            id TEXT PRIMARY KEY,
            folder_id TEXT,
            date TEXT,
            body TEXT,
            message_id TEXT,
            body_reaped_at TEXT
        );
        CREATE TABLE attachments (
            id TEXT PRIMARY KEY,
            email_id TEXT,
            filename TEXT
        );
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
// Tests
// ---------------------------------------------------------------------------

describe("sidecar_state singleton", () => {
	it("returns null before any write, round-trips a patch, and merges partial patches", () => {
		const sql = makeSqlLike();
		expect(_getSidecarStateImpl(sql)).toBeNull();
		_putSidecarStateImpl(sql, { history_cursor: "100", consecutive_failures: 0 });
		expect(_getSidecarStateImpl(sql)?.history_cursor).toBe("100");
		_putSidecarStateImpl(sql, { last_error: "boom", consecutive_failures: 2 });
		const s = _getSidecarStateImpl(sql)!;
		expect(s.history_cursor).toBe("100"); // untouched by the second patch
		expect(s.consecutive_failures).toBe(2);
		expect(s.last_error).toBe("boom");
	});
});

describe("sidecar_audit", () => {
	it("appends rows", () => {
		const sql = makeSqlLike();
		_appendSidecarAuditImpl(sql, {
			ts: "2026-07-06T00:00:00Z", gmail_message_id: "g1", email_id: "e1",
			action: "quarantine", score: 80, labels_applied: '["PhishPilot/Quarantine"]', mode: "active",
		});
		_appendSidecarAuditImpl(sql, {
			ts: "2026-07-06T00:01:00Z", gmail_message_id: "g2", email_id: "e2",
			action: "allow", score: 0, labels_applied: "[]", mode: "observe",
		});
		const rows = [...sql.exec("SELECT gmail_message_id, mode FROM sidecar_audit ORDER BY id")];
		expect(rows.length).toBe(2);
	});
});

describe("Message-ID dedupe lookup", () => {
	it("finds an email by its RFC Message-ID and returns null on miss", () => {
		const sql = makeSqlLike();
		sql.exec(
			"INSERT INTO emails (id, folder_id, date, body, message_id) VALUES (?, ?, ?, ?, ?)",
			"e1", "inbox", "2026-07-06T00:00:00Z", "hello", "abc@mail.gmail.com",
		);
		expect(_findEmailIdByMessageIdImpl(sql, "abc@mail.gmail.com")).toBe("e1");
		expect(_findEmailIdByMessageIdImpl(sql, "missing@x")).toBeNull();
	});
});

describe("retention reap", () => {
	it("lists only un-reaped emails older than the cutoff, with their attachments", () => {
		const sql = makeSqlLike();
		sql.exec("INSERT INTO emails (id, folder_id, date, body) VALUES ('old', 'inbox', '2026-06-01T00:00:00Z', 'b')");
		sql.exec("INSERT INTO emails (id, folder_id, date, body) VALUES ('new', 'inbox', '2026-07-05T00:00:00Z', 'b')");
		sql.exec("INSERT INTO emails (id, folder_id, date, body, body_reaped_at) VALUES ('done', 'inbox', '2026-06-01T00:00:00Z', '', '2026-06-10T00:00:00Z')");
		sql.exec("INSERT INTO attachments (id, email_id, filename) VALUES ('a1', 'old', 'x.pdf')");
		const rows = _listReapableEmailsImpl(sql, "2026-06-29T00:00:00Z");
		expect(rows.map((r) => r.id)).toEqual(["old"]);
		expect(rows[0].attachments).toEqual([{ id: "a1", filename: "x.pdf" }]);
	});

	it("marks bodies reaped: empties body, stamps body_reaped_at, deletes attachment rows, preserves verdict metadata columns", () => {
		const sql = makeSqlLike();
		sql.exec("INSERT INTO emails (id, folder_id, date, body, message_id) VALUES ('old', 'inbox', '2026-06-01T00:00:00Z', 'secret', 'm@x')");
		sql.exec("INSERT INTO attachments (id, email_id, filename) VALUES ('a1', 'old', 'x.pdf')");
		const n = _markBodiesReapedImpl(sql, ["old"], "2026-07-06T00:00:00Z");
		expect(n).toBe(1);
		const row = [...sql.exec("SELECT body, body_reaped_at, message_id FROM emails WHERE id = 'old'")][0] as Record<string, unknown>;
		expect(row.body).toBe("");
		expect(row.body_reaped_at).toBe("2026-07-06T00:00:00Z");
		expect(row.message_id).toBe("m@x"); // metadata survives
		expect([...sql.exec("SELECT id FROM attachments WHERE email_id = 'old'")].length).toBe(0);
	});

	it("markBodiesReaped with an empty id list is a no-op returning 0", () => {
		const sql = makeSqlLike();
		expect(_markBodiesReapedImpl(sql, [], "2026-07-06T00:00:00Z")).toBe(0);
	});
});
