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
	_acquirePollLeaseImpl,
	_appendSidecarAuditImpl,
	_findSidecarAuditPendingLabelsImpl,
	_updateSidecarAuditLabelsImpl,
	_appendSidecarEventImpl,
	_listSidecarEventsImpl,
	_latestSidecarGapImpl,
	_findEmailIdByMessageIdImpl,
	_findEmailIdByProviderMessageIdImpl,
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
            history_page_token TEXT,
            access_token TEXT,
            token_expires_at INTEGER,
            label_ids TEXT,
            last_poll_at INTEGER,
            last_error TEXT,
            consecutive_failures INTEGER NOT NULL DEFAULT 0,
            poll_lease_until INTEGER,
            label_error TEXT,
            label_failure_count INTEGER NOT NULL DEFAULT 0
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
        CREATE INDEX idx_sidecar_audit_gmail_message_id ON sidecar_audit(gmail_message_id);

        CREATE TABLE sidecar_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            kind TEXT NOT NULL,
            old_cursor TEXT,
            new_cursor TEXT,
            detail TEXT
        );
        CREATE INDEX idx_sidecar_events_ts ON sidecar_events(ts DESC);

        CREATE TABLE emails (
            id TEXT PRIMARY KEY,
            folder_id TEXT,
            date TEXT,
            body TEXT,
            message_id TEXT,
            provider_message_id TEXT,
            body_reaped_at TEXT
        );
        CREATE INDEX idx_emails_provider_message_id ON emails(provider_message_id);
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

describe("poll lease (#591)", () => {
	const T0 = 1_800_000_000_000;
	const TTL = 5 * 60 * 1000;

	it("acquires on a fresh DB (no state row yet) and blocks a second acquire inside the TTL", () => {
		const sql = makeSqlLike();
		expect(_acquirePollLeaseImpl(sql, T0, TTL)).toBe(true);
		// Overlapping tick, one minute later: the lease is held → refused.
		expect(_acquirePollLeaseImpl(sql, T0 + 60_000, TTL)).toBe(false);
	});

	it("an expired lease is stealable — a crashed poller never wedges the mailbox past the TTL", () => {
		const sql = makeSqlLike();
		expect(_acquirePollLeaseImpl(sql, T0, TTL)).toBe(true);
		// Poller crashed without releasing. At exactly now >= lease_until the
		// next tick steals the lease and re-arms it.
		expect(_acquirePollLeaseImpl(sql, T0 + TTL, TTL)).toBe(true);
		// ...and the stolen lease is itself held again.
		expect(_acquirePollLeaseImpl(sql, T0 + TTL + 60_000, TTL)).toBe(false);
	});

	it("release via the putSidecarState patch (poll_lease_until: null) frees the lease immediately", () => {
		const sql = makeSqlLike();
		expect(_acquirePollLeaseImpl(sql, T0, TTL)).toBe(true);
		// Success/failure paths release by patching the column to null.
		_putSidecarStateImpl(sql, { poll_lease_until: null });
		expect(_acquirePollLeaseImpl(sql, T0 + 1_000, TTL)).toBe(true);
	});

	it("patch-only semantics: a state patch WITHOUT poll_lease_until leaves a held lease intact", () => {
		const sql = makeSqlLike();
		expect(_acquirePollLeaseImpl(sql, T0, TTL)).toBe(true);
		_putSidecarStateImpl(sql, { history_cursor: "200", last_error: null });
		expect(_acquirePollLeaseImpl(sql, T0 + 1_000, TTL)).toBe(false);
		expect(_getSidecarStateImpl(sql)?.history_cursor).toBe("200");
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

describe("durable label-failure signal (#590)", () => {
	it("label_error / label_failure_count round-trip through state patches and survive unrelated patches", () => {
		const sql = makeSqlLike();
		_putSidecarStateImpl(sql, { label_error: "label write failed: 403", label_failure_count: 2 });
		let s = _getSidecarStateImpl(sql)!;
		expect(s.label_error).toBe("label write failed: 403");
		expect(s.label_failure_count).toBe(2);
		// A label-quiet poll patches other keys only — patch-only semantics keep
		// the durable signal raised (the point-a fix: no flap back to healthy).
		_putSidecarStateImpl(sql, { last_poll_at: 123, last_error: null, consecutive_failures: 0 });
		s = _getSidecarStateImpl(sql)!;
		expect(s.label_error).toBe("label write failed: 403");
		expect(s.label_failure_count).toBe(2);
		// Only a successful label write clears it (explicit patch).
		_putSidecarStateImpl(sql, { label_error: null, label_failure_count: 0 });
		s = _getSidecarStateImpl(sql)!;
		expect(s.label_error).toBeNull();
		expect(s.label_failure_count).toBe(0);
	});
});

describe("audit lookup for label backfill (#590)", () => {
	const auditRow = (gmailId: string, labels: string, mode: string, ts = "2026-07-06T00:00:00Z") => ({
		ts, gmail_message_id: gmailId, email_id: `e-${gmailId}`,
		action: "quarantine", score: 90, labels_applied: labels, mode,
	});

	it("returns the pending active-mode row (labels_applied '[]') and null after backfill", () => {
		const sql = makeSqlLike();
		expect(_findSidecarAuditPendingLabelsImpl(sql, "g1")).toBeNull();
		_appendSidecarAuditImpl(sql, auditRow("g1", "[]", "active"));
		const pending = _findSidecarAuditPendingLabelsImpl(sql, "g1")!;
		expect(pending).toMatchObject({ action: "quarantine" });
		expect(typeof pending.id).toBe("number");
		// Backfill success: the SAME row is updated in place — never a second
		// row, so the one-audit-row-per-verdict-decision contract holds.
		_updateSidecarAuditLabelsImpl(sql, pending.id, '["PhishPilot/Quarantine"]');
		expect(_findSidecarAuditPendingLabelsImpl(sql, "g1")).toBeNull();
		const rows = [...sql.exec("SELECT labels_applied FROM sidecar_audit WHERE gmail_message_id = 'g1'")];
		expect(rows.length).toBe(1);
		expect((rows[0] as { labels_applied: string }).labels_applied).toBe('["PhishPilot/Quarantine"]');
	});

	it("ignores rows whose labels were applied and other messages' rows", () => {
		const sql = makeSqlLike();
		_appendSidecarAuditImpl(sql, auditRow("g1", '["PhishPilot/Quarantine"]', "active"));
		_appendSidecarAuditImpl(sql, auditRow("g2", "[]", "active"));
		expect(_findSidecarAuditPendingLabelsImpl(sql, "g1")).toBeNull();
		expect(_findSidecarAuditPendingLabelsImpl(sql, "g2")).not.toBeNull();
	});

	it("never selects observe-mode rows: empty labels are by design there, not a failure", () => {
		const sql = makeSqlLike();
		_appendSidecarAuditImpl(sql, auditRow("g1", "[]", "observe"));
		expect(_findSidecarAuditPendingLabelsImpl(sql, "g1")).toBeNull();
	});

	it("picks the LATEST pending row when a message somehow has several", () => {
		const sql = makeSqlLike();
		_appendSidecarAuditImpl(sql, { ...auditRow("g1", "[]", "active", "2026-07-05T00:00:00Z"), action: "tag" });
		_appendSidecarAuditImpl(sql, auditRow("g1", "[]", "active", "2026-07-06T00:00:00Z"));
		expect(_findSidecarAuditPendingLabelsImpl(sql, "g1")).toMatchObject({ action: "quarantine" });
	});
});

describe("sidecar_events (durable history-gap record, #594)", () => {
	const gap = (ts: string, oldCursor: string, newCursor: string) => ({
		ts, kind: "history-gap", old_cursor: oldCursor, new_cursor: newCursor,
		detail: "cursor expired past Gmail history retention; mail during the gap was not scored",
	});

	it("appends events and lists them newest-first, queryable per mailbox DO", () => {
		const sql = makeSqlLike();
		expect(_listSidecarEventsImpl(sql)).toEqual([]);
		_appendSidecarEventImpl(sql, gap("2026-07-01T00:00:00Z", "100", "900"));
		_appendSidecarEventImpl(sql, gap("2026-07-06T00:00:00Z", "900", "4200"));
		const rows = _listSidecarEventsImpl(sql);
		// DO SQLite rowsWritten counts index rows, so insert success is asserted
		// via the read-back count (> 0), never an exact rowsWritten figure.
		expect(rows.length).toBeGreaterThan(0);
		expect(rows.map((r) => r.ts)).toEqual(["2026-07-06T00:00:00Z", "2026-07-01T00:00:00Z"]);
		expect(rows[0]).toMatchObject({ kind: "history-gap", old_cursor: "900", new_cursor: "4200" });
	});

	it("latestSidecarGap returns null with no events and the most recent gap row otherwise", () => {
		const sql = makeSqlLike();
		expect(_latestSidecarGapImpl(sql)).toBeNull();
		_appendSidecarEventImpl(sql, gap("2026-07-01T00:00:00Z", "100", "900"));
		_appendSidecarEventImpl(sql, gap("2026-07-06T00:00:00Z", "900", "4200"));
		expect(_latestSidecarGapImpl(sql)).toMatchObject({
			ts: "2026-07-06T00:00:00Z", old_cursor: "900", new_cursor: "4200",
		});
	});

	it("a history-gap event survives a subsequent clean-poll state write resetting last_error", () => {
		const sql = makeSqlLike();
		// The re-anchor poll: durable event + transient last_error.
		_appendSidecarEventImpl(sql, gap("2026-07-06T00:00:00Z", "100", "900"));
		_putSidecarStateImpl(sql, { history_cursor: "900", last_error: "history gap: cursor expired", consecutive_failures: 0 });
		// One clean poll later: last_error resets to null...
		_putSidecarStateImpl(sql, { history_cursor: "901", last_error: null, consecutive_failures: 0 });
		expect(_getSidecarStateImpl(sql)?.last_error).toBeNull();
		// ...but the durable gap record is untouched (append-only, no reset path).
		const rows = _listSidecarEventsImpl(sql);
		expect(rows.length).toBe(1);
		expect(_latestSidecarGapImpl(sql)).toMatchObject({ old_cursor: "100", new_cursor: "900" });
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

describe("provider-id dedupe lookup (#593)", () => {
	it("finds an email by its provider-native (Gmail) id and returns null on miss", () => {
		const sql = makeSqlLike();
		sql.exec(
			"INSERT INTO emails (id, folder_id, date, body, provider_message_id) VALUES (?, ?, ?, ?, ?)",
			"e1", "inbox", "2026-07-06T00:00:00Z", "hello", "gmail-abc123",
		);
		expect(_findEmailIdByProviderMessageIdImpl(sql, "gmail-abc123")).toBe("e1");
		expect(_findEmailIdByProviderMessageIdImpl(sql, "gmail-missing")).toBeNull();
	});

	it("a Message-ID-less email row (message_id NULL) is still findable by provider id", () => {
		const sql = makeSqlLike();
		sql.exec(
			"INSERT INTO emails (id, folder_id, date, body, message_id, provider_message_id) VALUES (?, ?, ?, ?, NULL, ?)",
			"e2", "inbox", "2026-07-06T00:00:00Z", "no msgid", "gmail-xyz",
		);
		expect(_findEmailIdByMessageIdImpl(sql, "anything@x")).toBeNull();
		expect(_findEmailIdByProviderMessageIdImpl(sql, "gmail-xyz")).toBe("e2");
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
