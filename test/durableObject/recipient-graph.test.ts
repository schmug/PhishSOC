// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Outbound recipient history (migration 32) — the backfill SQL, the upsert
 * on SENT writes, and the send-context read. Drives the pure `_xImpl`
 * functions through a node:sqlite adapter (pattern: threaded-emails.test.ts).
 */

import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import type { SqlLike } from "../../workers/durableObject/catchall-intel";
import { mailboxMigrations } from "../../workers/durableObject/migrations";
import {
	_getSendContextImpl,
	_recordSentRecipientsImpl,
	parseRecipientList,
} from "../../workers/durableObject/recipient-graph";

type Seed = {
	id: string;
	folder_id: string;
	recipient?: string | null;
	cc?: string | null;
	bcc?: string | null;
	date?: string | null;
	message_id?: string | null;
	in_reply_to?: string | null;
	security_verdict?: string | null;
};

const MIGRATION_32 = mailboxMigrations.find((m) => m.name === "32_send_risk_recipient_graph")!;

/** Pre-migration-32 emails table (only the columns these paths touch) + migration 32. */
function makeDb(rows: Seed[] = []): { sql: SqlLike; db: DatabaseSync } {
	const db = new DatabaseSync(":memory:");
	db.exec(`
		CREATE TABLE emails (
			id TEXT PRIMARY KEY, folder_id TEXT NOT NULL, recipient TEXT, cc TEXT, bcc TEXT,
			date TEXT, message_id TEXT, in_reply_to TEXT, security_verdict TEXT
		);
	`);
	const ins = db.prepare(
		`INSERT INTO emails (id, folder_id, recipient, cc, bcc, date, message_id, in_reply_to, security_verdict)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	);
	for (const r of rows) {
		ins.run(
			r.id, r.folder_id, r.recipient ?? null, r.cc ?? null, r.bcc ?? null,
			r.date === undefined ? "2026-01-01T00:00:00.000Z" : r.date,
			r.message_id ?? null, r.in_reply_to ?? null, r.security_verdict ?? null,
		);
	}
	db.exec(MIGRATION_32.sql);
	const sql: SqlLike = {
		exec<T = Record<string, unknown>>(query: string, ...params: unknown[]): Iterable<T> {
			return db.prepare(query.trim()).all(...(params as never[])) as T[];
		},
	};
	return { sql, db };
}

function graph(db: DatabaseSync) {
	return db.prepare(`SELECT * FROM recipient_graph ORDER BY address`).all() as Array<{
		address: string; domain: string; send_count: number; first_sent: string; last_sent: string;
	}>;
}

describe("parseRecipientList", () => {
	it("splits comma-joined fields, lowercases, and dedupes across fields", () => {
		expect(parseRecipientList("A@x.com, b@y.com", "a@x.com", ["C@z.com"])).toEqual([
			"a@x.com", "b@y.com", "c@z.com",
		]);
	});

	it("extracts the address from a display-name entry and drops non-addresses", () => {
		expect(parseRecipientList("Alice <Alice@X.com>, not-an-address, ", null, undefined)).toEqual(["alice@x.com"]);
	});
});

describe("migration 32 backfill", () => {
	it("builds history from SENT rows only, across to/cc/bcc", () => {
		const { db } = makeDb([
			{ id: "s1", folder_id: "sent", recipient: "vendor@acme.com, pal@corp.test", cc: "boss@corp.test", date: "2026-01-01T00:00:00.000Z" },
			{ id: "s2", folder_id: "sent", recipient: "vendor@acme.com", bcc: "audit@corp.test", date: "2026-03-01T00:00:00.000Z" },
			{ id: "i1", folder_id: "inbox", recipient: "me@corp.test", date: "2026-02-01T00:00:00.000Z" },
		]);
		expect(graph(db)).toEqual([
			{ address: "audit@corp.test", domain: "corp.test", send_count: 1, first_sent: "2026-03-01T00:00:00.000Z", last_sent: "2026-03-01T00:00:00.000Z" },
			{ address: "boss@corp.test", domain: "corp.test", send_count: 1, first_sent: "2026-01-01T00:00:00.000Z", last_sent: "2026-01-01T00:00:00.000Z" },
			{ address: "pal@corp.test", domain: "corp.test", send_count: 1, first_sent: "2026-01-01T00:00:00.000Z", last_sent: "2026-01-01T00:00:00.000Z" },
			{ address: "vendor@acme.com", domain: "acme.com", send_count: 2, first_sent: "2026-01-01T00:00:00.000Z", last_sent: "2026-03-01T00:00:00.000Z" },
		]);
	});

	it("skips malformed entries, NULL dates, and handles an empty SENT folder", () => {
		const { db } = makeDb([
			{ id: "s1", folder_id: "sent", recipient: "Name <x@y.com>, bogus, ok@fine.test,," },
			{ id: "s2", folder_id: "sent", recipient: "nodate@fine.test", date: null },
		]);
		expect(graph(db).map((r) => r.address)).toEqual(["ok@fine.test"]);
		expect(graph(makeDb().db)).toEqual([]);
	});

	it("adds the send_risk column to emails", () => {
		const { db } = makeDb();
		const cols = (db.prepare(`PRAGMA table_info(emails)`).all() as Array<{ name: string }>).map((c) => c.name);
		expect(cols).toContain("send_risk");
	});
});

describe("_recordSentRecipientsImpl", () => {
	it("inserts new recipients and increments existing ones without moving first_sent", () => {
		const { sql, db } = makeDb();
		_recordSentRecipientsImpl(sql, ["a@x.com", "b@y.com"], "2026-05-01T00:00:00.000Z");
		_recordSentRecipientsImpl(sql, ["a@x.com"], "2026-06-01T00:00:00.000Z");
		expect(graph(db)).toEqual([
			{ address: "a@x.com", domain: "x.com", send_count: 2, first_sent: "2026-05-01T00:00:00.000Z", last_sent: "2026-06-01T00:00:00.000Z" },
			{ address: "b@y.com", domain: "y.com", send_count: 1, first_sent: "2026-05-01T00:00:00.000Z", last_sent: "2026-05-01T00:00:00.000Z" },
		]);
	});
});

describe("_getSendContextImpl", () => {
	const verdict = JSON.stringify({ action: "quarantine", classification: { label: "bec" } });

	function seeded() {
		const made = makeDb([
			{ id: "in-1", folder_id: "inbox", message_id: "abc@mail.test", security_verdict: verdict },
			{ id: "draft-1", folder_id: "draft", in_reply_to: "in-1" },
		]);
		_recordSentRecipientsImpl(made.sql, ["vendor@acme.com", "ops@acme.com"], "2026-01-01T00:00:00.000Z");
		_recordSentRecipientsImpl(made.sql, ["vendor@acme.com"], "2026-02-01T00:00:00.000Z");
		_recordSentRecipientsImpl(made.sql, ["once@solo.test"], "2026-02-01T00:00:00.000Z");
		return made;
	}

	it("returns history for known addresses and per-domain totals", () => {
		const ctx = _getSendContextImpl(seeded().sql, { addresses: ["Vendor@acme.com", "new@acme.com", "x@else.test"] });
		expect(ctx.recipients).toEqual([
			{ address: "vendor@acme.com", send_count: 2, first_sent: "2026-01-01T00:00:00.000Z", last_sent: "2026-02-01T00:00:00.000Z" },
		]);
		expect(ctx.domainSendCounts).toEqual({ "acme.com": 3 });
	});

	it("lists only domains with at least two sends as lookalike anchors", () => {
		expect(_getSendContextImpl(seeded().sql, { addresses: [] }).knownDomains).toEqual(["acme.com"]);
	});

	it("resolves the original verdict by row id, through a draft, and by Message-ID", () => {
		const { sql } = seeded();
		expect(_getSendContextImpl(sql, { addresses: [], originalRef: "in-1" }).originalVerdict).toBe(verdict);
		expect(_getSendContextImpl(sql, { addresses: [], originalRef: "draft-1" }).originalVerdict).toBe(verdict);
		expect(_getSendContextImpl(sql, { addresses: [], originalRef: "<abc@mail.test>" }).originalVerdict).toBe(verdict);
		expect(_getSendContextImpl(sql, { addresses: [], originalRef: "missing" }).originalVerdict).toBeNull();
		expect(_getSendContextImpl(sql, { addresses: [] }).originalVerdict).toBeNull();
	});
});
