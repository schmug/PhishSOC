// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * `MailboxDO.findThreadBySubject` only considers threads active in the last
 * 7 days. Email `date` values are ISO-8601 (`YYYY-MM-DDTHH:MM:SS.sssZ`), so
 * the cutoff must be compared in the same format — otherwise every message
 * on the boundary day matches regardless of its time. Drives the method
 * through a node:sqlite adapter (pattern: threaded-emails.test.ts).
 */

import { DatabaseSync } from "node:sqlite";
import { describe, expect, it, vi } from "vitest";

vi.mock("cloudflare:workers", () => ({
	DurableObject: class {
		ctx: unknown;
		env: unknown;
		constructor(state: unknown, env: unknown) { this.ctx = state; this.env = env; }
	},
}));

import { MailboxDO } from "../../workers/durableObject/index";

const DAY_MS = 24 * 60 * 60 * 1000;

function makeDO(rows: { id: string; thread_id: string; subject: string; date: string }[]) {
	const db = new DatabaseSync(":memory:");
	db.exec(`CREATE TABLE emails (id TEXT PRIMARY KEY, thread_id TEXT, subject TEXT, sender TEXT, recipient TEXT, date TEXT)`);
	const ins = db.prepare(`INSERT INTO emails VALUES (?, ?, ?, 'peer@ext.test', 'me@a.test', ?)`);
	for (const r of rows) ins.run(r.id, r.thread_id, r.subject, r.date);
	const sql = {
		exec: (query: string, ...params: unknown[]) => db.prepare(query.trim()).all(...(params as never[])),
	};
	const mailboxDO = Object.create(MailboxDO.prototype) as MailboxDO;
	(mailboxDO as unknown as { ctx: unknown }).ctx = { storage: { sql } };
	return mailboxDO;
}

describe("MailboxDO.findThreadBySubject — 7-day window", () => {
	it("excludes a thread whose last message is earlier on the boundary day", async () => {
		// Midnight UTC of the day 7 days ago: same calendar date as the
		// cutoff, but before it.
		const boundaryDay = new Date(Date.now() - 7 * DAY_MS).toISOString().slice(0, 10);
		const stale = `${boundaryDay}T00:00:00.000Z`;
		const mailboxDO = makeDO([{ id: "m2", thread_id: "t-old", subject: "Re: Quarterly report", date: stale }]);
		expect(await mailboxDO.findThreadBySubject("Quarterly report")).toBeNull();
	});

	it("still matches a thread active within the window", async () => {
		const recent = new Date(Date.now() - 6 * DAY_MS).toISOString();
		const mailboxDO = makeDO([{ id: "m2", thread_id: "t-new", subject: "Re: Quarterly report", date: recent }]);
		expect(await mailboxDO.findThreadBySubject("Quarterly report")).toBe("t-new");
	});
});
