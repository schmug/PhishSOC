// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * `MailboxDO.moveEmail` reports whether an email was actually moved: false
 * for an unknown folder and false for an email id that matches no row.
 * Drives the real drizzle query through a node:sqlite-backed
 * `ctx.storage.sql` adapter.
 */

import { DatabaseSync } from "node:sqlite";
import { drizzle } from "drizzle-orm/durable-sqlite";
import { describe, expect, it, vi } from "vitest";

vi.mock("cloudflare:workers", () => ({
	DurableObject: class {
		ctx: unknown;
		env: unknown;
		constructor(state: unknown, env: unknown) { this.ctx = state; this.env = env; }
	},
}));

import * as schema from "../../workers/db/schema";
import { MailboxDO } from "../../workers/durableObject/index";

function makeDO() {
	const db = new DatabaseSync(":memory:");
	db.exec(`
		CREATE TABLE folders (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, is_deletable INTEGER NOT NULL DEFAULT 1);
		INSERT INTO folders (id, name, is_deletable) VALUES ('inbox','Inbox',0), ('archive','Archive',0);
		CREATE TABLE emails (id TEXT PRIMARY KEY, folder_id TEXT NOT NULL);
		INSERT INTO emails (id, folder_id) VALUES ('e-1', 'inbox');
	`);
	const sql = {
		exec(query: string, ...params: unknown[]) {
			const stmt = db.prepare(query);
			const isRead = /^\s*select\b|\breturning\b/i.test(query);
			const rows = isRead ? (stmt.all(...(params as never[])) as Record<string, unknown>[]) : (stmt.run(...(params as never[])), []);
			let i = 0;
			return {
				toArray: () => rows,
				raw: () => ({ toArray: () => rows.map((r) => Object.values(r)) }),
				next: () => (i < rows.length ? { value: rows[i++], done: false } : { value: undefined, done: true }),
			};
		},
	};
	const storage = { sql };
	const mailboxDO = Object.create(MailboxDO.prototype) as MailboxDO;
	(mailboxDO as unknown as { ctx: unknown }).ctx = { storage };
	(mailboxDO as unknown as { db: unknown }).db = drizzle(storage as never, { schema });
	return { mailboxDO, db };
}

describe("MailboxDO.moveEmail", () => {
	it("moves an existing email and returns true", async () => {
		const { mailboxDO, db } = makeDO();
		expect(await mailboxDO.moveEmail("e-1", "archive")).toBe(true);
		expect(db.prepare("SELECT folder_id FROM emails WHERE id = 'e-1'").get()).toEqual({ folder_id: "archive" });
	});

	it("returns false for an unknown folder", async () => {
		const { mailboxDO } = makeDO();
		expect(await mailboxDO.moveEmail("e-1", "nope")).toBe(false);
	});

	it("returns false when no email has the given id", async () => {
		const { mailboxDO } = makeDO();
		expect(await mailboxDO.moveEmail("missing", "archive")).toBe(false);
	});
});
