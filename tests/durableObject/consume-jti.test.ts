// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Unit tests for `MailboxDO.consumeJti` (issue #461 / PR #468 regression).
 *
 * In Cloudflare DO SQLite, `cursor.rowsWritten` counts rows written to
 * indexes as well as tables. `consumed_jti` declares `jti TEXT PRIMARY KEY`,
 * which SQLite backs with an implicit unique index — so a successful
 * first-time INSERT reports rowsWritten === 2, not 1. Measured empirically
 * against workerd (wrangler dev --local, 2026-06-11):
 *
 *   INSERT OR IGNORE ... (new jti)        → rowsWritten === 2
 *   INSERT OR IGNORE ... (duplicate jti)  → rowsWritten === 0
 *   control: INTEGER PRIMARY KEY insert   → rowsWritten === 1
 *
 * The shipped check `rowsWritten === 1` therefore rejected EVERY legitimate
 * consume, 401-ing all Tier ≥ 1 sends. The fix treats any written row as a
 * successful consume (`> 0`); a replayed jti still reports 0.
 */

import { describe, expect, it, vi } from "vitest";

// Mock cloudflare:workers — MailboxDO extends DurableObject from this module,
// but consumeJti only touches `this.ctx.storage.sql.exec`.
vi.mock("cloudflare:workers", () => ({
	DurableObject: class {
		ctx: unknown;
		env: unknown;
		constructor(state: unknown, env: unknown) { this.ctx = state; this.env = env; }
	},
}));

import { MailboxDO } from "../../workers/durableObject/index";

/**
 * Builds a MailboxDO whose sql.exec mimics workerd's measured rowsWritten
 * accounting for the consumed_jti table (see header comment). The
 * constructor (drizzle + migrations) is bypassed — consumeJti needs only
 * `ctx.storage.sql`.
 */
function makeDO() {
	const consumed = new Set<string>();
	const sql = {
		exec: (query: string, ...bindings: unknown[]) => {
			if (!/INSERT OR IGNORE INTO consumed_jti/.test(query)) {
				throw new Error(`unexpected query: ${query}`);
			}
			const jti = bindings[0] as string;
			if (consumed.has(jti)) return { rowsWritten: 0 };
			consumed.add(jti);
			// 2 = table row + implicit `jti TEXT PRIMARY KEY` unique index row.
			return { rowsWritten: 2 };
		},
	};
	const mailboxDO = Object.create(MailboxDO.prototype) as MailboxDO;
	(mailboxDO as unknown as { ctx: unknown }).ctx = { storage: { sql } };
	return mailboxDO;
}

describe("MailboxDO.consumeJti — workerd rowsWritten accounting (PR #468 regression)", () => {
	it("returns true on first consume even though the PK index makes rowsWritten 2", async () => {
		const mailboxDO = makeDO();
		await expect(mailboxDO.consumeJti("jti-1")).resolves.toBe(true);
	});

	it("returns false when the jti was already consumed (replay)", async () => {
		const mailboxDO = makeDO();
		await mailboxDO.consumeJti("jti-1");
		await expect(mailboxDO.consumeJti("jti-1")).resolves.toBe(false);
	});

	it("consumes distinct jtis independently", async () => {
		const mailboxDO = makeDO();
		await expect(mailboxDO.consumeJti("jti-a")).resolves.toBe(true);
		await expect(mailboxDO.consumeJti("jti-b")).resolves.toBe(true);
		await expect(mailboxDO.consumeJti("jti-a")).resolves.toBe(false);
	});
});
