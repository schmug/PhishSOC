# Unified Inbox ("All inboxes") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `/inbox` "All inboxes" view that merges the Inbox conversations of every visible mailbox, with per-row actions routed to the owning mailbox, a From picker for new mail, and a per-mailbox "Hide from All inboxes" setting.

**Architecture:** A new `GET /api/v1/inbox` Worker route fans out one `getThreadedEmails` RPC per visible mailbox (ACL-filtered; honeypot, sidecar and hidden mailboxes dropped), merges the pages by `(date DESC, id DESC)` in a pure module, and pages with an opaque `{date, id}` keyset cursor. The SPA adds a top-level `/inbox` route that reuses a row component extracted from `email-list.tsx` and the existing split view, whose panels gain an optional `mailboxId` override because `/inbox` has no `:mailboxId` param.

**Tech Stack:** Cloudflare Workers + Durable Objects (SQLite), Hono, Zod, React 19 + React Router v7, TanStack Query, Vitest (node / jsdom projects), `node:sqlite` for DO-query tests.

**Spec:** `docs/superpowers/specs/2026-09-26-unified-inbox-design.md` — read it before starting any task.

## Global Constraints

- Branch: `claude/unified-inbox-domains-59bd86`, worktree `/Users/cory/PhishSOC/.claude/worktrees/jovial-sutherland-e3623f`. Run `git rev-parse --abbrev-ref HEAD && pwd` before editing.
- Indentation: tabs in `workers/`, `app/`, `tests/`, `test/`. `shared/mailbox-settings.ts` uses 2 spaces — match it.
- New files start with `// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.`
- Caller identity comes only from `callerEmailFromJwt(c.req.header("cf-access-jwt-assertion"))` / `callerGroupsFromJwt(...)` — never the `cf-access-authenticated-user-email` header.
- Every settings-tier write goes through `stripDefaultEqual` (root `CLAUDE.md`). This plan adds no new write endpoint; the existing mailbox PUT already strips.
- Test URL mock dispatchers parse with `new URL(url)` — never `startsWith`/`includes` on URLs (CodeQL gate, root `CLAUDE.md`).
- Merge order is `(date DESC, id DESC)`. Email ids are `crypto.randomUUID()` (`workers/index.ts:1664`) and dates are ISO-8601 receive time (`workers/index.ts:1734`), so string comparison is correct in both SQL and JS.
- `limit` default 25, clamp 1–50. Each DO is asked for `limit + 1` rows.
- Refresh interval: 30 000 ms, paused while the tab is hidden (React Query default).
- Response shape: `{ emails, nextCursor, failed, mailboxCount }`. `mailboxCount` (number of mailboxes queried) is an addition to the spec's shape. It is needed to tell "no mailboxes selected" (spec's empty state linking to `/mailboxes`) apart from "empty inboxes".
- `failed` lists only mailbox ids the caller passes the ACL for.
- Conventional commit prefixes; end every commit message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Commands (repo root): single file `npx vitest run <path>`; full `npm test`; `npm run typecheck`; `npm run build`. There is no lint script.

## Review Focus

1. **Mailbox-id leak via `failed`** — a mailbox whose settings or DO call fails, but which the caller cannot see under its ACL, must not appear in `failed`. Test: Task 1 (`selectInboxMailboxes` puts only ACL-visible unreadable mailboxes in `unreadable`) and Task 4 (route response).
2. **Garbage `limit`** — `?limit=abc`, `?limit=-5`, `?limit=9999` must return 200 with a clamped page size, not 500. Test: Task 4.
3. **Changing From after typing** — switching the From picker must keep the typed To and Subject. Test: Task 7.
4. **Stale selection on entry** — an email selected on a per-mailbox page must not open in `/inbox` against the wrong mailbox; entering `/inbox` clears it. Test: Task 8.
5. **Deleting the open row** — deleting the row shown in the reading pane closes the pane (parity with `email-list.tsx`). Test: Task 8.

---

### Task 1: Pure merge / filter / cursor module

**Files:**
- Create: `workers/lib/unified-inbox.ts`
- Test: `tests/lib/unified-inbox.test.ts`

**Interfaces:**
- Consumes: `callerInAcl(acl, callerEmail, callerGroups, isDev)` and `type MailboxAcl` from `workers/lib/mailbox-acl.ts`.
- Produces:
  - `type InboxCursor = { date: string; id: string }`
  - `type InboxMailboxFlags = { honeypot: boolean; sidecar: boolean; hidden: boolean }`
  - `type InboxRow = { id: string; date: string | null; [k: string]: unknown }`
  - `type PerMailboxInboxPage = { mailboxId: string; mailboxEmail: string; emails: InboxRow[] }`
  - `type UnifiedInboxRow = InboxRow & { mailbox_id: string; mailbox_email: string }`
  - `selectInboxMailboxes<T extends { id: string }>(mailboxes: T[], acls: Array<MailboxAcl | null>, flags: Array<InboxMailboxFlags | null>, callerEmail: string | null | undefined, callerGroups: string[], isDev?: boolean): { selected: T[]; unreadable: T[] }`
  - `compareInboxRows(a: { date: string | null; id: string }, b: { date: string | null; id: string }): number`
  - `encodeCursor(c: InboxCursor): string` / `decodeCursor(s: string): InboxCursor | null`
  - `mergeInboxPages(perMailbox: PerMailboxInboxPage[], limit: number): { emails: UnifiedInboxRow[]; nextCursor: string | null }`

- [ ] **Step 1: Write the failing test**

Create `tests/lib/unified-inbox.test.ts`:

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";
import {
	compareInboxRows,
	decodeCursor,
	encodeCursor,
	mergeInboxPages,
	selectInboxMailboxes,
	type InboxCursor,
	type InboxMailboxFlags,
	type InboxRow,
	type PerMailboxInboxPage,
} from "../../workers/lib/unified-inbox";

const SHOWN: InboxMailboxFlags = { honeypot: false, sidecar: false, hidden: false };

describe("selectInboxMailboxes", () => {
	const mailboxes = [
		{ id: "open@a.test", email: "open@a.test" },
		{ id: "mine@a.test", email: "mine@a.test" },
		{ id: "theirs@b.test", email: "theirs@b.test" },
		{ id: "pot@a.test", email: "pot@a.test" },
		{ id: "side@a.test", email: "side@a.test" },
		{ id: "quiet@b.test", email: "quiet@b.test" },
		{ id: "broken@b.test", email: "broken@b.test" },
		{ id: "broken-theirs@b.test", email: "broken-theirs@b.test" },
	];
	const alice: MailboxAcl = { owner: "alice@corp.test", members: ["alice@corp.test"] };
	const bob: MailboxAcl = { owner: "bob@corp.test", members: ["bob@corp.test"] };
	const acls: Array<MailboxAcl | null> = [null, alice, bob, null, null, null, null, bob];
	const flags: Array<InboxMailboxFlags | null> = [
		SHOWN,
		SHOWN,
		SHOWN,
		{ ...SHOWN, honeypot: true },
		{ ...SHOWN, sidecar: true },
		{ ...SHOWN, hidden: true },
		null,
		null,
	];

	it("keeps unscoped and permitted mailboxes; drops ACL-denied, honeypot, sidecar and hidden", () => {
		const { selected } = selectInboxMailboxes(mailboxes, acls, flags, "alice@corp.test", []);
		expect(selected.map((m) => m.id)).toEqual(["open@a.test", "mine@a.test"]);
	});

	it("reports unreadable-settings mailboxes only when the caller passes their ACL", () => {
		const { selected, unreadable } = selectInboxMailboxes(mailboxes, acls, flags, "alice@corp.test", []);
		expect(unreadable.map((m) => m.id)).toEqual(["broken@b.test"]);
		expect(selected.map((m) => m.id)).not.toContain("broken@b.test");
	});

	it("fails closed for a null caller outside dev (scoped mailboxes hidden)", () => {
		const { selected } = selectInboxMailboxes(mailboxes, acls, flags, null, [], false);
		expect(selected.map((m) => m.id)).toEqual(["open@a.test"]);
	});
});

describe("cursor encoding", () => {
	it("round-trips", () => {
		const c: InboxCursor = { date: "2026-09-01T12:00:00.000Z", id: "9f1c2d3e-0000-4000-8000-000000000001" };
		expect(decodeCursor(encodeCursor(c))).toEqual(c);
	});

	it("uses base64url characters only", () => {
		expect(encodeCursor({ date: "2026-09-01T12:00:00.000Z", id: "x".repeat(40) })).toMatch(/^[A-Za-z0-9_-]+$/);
	});

	it.each([
		["not base64", "%%%"],
		["not JSON", btoa("hello")],
		["wrong shape", btoa(JSON.stringify({ date: "2026-09-01T12:00:00.000Z" }))],
		["empty id", btoa(JSON.stringify({ d: "2026-09-01T12:00:00.000Z", i: "" }))],
		["non-date", btoa(JSON.stringify({ d: "yesterday", i: "abc" }))],
	])("rejects %s", (_label, input) => {
		expect(decodeCursor(input)).toBeNull();
	});
});

describe("compareInboxRows", () => {
	it("sorts newer first, then higher id first on equal dates", () => {
		const rows = [
			{ id: "a", date: "2026-09-01T10:00:00.000Z" },
			{ id: "b", date: "2026-09-01T12:00:00.000Z" },
			{ id: "c", date: "2026-09-01T12:00:00.000Z" },
		];
		expect([...rows].sort(compareInboxRows).map((r) => r.id)).toEqual(["c", "b", "a"]);
	});
});

// Simulates MailboxDO.getThreadedEmails({ before, limit }) in JS: rows strictly
// after the cursor in (date DESC, id DESC) order. The SQL side is tested in
// test/durableObject/threaded-emails.test.ts.
function doPage(rows: InboxRow[], before: InboxCursor | null, limit: number): InboxRow[] {
	return [...rows]
		.sort(compareInboxRows)
		.filter((r) => !before || compareInboxRows(r, before) > 0)
		.slice(0, limit);
}

function mkRows(prefix: string, dates: string[]): InboxRow[] {
	return dates.map((d, i) => ({ id: `${prefix}-${String(i).padStart(3, "0")}`, date: d, subject: `${prefix} ${i}` }));
}

describe("mergeInboxPages", () => {
	const SAME = "2026-09-01T12:00:00.000Z";
	const fixture: Record<string, InboxRow[]> = {
		"ops@a.test": mkRows("a", [SAME, "2026-09-01T09:00:00.000Z", "2026-08-30T00:00:00.000Z", "2026-08-01T00:00:00.000Z"]),
		"ops@b.test": mkRows("b", [SAME, SAME, "2026-09-02T00:00:00.000Z"]),
		"ops@c.test": mkRows("c", Array.from({ length: 9 }, (_, i) => `2026-07-${String(10 + i).padStart(2, "0")}T00:00:00.000Z`)),
	};

	function pageAt(before: InboxCursor | null, limit: number): PerMailboxInboxPage[] {
		return Object.entries(fixture).map(([id, rows]) => ({
			mailboxId: id,
			mailboxEmail: id,
			emails: doPage(rows, before, limit + 1),
		}));
	}

	it("tags rows with their mailbox and orders across mailboxes", () => {
		const { emails } = mergeInboxPages(pageAt(null, 4), 4);
		expect(emails.map((e) => [e.mailbox_id, e.id])).toEqual([
			["ops@b.test", "b-002"],
			["ops@b.test", "b-001"],
			["ops@b.test", "b-000"],
			["ops@a.test", "a-000"],
		]);
	});

	it("walks every row exactly once across pages, matching one global sort", () => {
		const all = Object.values(fixture).flat().sort(compareInboxRows).map((r) => r.id);
		const seen: string[] = [];
		let before: InboxCursor | null = null;
		for (let guard = 0; guard < 20; guard++) {
			const { emails, nextCursor } = mergeInboxPages(pageAt(before, 3), 3);
			seen.push(...emails.map((e) => e.id));
			if (!nextCursor) break;
			before = decodeCursor(nextCursor);
		}
		expect(seen).toEqual(all);
	});

	it("returns a null cursor exactly when nothing remains", () => {
		const total = Object.values(fixture).flat().length; // 16
		expect(mergeInboxPages(pageAt(null, total), total).nextCursor).toBeNull();
		expect(mergeInboxPages(pageAt(null, total - 1), total - 1).nextCursor).not.toBeNull();
	});

	it("drops rows without a date (they cannot be cursor-paged)", () => {
		const { emails } = mergeInboxPages(
			[{ mailboxId: "x@a.test", mailboxEmail: "x@a.test", emails: [{ id: "n", date: null }, { id: "d", date: SAME }] }],
			10,
		);
		expect(emails.map((e) => e.id)).toEqual(["d"]);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/lib/unified-inbox.test.ts`
Expected: FAIL — `Failed to resolve import "../../workers/lib/unified-inbox"`.

- [ ] **Step 3: Write the implementation**

Create `workers/lib/unified-inbox.ts`:

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Pure helpers for the unified "All inboxes" endpoint (GET /api/v1/inbox,
 * workers/routes/unified-inbox.ts). No env, no I/O.
 * Spec: docs/superpowers/specs/2026-09-26-unified-inbox-design.md
 *
 * Ordering invariant: rows merge by (date DESC, id DESC). Email ids are
 * crypto.randomUUID() (workers/index.ts receiveEmail) and dates are ISO-8601,
 * so the pair is a strict total order across mailboxes and a {date, id}
 * cursor never duplicates or skips a row. JS string `<` and SQLite BINARY
 * collation agree on these ASCII values, so this sort matches the DO's
 * `ORDER BY lif.date DESC, lif.id DESC` (workers/durableObject/threaded-emails.ts).
 */

import { callerInAcl, type MailboxAcl } from "./mailbox-acl";

export type InboxCursor = { date: string; id: string };

export type InboxMailboxFlags = { honeypot: boolean; sidecar: boolean; hidden: boolean };

export type InboxRow = { id: string; date: string | null; [k: string]: unknown };

export type PerMailboxInboxPage = {
	mailboxId: string;
	mailboxEmail: string;
	emails: InboxRow[];
};

export type UnifiedInboxRow = InboxRow & { mailbox_id: string; mailbox_email: string };

/**
 * ACL first, then settings flags. `flags[i] === null` means the settings read
 * failed: the mailbox is excluded (unknown honeypot/hidden state must not leak
 * lure mail into the list) and reported in `unreadable` so the UI can show it.
 * A mailbox the caller cannot see never reaches `unreadable` — its id must not
 * leak through the `failed` list.
 */
export function selectInboxMailboxes<T extends { id: string }>(
	mailboxes: T[],
	acls: Array<MailboxAcl | null>,
	flags: Array<InboxMailboxFlags | null>,
	callerEmail: string | null | undefined,
	callerGroups: string[],
	isDev: boolean = false,
): { selected: T[]; unreadable: T[] } {
	const selected: T[] = [];
	const unreadable: T[] = [];
	mailboxes.forEach((m, i) => {
		if (!callerInAcl(acls[i], callerEmail, callerGroups, isDev)) return;
		const f = flags[i];
		if (f === null) {
			unreadable.push(m);
			return;
		}
		if (f.honeypot || f.sidecar || f.hidden) return;
		selected.push(m);
	});
	return { selected, unreadable };
}

/** Negative when `a` sorts first: newer date first, then higher id first. */
export function compareInboxRows(
	a: { date: string | null; id: string },
	b: { date: string | null; id: string },
): number {
	const da = a.date ?? "";
	const db = b.date ?? "";
	if (da !== db) return da < db ? 1 : -1;
	if (a.id !== b.id) return a.id < b.id ? 1 : -1;
	return 0;
}

export function encodeCursor(c: InboxCursor): string {
	return btoa(JSON.stringify({ d: c.date, i: c.id }))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

export function decodeCursor(s: string): InboxCursor | null {
	try {
		const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
		const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
		const v = JSON.parse(atob(padded)) as unknown;
		if (!v || typeof v !== "object") return null;
		const { d, i } = v as { d?: unknown; i?: unknown };
		if (typeof d !== "string" || typeof i !== "string" || !d || !i) return null;
		if (Number.isNaN(Date.parse(d))) return null;
		return { date: d, id: i };
	} catch {
		return null;
	}
}

/**
 * Each page in `perMailbox` must be that mailbox's first `limit + 1` rows after
 * the cursor. The merged set then holds more than `limit` rows exactly when
 * another page exists. Rows without a date are dropped: inbox rows always carry
 * a receive time, and a null date cannot be encoded in a cursor.
 */
export function mergeInboxPages(
	perMailbox: PerMailboxInboxPage[],
	limit: number,
): { emails: UnifiedInboxRow[]; nextCursor: string | null } {
	const rows: UnifiedInboxRow[] = [];
	for (const p of perMailbox) {
		for (const e of p.emails) {
			if (typeof e.date !== "string" || e.date === "") continue;
			rows.push({ ...e, mailbox_id: p.mailboxId, mailbox_email: p.mailboxEmail });
		}
	}
	rows.sort(compareInboxRows);
	const page = rows.slice(0, limit);
	const last = page[page.length - 1];
	const nextCursor =
		rows.length > limit && last ? encodeCursor({ date: last.date as string, id: last.id }) : null;
	return { emails: page, nextCursor };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/lib/unified-inbox.test.ts`
Expected: PASS (all tests in the file).

- [ ] **Step 5: Commit**

```bash
git add workers/lib/unified-inbox.ts tests/lib/unified-inbox.test.ts
git commit -m "feat(inbox): pure merge, filter and cursor helpers for All inboxes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Keyset cursor on the threaded inbox query

Extract the non-draft branch of `MailboxDO.getThreadedEmails` into a module that takes a `SqlLike`, following the `_xImpl` pattern in `workers/durableObject/sidecar-state.ts`, so it can be tested under `node:sqlite`. Add the `before` bound and the `id` tie-break.

**Files:**
- Create: `workers/durableObject/threaded-emails.ts`
- Modify: `workers/durableObject/index.ts` — delete `NORMALIZED_SUBJECT_SQL` (lines 40–51) and import it instead; add `before` to `GetEmailsOptions` (lines 94–101); replace the non-draft branch of `getThreadedEmails` (lines 386–485)
- Test: `test/durableObject/threaded-emails.test.ts`

**Interfaces:**
- Consumes: `type SqlLike` from `workers/durableObject/catchall-intel.ts`.
- Produces:
  - `NORMALIZED_SUBJECT_SQL: string` (moved; `countThreadedEmails` in `index.ts` keeps using it)
  - `type ThreadedCursor = { date: string; id: string }`
  - `_getThreadedEmailsImpl(sql: SqlLike, q: { folder: string; limit: number; offset: number; before?: ThreadedCursor }): ThreadedEmailRow[]`
  - `MailboxDO.getThreadedEmails({ folder, limit, page?, before? })` — RPC used by Task 4. With `before`, returns conversations whose latest in-folder message sorts strictly after the cursor in `(date DESC, id DESC)`; `page`/offset is ignored.

- [ ] **Step 1: Write the failing test**

Create `test/durableObject/threaded-emails.test.ts`:

```ts
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

type Seed = { id: string; date: string; thread_id?: string; folder_id?: string; read?: number };

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
		ins.run(r.id, r.folder_id ?? "inbox", `subject ${r.id}`, r.date, r.read ?? 0, r.thread_id ?? null);
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
			{ id: "m1", date: "2026-09-01T09:00:00.000Z", thread_id: "t1" },
			{ id: "m2", date: "2026-09-01T11:00:00.000Z", thread_id: "t1" },
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/durableObject/threaded-emails.test.ts`
Expected: FAIL — `Failed to resolve import "../../workers/durableObject/threaded-emails"`.

- [ ] **Step 3: Create the module**

Create `workers/durableObject/threaded-emails.ts`. The SQL is the existing non-draft query from `workers/durableObject/index.ts:388-471`, with two changes marked `// CHANGED`:

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Threaded (conversation-grouped) folder listing for non-draft folders,
 * extracted from MailboxDO.getThreadedEmails so node:sqlite tests can drive it
 * (test/durableObject/threaded-emails.test.ts).
 *
 * `before` is the unified-inbox keyset cursor (GET /api/v1/inbox,
 * workers/lib/unified-inbox.ts): only conversations whose latest in-folder
 * message sorts strictly after {date, id} in (date DESC, id DESC) order.
 * OFFSET is ignored when `before` is set.
 */

import type { SqlLike } from "./catchall-intel";

/**
 * SQL expression to normalize email subjects by stripping common
 * reply/forward prefixes (Re:, Fwd:, FW:, AW:, WG:, Réf:, SV:).
 * Used for conversation grouping. Hardcoded to the `subject` column.
 */
export const NORMALIZED_SUBJECT_SQL = `LOWER(TRIM(
	REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
		LOWER(subject),
		'aw: ', ''), 'wg: ', ''), 'réf: ', ''), 'sv: ', ''),
		're: ', ''), 'fwd: ', ''), 'fw: ', '')
))`;

export type ThreadedCursor = { date: string; id: string };

export type ThreadedEmailRow = {
	id: string;
	subject: string | null;
	sender: string | null;
	recipient: string | null;
	date: string | null;
	read: boolean;
	starred: boolean;
	thread_id: string | null;
	folder_id: string;
	in_reply_to: string | null;
	email_references: string | null;
	snippet: string | null;
	thread_count: number;
	thread_unread_count: number;
	participants: string;
	needs_reply: boolean;
	has_draft: boolean;
};

export function _getThreadedEmailsImpl(
	sql: SqlLike,
	q: { folder: string; limit: number; offset: number; before?: ThreadedCursor },
): ThreadedEmailRow[] {
	const result = sql.exec<Record<string, unknown>>(
		`WITH
		folder_emails AS (
			SELECT *,
				COALESCE(thread_id, id) as raw_thread_id,
				${NORMALIZED_SUBJECT_SQL} as normalized_subject
			FROM emails
			WHERE folder_id = (SELECT id FROM folders WHERE name = ?1 OR id = ?1 LIMIT 1)
		),
		thread_to_conversation AS (
			SELECT
				raw_thread_id,
				normalized_subject,
				CASE
					WHEN thread_id IS NOT NULL THEN raw_thread_id
					ELSE MIN(raw_thread_id) OVER (PARTITION BY normalized_subject)
				END as conversation_id
			FROM folder_emails
			GROUP BY raw_thread_id, normalized_subject, thread_id
		),
		all_emails_with_conversation AS (
			SELECT
				e.*,
				COALESCE(tc.conversation_id, COALESCE(e.thread_id, e.id)) as conversation_id
			FROM emails e
			LEFT JOIN thread_to_conversation tc
				ON COALESCE(e.thread_id, e.id) = tc.raw_thread_id
		),
		conversation_stats AS (
			SELECT
				conversation_id,
				COUNT(*) as thread_count,
				SUM(CASE WHEN read = 0 THEN 1 ELSE 0 END) as thread_unread_count,
				SUM(CASE WHEN read = 1 THEN 1 ELSE 0 END) as thread_read_count,
				GROUP_CONCAT(DISTINCT sender) as participants,
				SUM(CASE WHEN folder_id = (SELECT id FROM folders WHERE name = 'draft' LIMIT 1) THEN 1 ELSE 0 END) as has_draft
			FROM all_emails_with_conversation
			WHERE conversation_id IN (
				SELECT DISTINCT conversation_id FROM all_emails_with_conversation
				WHERE folder_id = (SELECT id FROM folders WHERE name = ?1 OR id = ?1 LIMIT 1)
			)
			GROUP BY conversation_id
		),
		latest_message_per_conversation AS (
			SELECT
				conversation_id,
				folder_id,
				ROW_NUMBER() OVER (PARTITION BY conversation_id ORDER BY date DESC) as rn
			FROM all_emails_with_conversation
		),
		latest_in_folder AS (
			SELECT
				fe.*,
				COALESCE(tc.conversation_id, fe.raw_thread_id) as conversation_id,
				ROW_NUMBER() OVER (
					PARTITION BY COALESCE(tc.conversation_id, fe.raw_thread_id)
					ORDER BY fe.date DESC
				) as rn
			FROM folder_emails fe
			LEFT JOIN thread_to_conversation tc
				ON fe.raw_thread_id = tc.raw_thread_id
		)
		SELECT
			lif.id, lif.subject, lif.sender, lif.recipient, lif.date,
			lif.read, lif.starred, lif.thread_id, lif.folder_id,
			lif.in_reply_to, lif.email_references,
			SUBSTR(lif.body, 1, 300) as snippet,
			cs.thread_count, cs.thread_unread_count, cs.participants,
			CASE WHEN lmc.folder_id != (SELECT id FROM folders WHERE name = 'sent' LIMIT 1)
				AND lmc.folder_id != (SELECT id FROM folders WHERE name = 'draft' LIMIT 1)
				AND cs.thread_read_count > 0
				THEN 1 ELSE 0 END as needs_reply,
			CASE WHEN cs.has_draft > 0 THEN 1 ELSE 0 END as has_draft
		FROM latest_in_folder lif
		JOIN conversation_stats cs ON lif.conversation_id = cs.conversation_id
		LEFT JOIN latest_message_per_conversation lmc
			ON lmc.conversation_id = lif.conversation_id AND lmc.rn = 1
		WHERE lif.rn = 1
			AND (?4 IS NULL OR lif.date < ?4 OR (lif.date = ?4 AND lif.id < ?5)) -- CHANGED: keyset cursor
		ORDER BY lif.date DESC, lif.id DESC -- CHANGED: id tie-break
		LIMIT ?2 OFFSET ?3`,
		q.folder,
		q.limit,
		q.before ? 0 : q.offset,
		q.before?.date ?? null,
		q.before?.id ?? null,
	);

	return [...result].map((row: any) => ({
		...row,
		read: !!row.read,
		starred: !!row.starred,
		thread_count: row.thread_count || 1,
		thread_unread_count: row.thread_unread_count || 0,
		participants: row.participants || row.sender,
		needs_reply: !!row.needs_reply,
		has_draft: !!row.has_draft,
	}));
}
```

- [ ] **Step 4: Run the new test**

Run: `npx vitest run test/durableObject/threaded-emails.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Rewire `MailboxDO`**

In `workers/durableObject/index.ts`:

1. Delete the `NORMALIZED_SUBJECT_SQL` constant and its doc comment (lines 40–51). Below the `./sidecar-state` import block (ends line 38) add:

```ts
import {
	_getThreadedEmailsImpl,
	NORMALIZED_SUBJECT_SQL,
	type ThreadedCursor,
} from "./threaded-emails";
```

2. Add `before` to `GetEmailsOptions` (lines 94–101):

```ts
interface GetEmailsOptions {
	folder?: string;
	thread_id?: string;
	page?: number;
	limit?: number;
	sortColumn?: SortColumn;
	sortDirection?: "ASC" | "DESC";
	/** Unified-inbox keyset cursor; honoured by getThreadedEmails for non-draft folders only. */
	before?: ThreadedCursor;
}
```

3. In `getThreadedEmails` (line 312), change the destructure to `const { folder, page = 1, limit: rawLimit = 25, before } = options;`. Replace everything from the `// Non-draft folders: full threading logic` comment (line 387) through and including the method's closing `}` (the line after the second `return rows.map(...)`'s `}));`, ~line 485) with the block below, which supplies its own closing `}`:

```ts
		// Non-draft folders: full threading logic. Lives in ./threaded-emails
		// so node:sqlite tests can drive it (test/durableObject/threaded-emails.test.ts).
		return _getThreadedEmailsImpl(this.ctx.storage.sql as SqlLike, {
			folder,
			limit,
			offset,
			before,
		});
	}
```

Leave the draft branch (lines 334–385) unchanged.

- [ ] **Step 6: Verify nothing else broke**

Run: `npx vitest run test/durableObject tests/durableObject && npm run typecheck`
Expected: all tests PASS; typecheck exits 0. `grep -n "NORMALIZED_SUBJECT_SQL" workers/durableObject/index.ts` shows only the import and the `countThreadedEmails` usage.

- [ ] **Step 7: Commit**

```bash
git add workers/durableObject/threaded-emails.ts workers/durableObject/index.ts test/durableObject/threaded-emails.test.ts
git commit -m "feat(inbox): keyset cursor on the threaded folder query

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: `hideFromAllInboxes` mailbox setting

**Files:**
- Modify: `shared/mailbox-settings.ts:394-407` (schema field)
- Modify: `workers/lib/mailbox-settings.ts:451-507` (`isDefaultEqual` case)
- Modify: `app/types/index.ts:147-157` (frontend `MailboxSettings` type)
- Modify: `app/routes/settings.tsx` (state ~line 123, init effect ~line 198, save payload ~line 405, Account card ~line 530)
- Test: `tests/lib/hide-from-all-inboxes.test.ts`, `tests/frontend/settings-hide-from-all-inboxes.test.tsx`

**Interfaces:**
- Produces: `MailboxSettings.hideFromAllInboxes?: boolean` (Zod + TS type). Task 4 reads `resolveMailboxSettings(env, id).raw.hideFromAllInboxes`. `false` is stripped on write.

- [ ] **Step 1: Write the failing backend test**

Create `tests/lib/hide-from-all-inboxes.test.ts`:

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import { MailboxSettings } from "../../shared/mailbox-settings";
import { stripDefaultEqual } from "../../workers/lib/mailbox-settings";

describe("hideFromAllInboxes mailbox setting", () => {
	it("parses as an optional boolean", () => {
		expect(MailboxSettings.parse({ hideFromAllInboxes: true }).hideFromAllInboxes).toBe(true);
		expect(MailboxSettings.parse({}).hideFromAllInboxes).toBeUndefined();
		expect(MailboxSettings.safeParse({ hideFromAllInboxes: "yes" }).success).toBe(false);
	});

	it("strips the false default so absent-key semantics hold", () => {
		expect(stripDefaultEqual({ hideFromAllInboxes: false })).toEqual({});
	});

	it("keeps an explicit true", () => {
		expect(stripDefaultEqual({ hideFromAllInboxes: true })).toEqual({ hideFromAllInboxes: true });
	});
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npx vitest run tests/lib/hide-from-all-inboxes.test.ts`
Expected: FAIL — the `"yes"` case parses successfully (the schema is `.passthrough()`), and `stripDefaultEqual({ hideFromAllInboxes: false })` returns the key.

- [ ] **Step 3: Implement the backend side**

In `shared/mailbox-settings.ts`, inside `MailboxSettings` after `newEmailWebhook: NewEmailWebhookSettings.optional(),` (2-space indent):

```ts
  /** Leave this mailbox out of the unified All inboxes view (GET /api/v1/inbox). Mailbox tier only. */
  hideFromAllInboxes: z.boolean().optional(),
```

In `workers/lib/mailbox-settings.ts` `isDefaultEqual`, add before `default:`:

```ts
		case "hideFromAllInboxes":
			// Shown by default — strip `false` so absent-key semantics hold.
			return value === false;
```

- [ ] **Step 4: Run it to verify it passes**

Run: `npx vitest run tests/lib/hide-from-all-inboxes.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Write the failing frontend test**

Create `tests/frontend/settings-hide-from-all-inboxes.test.tsx`. The mock block is copied from `tests/frontend/settings-behavior.test.tsx:12-43`:

```tsx
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// "Hide from All inboxes" toggle in the per-mailbox Account card.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import type { Mailbox } from "~/types";

const mutateAsync = vi.fn();
const updateMailboxMock = {
	mutateAsync,
	isPending: false,
} as unknown as ReturnType<typeof import("~/queries/mailboxes").useUpdateMailbox>;

let mailboxFixture: Mailbox;

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({ data: mailboxFixture }),
	useUpdateMailbox: () => updateMailboxMock,
	useLockDownMailbox: () => ({ mutate: vi.fn(), isPending: false, isError: false }),
	useMailboxAcl: () => ({ data: undefined, isLoading: true }),
	useAddAclMember: () => ({ mutateAsync: vi.fn(), isPending: false }),
	useRemoveAclMember: () => ({ mutateAsync: vi.fn(), isPending: false }),
	useTransferAclOwnership: () => ({ mutateAsync: vi.fn(), isPending: false }),
	useAddAclGroup: () => ({ mutateAsync: vi.fn(), isPending: false }),
	useRemoveAclGroup: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));

vi.mock("~/queries/org-settings", () => ({
	useOrgSettings: () => ({ data: { settings: {} }, isLoading: false }),
}));

vi.mock("~/queries/domain-settings", () => ({
	useDomainSettings: () => ({ data: { domain: "example.com", settings: {} }, isLoading: false }),
}));

import SettingsRoute from "~/routes/settings";
import { renderWithProviders } from "./test-utils";

function renderSettings() {
	return renderWithProviders(
		<Routes>
			<Route path="/mailbox/:mailboxId/settings" element={<SettingsRoute />} />
		</Routes>,
		{ initialEntries: ["/mailbox/m1/settings"] },
	);
}

function fixture(settings: Record<string, unknown>): Mailbox {
	return { id: "m1", email: "ops@example.com", name: "Ops", settings } as unknown as Mailbox;
}

describe("Settings · Hide from All inboxes", () => {
	beforeEach(() => {
		mutateAsync.mockReset();
		mutateAsync.mockResolvedValue(undefined);
	});

	it("is off when the setting is absent", async () => {
		mailboxFixture = fixture({});
		renderSettings();
		expect(await screen.findByRole("checkbox", { name: /hide from all inboxes/i })).not.toBeChecked();
	});

	it("is on when saved as true", async () => {
		mailboxFixture = fixture({ hideFromAllInboxes: true });
		renderSettings();
		expect(await screen.findByRole("checkbox", { name: /hide from all inboxes/i })).toBeChecked();
	});

	it("saves true when switched on", async () => {
		mailboxFixture = fixture({});
		const user = userEvent.setup();
		renderSettings();
		await user.click(await screen.findByRole("checkbox", { name: /hide from all inboxes/i }));
		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));
		expect(mutateAsync.mock.calls[0][0].settings.hideFromAllInboxes).toBe(true);
	});

	it("drops the key when switched off", async () => {
		mailboxFixture = fixture({ hideFromAllInboxes: true });
		const user = userEvent.setup();
		renderSettings();
		await user.click(await screen.findByRole("checkbox", { name: /hide from all inboxes/i }));
		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));
		expect(mutateAsync.mock.calls[0][0].settings.hideFromAllInboxes).toBeUndefined();
	});
});
```

- [ ] **Step 6: Run it to verify it fails**

Run: `npx vitest run tests/frontend/settings-hide-from-all-inboxes.test.tsx`
Expected: FAIL — `Unable to find role="checkbox" and name /hide from all inboxes/i`.

- [ ] **Step 7: Implement the frontend side**

`app/types/index.ts`, in `interface MailboxSettings` after `sidecar?: SidecarSettings;`:

```ts
	/** Leave this mailbox out of the /inbox All inboxes view. */
	hideFromAllInboxes?: boolean;
```

`app/routes/settings.tsx`:

1. After `const [displayName, setDisplayName] = useState("");` (line 123):

```tsx
	const [hideFromAllInboxes, setHideFromAllInboxes] = useState(false);
```

2. In the init `useEffect`, after `setDisplayName(mailbox.settings?.fromName || mailbox.name || "");` (line 198):

```tsx
		setHideFromAllInboxes(mailbox.settings?.hideFromAllInboxes === true);
```

3. In `handleSave`'s `settings` object, after `fromName: displayName,` (line 407):

```tsx
			// Explicit undefined overrides a stale `true` carried by the spread above.
			hideFromAllInboxes: hideFromAllInboxes || undefined,
```

4. In the Account card, after `<Input label="Email" type="email" value={mailbox.email} disabled />` (line 538):

```tsx
						<Switch
							label="Hide from All inboxes"
							checked={hideFromAllInboxes}
							onCheckedChange={setHideFromAllInboxes}
							data-testid="hide-from-all-inboxes-toggle"
						/>
						<p className="text-xs text-ink-3">
							Leave this mailbox out of the merged All inboxes view. You can still
							open it here and send from it.
						</p>
```

- [ ] **Step 8: Run both tests plus the existing settings suites**

Run: `npx vitest run tests/lib/hide-from-all-inboxes.test.ts tests/frontend/settings-hide-from-all-inboxes.test.tsx tests/frontend/settings-behavior.test.tsx tests/lib/resolve-mailbox-settings.test.ts`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add shared/mailbox-settings.ts workers/lib/mailbox-settings.ts app/types/index.ts app/routes/settings.tsx tests/lib/hide-from-all-inboxes.test.ts tests/frontend/settings-hide-from-all-inboxes.test.tsx
git commit -m "feat(inbox): per-mailbox Hide from All inboxes setting

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: `GET /api/v1/inbox` route

**Files:**
- Create: `workers/routes/unified-inbox.ts`
- Modify: `workers/index.ts` — import at the top next to `import { sendEmailRoutes } from "./routes/send-email";` (line 41); mount after `app.route("/api/v1/mailboxes/:mailboxId", sendEmailRoutes);` (line 173)
- Test: `tests/routes/unified-inbox.test.ts`

**Interfaces:**
- Consumes: Task 1 (`selectInboxMailboxes`, `decodeCursor`, `mergeInboxPages`, types), Task 2 (`getThreadedEmails({ folder, limit, before })` RPC), Task 3 (`raw.hideFromAllInboxes`), `listMailboxes` (`workers/lib/email-helpers.ts:38`), `readMailboxAcl` / `callerEmailFromJwt` / `callerGroupsFromJwt` (`workers/lib/mailbox-acl.ts`), `resolveMailboxSettings` (`workers/lib/mailbox-settings.ts:153`), `sidecarConfigOf` (`workers/lib/sidecar-config.ts:29`).
- Produces: `unifiedInboxRoutes: Hono<{ Bindings: Env }>` mounted at `/api/v1/inbox`. Response JSON: `{ emails: UnifiedInboxRow[]; nextCursor: string | null; failed: string[]; mailboxCount: number }`; 400 `{ error: "Invalid cursor" }` on a bad `before`.

- [ ] **Step 1: Write the failing test**

Create `tests/routes/unified-inbox.test.ts`:

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Every settings tier swallows R2 errors, so the route's settings `catch` is
// only reachable when resolveMailboxSettings itself throws. Force that per id.
const { resolveFail } = vi.hoisted(() => ({ resolveFail: new Set<string>() }));
vi.mock("../../workers/lib/mailbox-settings", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../../workers/lib/mailbox-settings")>();
	return {
		...actual,
		resolveMailboxSettings: async (env: Parameters<typeof actual.resolveMailboxSettings>[0], id: string) => {
			if (resolveFail.has(id)) throw new Error("settings down");
			return actual.resolveMailboxSettings(env, id);
		},
	};
});

import { encodeCursor } from "../../workers/lib/unified-inbox";
import { unifiedInboxRoutes } from "../../workers/routes/unified-inbox";

// Unsigned JWT carrying claims — identity is decoded from cf-access-jwt-assertion (f17).
function makeFakeJwt(claims: Record<string, unknown>): string {
	const b64url = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
	return `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify(claims))}.`;
}

function makeR2Stub(initial: Record<string, string>) {
	const store = { ...initial };
	return {
		async get(key: string) {
			const val = store[key];
			if (val === undefined) return null;
			return { json: async <T>() => JSON.parse(val) as T };
		},
		async put(key: string, value: string) {
			store[key] = value;
		},
		async list({ prefix }: { prefix: string }) {
			return { objects: Object.keys(store).filter((k) => k.startsWith(prefix)).map((key) => ({ key })) };
		},
	};
}

type Row = { id: string; date: string; subject: string };
type Stub = { getThreadedEmails: ReturnType<typeof vi.fn> };

function stubReturning(rows: Row[]): Stub {
	return { getThreadedEmails: vi.fn(async ({ limit }: { limit: number }) => rows.slice(0, limit)) };
}

function makeApp(bucket: ReturnType<typeof makeR2Stub>, stubs: Record<string, Stub>) {
	const MAILBOX = { idFromName: (name: string) => name, get: (id: string) => stubs[id] };
	const app = new Hono();
	app.route("/api/v1/inbox", unifiedInboxRoutes as unknown as Hono);
	return (path: string, caller = "alice@corp.test") =>
		app.request(path, { headers: { "cf-access-jwt-assertion": makeFakeJwt({ email: caller }) } }, {
			BUCKET: bucket,
			MAILBOX,
		});
}

const ALICE_ACL = JSON.stringify({ owner: "alice@corp.test", members: ["alice@corp.test"] });
const BOB_ACL = JSON.stringify({ owner: "bob@corp.test", members: ["bob@corp.test"] });

function baseStore(): Record<string, string> {
	return {
		"mailboxes/ops@a.test.json": JSON.stringify({}),
		"mailboxes/ops@b.test.json": JSON.stringify({}),
		"mailboxes/pot@a.test.json": JSON.stringify({ honeypot: { enabled: true } }),
		"mailboxes/quiet@b.test.json": JSON.stringify({ hideFromAllInboxes: true }),
		"mailboxes/bob@b.test.json": JSON.stringify({}),
		"mailboxes-acl/ops@a.test.json": ALICE_ACL,
		"mailboxes-acl/bob@b.test.json": BOB_ACL,
	};
}

function baseStubs(): Record<string, Stub> {
	return {
		"ops@a.test": stubReturning([{ id: "a1", date: "2026-09-01T10:00:00.000Z", subject: "A" }]),
		"ops@b.test": stubReturning([{ id: "b1", date: "2026-09-01T12:00:00.000Z", subject: "B" }]),
		"pot@a.test": stubReturning([{ id: "p1", date: "2026-09-02T00:00:00.000Z", subject: "lure" }]),
		"quiet@b.test": stubReturning([{ id: "q1", date: "2026-09-02T00:00:00.000Z", subject: "quiet" }]),
		"bob@b.test": stubReturning([{ id: "x1", date: "2026-09-02T00:00:00.000Z", subject: "bob only" }]),
	};
}

describe("GET /api/v1/inbox", () => {
	beforeEach(() => resolveFail.clear());

	it("merges visible mailboxes newest first and drops honeypot, hidden and ACL-denied mailboxes", async () => {
		const stubs = baseStubs();
		const res = await makeApp(makeR2Stub(baseStore()), stubs)("/api/v1/inbox");
		expect(res.status).toBe(200);
		const body = (await res.json()) as { emails: Array<{ id: string; mailbox_id: string }>; nextCursor: string | null; failed: string[]; mailboxCount: number };
		expect(body.emails.map((e) => [e.mailbox_id, e.id])).toEqual([
			["ops@b.test", "b1"],
			["ops@a.test", "a1"],
		]);
		expect(body.failed).toEqual([]);
		expect(body.mailboxCount).toBe(2);
		expect(body.nextCursor).toBeNull();
		expect(stubs["pot@a.test"].getThreadedEmails).not.toHaveBeenCalled();
		expect(stubs["quiet@b.test"].getThreadedEmails).not.toHaveBeenCalled();
		expect(stubs["bob@b.test"].getThreadedEmails).not.toHaveBeenCalled();
		expect(stubs["ops@a.test"].getThreadedEmails).toHaveBeenCalledWith({ folder: "inbox", limit: 26, before: undefined });
	});

	it("returns the other mailboxes and lists a failing one in failed", async () => {
		const stubs = baseStubs();
		stubs["ops@a.test"].getThreadedEmails.mockRejectedValue(new Error("DO reset"));
		const res = await makeApp(makeR2Stub(baseStore()), stubs)("/api/v1/inbox");
		const body = (await res.json()) as { emails: Array<{ id: string }>; failed: string[] };
		expect(body.emails.map((e) => e.id)).toEqual(["b1"]);
		expect(body.failed).toEqual(["ops@a.test"]);
	});

	it("excludes a mailbox whose settings cannot be resolved and lists it in failed", async () => {
		resolveFail.add("ops@b.test");
		const stubs = baseStubs();
		const res = await makeApp(makeR2Stub(baseStore()), stubs)("/api/v1/inbox");
		const body = (await res.json()) as { emails: Array<{ id: string }>; failed: string[] };
		expect(body.emails.map((e) => e.id)).toEqual(["a1"]);
		expect(body.failed).toEqual(["ops@b.test"]);
		expect(stubs["ops@b.test"].getThreadedEmails).not.toHaveBeenCalled();
	});

	it("never lists a mailbox the caller cannot see in failed", async () => {
		resolveFail.add("bob@b.test");
		const res = await makeApp(makeR2Stub(baseStore()), baseStubs())("/api/v1/inbox");
		const body = (await res.json()) as { failed: string[] };
		expect(body.failed).not.toContain("bob@b.test");
	});

	it("passes a decoded cursor through and pages with limit + 1", async () => {
		const stubs = baseStubs();
		const before = { date: "2026-09-01T12:00:00.000Z", id: "b1" };
		await makeApp(makeR2Stub(baseStore()), stubs)(`/api/v1/inbox?limit=5&before=${encodeCursor(before)}`);
		expect(stubs["ops@b.test"].getThreadedEmails).toHaveBeenCalledWith({ folder: "inbox", limit: 6, before });
	});

	it("rejects a malformed cursor with 400", async () => {
		const res = await makeApp(makeR2Stub(baseStore()), baseStubs())("/api/v1/inbox?before=%25%25%25");
		expect(res.status).toBe(400);
	});

	it.each([
		["abc", 26],
		["-5", 2],
		["9999", 51],
	])("clamps limit=%s", async (raw, expectedDoLimit) => {
		const stubs = baseStubs();
		const res = await makeApp(makeR2Stub(baseStore()), stubs)(`/api/v1/inbox?limit=${raw}`);
		expect(res.status).toBe(200);
		expect(stubs["ops@b.test"].getThreadedEmails).toHaveBeenCalledWith({ folder: "inbox", limit: expectedDoLimit, before: undefined });
	});
});
```

Why the `vi.mock`: `getMailboxSettings` (`workers/lib/mailbox-settings.ts:37-54`) and the domain/org readers catch R2 errors and return empty settings, so an R2 stub cannot reach the route's settings `catch`. Mocking `resolveMailboxSettings` per id exercises that branch and the ACL-leak rule (Review Focus 1) deterministically.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/routes/unified-inbox.test.ts`
Expected: FAIL — `Failed to resolve import "../../workers/routes/unified-inbox"`.

- [ ] **Step 3: Write the route**

Create `workers/routes/unified-inbox.ts`:

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * GET /api/v1/inbox — unified "All inboxes" list.
 * Spec: docs/superpowers/specs/2026-09-26-unified-inbox-design.md
 *
 * Mounted at /api/v1/inbox in workers/index.ts, OUTSIDE
 * /api/v1/mailboxes/:mailboxId, so requireMailbox does not run: this handler
 * applies the per-mailbox ACL itself via selectInboxMailboxes. Identity comes
 * from the verified CF Access JWT only (f17) — never the
 * cf-access-authenticated-user-email header.
 *
 * Query: before (opaque cursor from a previous nextCursor), limit (1–50, default 25).
 * Response: { emails, nextCursor, failed, mailboxCount }.
 */

import { Hono } from "hono";
import { Folders } from "../../shared/folders";
import { listMailboxes } from "../lib/email-helpers";
import { callerEmailFromJwt, callerGroupsFromJwt, readMailboxAcl } from "../lib/mailbox-acl";
import { resolveMailboxSettings } from "../lib/mailbox-settings";
import { sidecarConfigOf } from "../lib/sidecar-config";
import {
	decodeCursor,
	mergeInboxPages,
	selectInboxMailboxes,
	type InboxCursor,
	type InboxMailboxFlags,
	type InboxRow,
	type PerMailboxInboxPage,
} from "../lib/unified-inbox";
import type { Env } from "../types";

export const UNIFIED_INBOX_DEFAULT_LIMIT = 25;
export const UNIFIED_INBOX_MAX_LIMIT = 50;

/** The one MailboxDO RPC this route calls (workers/durableObject/index.ts getThreadedEmails). */
type ThreadedInboxStub = {
	getThreadedEmails(opts: { folder: string; limit: number; before?: InboxCursor }): Promise<InboxRow[]>;
};

export const unifiedInboxRoutes = new Hono<{ Bindings: Env }>();

unifiedInboxRoutes.get("/", async (c) => {
	const jwt = c.req.header("cf-access-jwt-assertion");
	const callerEmail = callerEmailFromJwt(jwt)?.toLowerCase() ?? null;
	const callerGroups = callerGroupsFromJwt(jwt);

	let before: InboxCursor | undefined;
	const rawBefore = c.req.query("before");
	if (rawBefore) {
		const decoded = decodeCursor(rawBefore);
		if (!decoded) return c.json({ error: "Invalid cursor" }, 400);
		before = decoded;
	}
	const parsedLimit = Number.parseInt(c.req.query("limit") ?? "", 10);
	const limit = Number.isFinite(parsedLimit)
		? Math.min(Math.max(parsedLimit, 1), UNIFIED_INBOX_MAX_LIMIT)
		: UNIFIED_INBOX_DEFAULT_LIMIT;

	const mailboxes = await listMailboxes(c.env.BUCKET);
	const [acls, flags] = await Promise.all([
		Promise.all(mailboxes.map((m) => readMailboxAcl(c.env, m.id))),
		Promise.all(
			mailboxes.map(async (m): Promise<InboxMailboxFlags | null> => {
				try {
					const raw = (await resolveMailboxSettings(c.env, m.id)).raw;
					return {
						honeypot: !!raw?.honeypot?.enabled,
						sidecar: !!sidecarConfigOf(raw),
						hidden: raw?.hideFromAllInboxes === true,
					};
				} catch (err) {
					console.error("unified-inbox: settings read failed:", m.id, (err as Error)?.message);
					return null;
				}
			}),
		),
	]);
	const { selected, unreadable } = selectInboxMailboxes(
		mailboxes,
		acls,
		flags,
		callerEmail,
		callerGroups,
		import.meta.env.DEV,
	);

	const settled = await Promise.allSettled(
		selected.map(async (m): Promise<PerMailboxInboxPage> => {
			const stub = c.env.MAILBOX.get(c.env.MAILBOX.idFromName(m.id)) as unknown as ThreadedInboxStub;
			const emails = await stub.getThreadedEmails({ folder: Folders.INBOX, limit: limit + 1, before });
			return { mailboxId: m.id, mailboxEmail: m.email, emails };
		}),
	);
	const pages: PerMailboxInboxPage[] = [];
	const failed = unreadable.map((m) => m.id);
	settled.forEach((r, i) => {
		if (r.status === "fulfilled") {
			pages.push(r.value);
			return;
		}
		failed.push(selected[i].id);
		console.error("unified-inbox: mailbox query failed:", selected[i].id, (r.reason as Error)?.message);
	});

	return c.json({ ...mergeInboxPages(pages, limit), failed, mailboxCount: selected.length });
});
```

In `workers/index.ts`, add the import after line 41:

```ts
import { unifiedInboxRoutes } from "./routes/unified-inbox";
```

and after line 173 (`app.route("/api/v1/mailboxes/:mailboxId", sendEmailRoutes);`):

```ts
// Unified All inboxes (spec 2026-09-26). Not under /mailboxes/:mailboxId, so
// requireMailbox does not run — the route ACL-filters every mailbox itself.
app.route("/api/v1/inbox", unifiedInboxRoutes);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/routes/unified-inbox.test.ts`
Expected: PASS (9 tests: 6 `it` + 3 `it.each` rows).

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck`
Expected: exit 0. If `import.meta.env` is untyped in `workers/routes/`, copy the `/// <reference ... />` or type import that `workers/index.ts` relies on for `import.meta.env.DEV`. Do not replace the check with `false`.

- [ ] **Step 6: Commit**

```bash
git add workers/routes/unified-inbox.ts workers/index.ts tests/routes/unified-inbox.test.ts
git commit -m "feat(inbox): GET /api/v1/inbox merges visible mailbox inboxes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Extract `EmailListRow` from `email-list.tsx`

A behavior-preserving refactor so `/inbox` reuses the row markup. The existing frontend suite is the gate; one new test covers the new `mailboxLabel` chip.

**Files:**
- Create: `app/components/EmailListRow.tsx`
- Modify: `app/routes/email-list.tsx` (move `EmailVerdictPill` lines 31–48 and `hasUnread` lines 292–297 out; replace row markup lines 381–487)
- Test: `tests/frontend/email-list-row.test.tsx`

**Interfaces:**
- Produces:
  - `export function hasUnread(email: Email): boolean`
  - `export default function EmailListRow(props: EmailListRowProps)` where

```ts
export interface EmailListRowProps {
	email: Email;
	isSelected: boolean;
	/** Tighter padding while the reading pane is open (md+). */
	compact: boolean;
	/** Unified inbox only: owning mailbox address rendered as a chip. */
	mailboxLabel?: string;
	onOpen: () => void;
	onToggleStar: () => void;
	onToggleRead: () => void;
	onDelete: () => void;
}
```

- [ ] **Step 1: Write the failing test**

Create `tests/frontend/email-list-row.test.tsx`:

```tsx
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import EmailListRow from "~/components/EmailListRow";
import type { Email } from "~/types";
import { renderWithProviders } from "./test-utils";

const EMAIL: Email = {
	id: "e1",
	subject: "Quarterly numbers",
	sender: "cfo@vendor.test",
	recipient: "ops@a.test",
	date: "2026-09-01T12:00:00.000Z",
	read: false,
	starred: false,
	snippet: "See attached",
	thread_count: 1,
};

function renderRow(extra: Partial<Parameters<typeof EmailListRow>[0]> = {}) {
	const handlers = { onOpen: vi.fn(), onToggleStar: vi.fn(), onToggleRead: vi.fn(), onDelete: vi.fn() };
	renderWithProviders(<EmailListRow email={EMAIL} isSelected={false} compact={false} {...handlers} {...extra} />);
	return handlers;
}

describe("EmailListRow", () => {
	it("renders the mailbox chip only when mailboxLabel is given", () => {
		renderRow({ mailboxLabel: "ops@a.test" });
		expect(screen.getByTestId("row-mailbox")).toHaveTextContent("ops@a.test");
	});

	it("omits the chip on per-mailbox pages", () => {
		renderRow();
		expect(screen.queryByTestId("row-mailbox")).toBeNull();
	});

	it("routes clicks to the right handler without opening the row", async () => {
		const user = userEvent.setup();
		const h = renderRow();
		await user.click(screen.getByRole("button", { name: /star message/i }));
		expect(h.onToggleStar).toHaveBeenCalledTimes(1);
		expect(h.onOpen).not.toHaveBeenCalled();
		await user.click(screen.getByText("Quarterly numbers"));
		expect(h.onOpen).toHaveBeenCalledTimes(1);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/frontend/email-list-row.test.tsx`
Expected: FAIL — `Failed to resolve import "~/components/EmailListRow"`.

- [ ] **Step 3: Create the component**

Create `app/components/EmailListRow.tsx`. The markup is the row from `app/routes/email-list.tsx:383-485`, with handlers turned into props and the chip added after the thread-count badge:

```tsx
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * One conversation row in a mail list. Shared by the per-mailbox folder list
 * (app/routes/email-list.tsx) and the unified /inbox (app/routes/unified-inbox.tsx).
 * Callers own the mutations; this component only renders and forwards clicks.
 */

import { Button, Tooltip } from "@cloudflare/kumo";
import {
	ArrowBendUpLeftIcon,
	EnvelopeOpenIcon,
	EnvelopeSimpleIcon,
	ShieldIcon,
	ShieldWarningIcon,
	StarIcon,
	TrashIcon,
} from "@phosphor-icons/react";
import { formatListDate } from "shared/dates";
import VerdictPill from "~/components/phishsoc/VerdictPill";
import { verdictActionToPill } from "~/components/phishsoc/verdict";
import { formatParticipants, getSnippetText } from "~/lib/utils";
import { parseVerdict, type Email } from "~/types";

function EmailVerdictPill({ email }: { email: Pick<Email, "security_verdict"> }) {
	const verdict = parseVerdict(email.security_verdict);
	const pill = verdictActionToPill(verdict?.action);
	if (!pill || !verdict) return null;
	const icon =
		pill.tone === "danger" ? (
			<ShieldWarningIcon size={12} weight="fill" />
		) : (
			<ShieldIcon size={12} weight="bold" />
		);
	return (
		<VerdictPill tone={pill.tone} icon={icon} title={verdict.explanation}>
			{pill.label}
		</VerdictPill>
	);
}

/** Thread-aware unread check: threaded rows carry thread_unread_count. */
export function hasUnread(email: Email): boolean {
	if (email.thread_unread_count !== undefined) {
		return email.thread_unread_count > 0;
	}
	return !email.read;
}

export interface EmailListRowProps {
	email: Email;
	isSelected: boolean;
	/** Tighter padding while the reading pane is open (md+). */
	compact: boolean;
	/** Unified inbox only: owning mailbox address rendered as a chip. */
	mailboxLabel?: string;
	onOpen: () => void;
	onToggleStar: () => void;
	onToggleRead: () => void;
	onDelete: () => void;
}

export default function EmailListRow({
	email,
	isSelected,
	compact,
	mailboxLabel,
	onOpen,
	onToggleStar,
	onToggleRead,
	onDelete,
}: EmailListRowProps) {
	const snippet = getSnippetText(email.snippet);
	const unread = hasUnread(email);
	return (
		<div
			role="button"
			tabIndex={0}
			onClick={onOpen}
			onKeyDown={(e) => {
				if (e.key === "Enter" || e.key === " ") {
					e.preventDefault();
					onOpen();
				}
			}}
			className={`group flex items-center gap-3 w-full text-left cursor-pointer transition-colors border-b border-line px-4 py-2.5 md:px-6 md:py-3 ${
				compact ? "md:px-4 md:py-2.5" : ""
			} ${isSelected ? "bg-paper-3" : "hover:bg-paper-2"}`}
		>
			{/* Unread dot */}
			<div className="w-2.5 shrink-0 flex justify-center">
				{unread && <div className="h-2 w-2 rounded-full bg-accent" />}
			</div>

			{/* Star */}
			<button
				type="button"
				className="shrink-0 p-0.5 bg-transparent border-0 cursor-pointer"
				aria-label={email.starred ? "Unstar message" : "Star message"}
				onClick={(e) => {
					e.preventDefault();
					e.stopPropagation();
					onToggleStar();
				}}
			>
				<StarIcon
					size={16}
					weight={email.starred ? "fill" : "regular"}
					className={email.starred ? "text-suspect" : "text-ink-3 hover:text-suspect"}
				/>
			</button>

			{/* Content */}
			<div className="min-w-0 flex-1">
				<div className="flex items-center gap-2">
					<span className={`truncate text-sm ${unread ? "font-semibold text-ink" : "text-ink"}`}>
						{formatParticipants(email)}
					</span>
					{(email.thread_count ?? 1) > 1 && (
						<span className="shrink-0 text-xs text-ink-3 bg-paper-3 rounded-full px-1.5 py-0.5 font-medium">
							{email.thread_count}
						</span>
					)}
					{mailboxLabel && (
						<span
							data-testid="row-mailbox"
							title={mailboxLabel}
							className="shrink min-w-0 max-w-[40%] truncate text-xs text-ink-3 border border-line rounded-full px-1.5 py-0.5"
						>
							{mailboxLabel}
						</span>
					)}
					{email.has_draft && <span className="shrink-0 text-xs text-danger font-medium">Draft</span>}
					{email.needs_reply && !email.has_draft && (
						<Tooltip content="Needs reply" asChild>
							<span className="shrink-0 text-suspect">
								<ArrowBendUpLeftIcon size={14} weight="bold" />
							</span>
						</Tooltip>
					)}
					<EmailVerdictPill email={email} />
					<span className="text-sm text-ink-3 shrink-0 ml-auto">{formatListDate(email.date)}</span>
				</div>
				<div className="truncate text-sm mt-0.5">
					<span className={unread ? "font-medium text-ink" : "text-ink-3"}>{email.subject}</span>
					{snippet && <span className="text-ink-3 font-normal"> &mdash; {snippet}</span>}
				</div>
			</div>

			{/* Hover actions */}
			<div className="hidden group-hover:flex items-center shrink-0">
				<Tooltip content={email.read ? "Mark unread" : "Mark read"} asChild>
					<Button
						variant="ghost"
						shape="square"
						size="sm"
						icon={email.read ? <EnvelopeSimpleIcon size={14} /> : <EnvelopeOpenIcon size={14} />}
						onClick={(e) => {
							e.stopPropagation();
							onToggleRead();
						}}
						aria-label={email.read ? "Mark unread" : "Mark read"}
					/>
				</Tooltip>
				<Tooltip content="Delete" asChild>
					<Button
						variant="ghost"
						shape="square"
						size="sm"
						icon={<TrashIcon size={14} />}
						onClick={(e) => {
							e.preventDefault();
							e.stopPropagation();
							onDelete();
						}}
						aria-label="Delete"
					/>
				</Tooltip>
			</div>
		</div>
	);
}
```

- [ ] **Step 4: Switch `email-list.tsx` to the component**

In `app/routes/email-list.tsx`:

1. Delete `EmailVerdictPill` (lines 31–48) and the local `hasUnread` (lines 292–297).
2. Add `import EmailListRow, { hasUnread } from "~/components/EmailListRow";`.
3. Remove imports now used only by the moved code: `ArrowBendUpLeftIcon`, `EnvelopeOpenIcon`, `ShieldIcon`, `StarIcon` (from `@phosphor-icons/react`), `formatListDate`, `VerdictPill`, `verdictActionToPill`, `parseVerdict`, `type Email as EmailType`, and `getSnippetText, formatParticipants`. Keep `EnvelopeSimpleIcon`, `ShieldWarningIcon`, `TrashIcon`, `ArchiveIcon`, `FileIcon`, `PaperPlaneTiltIcon`, `PencilSimpleIcon`, `TrayIcon`, `ArrowsClockwiseIcon` — `FOLDER_EMPTY_STATES`, the empty state and the header still use them. Confirm with `grep -n "StarIcon\|VerdictPill\|formatListDate\|getSnippetText" app/routes/email-list.tsx` → no matches.
4. Replace `toggleStar` and `handleDelete` (lines 256–282) with event-free versions and add `toggleRead`:

```tsx
	const toggleStar = (email: Email) => {
		if (mailboxId)
			updateEmail.mutate(
				{ mailboxId, id: email.id, data: { starred: !email.starred } },
				{ onError: () => feedback.error("Couldn't update email.") },
			);
	};

	const toggleRead = (email: Email) => {
		if (mailboxId)
			updateEmail.mutate(
				{ mailboxId, id: email.id, data: { read: !email.read } },
				{ onError: () => feedback.error("Couldn't update email.") },
			);
	};

	const handleDelete = (emailId: string) => {
		if (mailboxId) {
			const confirmed = window.confirm("Are you sure you want to delete this email?");
			if (!confirmed) return;
			deleteEmail.mutate(
				{ mailboxId, id: emailId },
				{ onError: () => feedback.error("Couldn't delete email.") },
			);
			if (selectedEmailId === emailId) closePanel();
		}
	};
```

5. Replace the `<div>{emails.map((email) => { ... })}</div>` block (lines 381–488) with:

```tsx
						<div>
							{emails.map((email) => (
								<EmailListRow
									key={email.id}
									email={email}
									isSelected={selectedEmailId === email.id}
									compact={isPanelOpen}
									onOpen={() => handleRowClick(email)}
									onToggleStar={() => toggleStar(email)}
									onToggleRead={() => toggleRead(email)}
									onDelete={() => handleDelete(email.id)}
								/>
							))}
						</div>
```

- [ ] **Step 5: Run the new test and every existing email-list test**

Run: `npx vitest run tests/frontend/email-list-row.test.tsx tests/frontend/email-list-deep-link.test.tsx tests/frontend/email-list-compose-button.test.tsx && npm run typecheck`
Expected: PASS; typecheck exit 0.

- [ ] **Step 6: Commit**

```bash
git add app/components/EmailListRow.tsx app/routes/email-list.tsx tests/frontend/email-list-row.test.tsx
git commit -m "refactor(inbox): extract EmailListRow for reuse by All inboxes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Panels accept a `mailboxId` override

`EmailPanel`, `ComposePanel` and `MailboxSplitView` read `:mailboxId` from the URL. `/inbox` has none, so each gains optional `mailboxId` / `folder` props that fall back to the URL. Per-mailbox pages pass nothing and behave as before.

**Files:**
- Modify: `app/components/EmailPanel.tsx:53-57`
- Modify: `app/components/ComposePanel.tsx:15-19`
- Modify: `app/components/MailboxSplitView.tsx`
- Test: `tests/frontend/panel-mailbox-override.test.tsx`

**Interfaces:**
- Produces:
  - `EmailPanel({ emailId, mailboxId?, folder? })`
  - `ComposePanel({ mailboxId?, folder? })` (Task 7 adds `fromPicker?`)
  - `MailboxSplitView({ selectedEmailId, isComposing, children, mailboxId?, folder? })` (Task 7 adds `fromPicker?`) — forwards `mailboxId`/`folder` to both panels.

- [ ] **Step 1: Write the failing test**

Create `tests/frontend/panel-mailbox-override.test.tsx`. The mock set mirrors `tests/frontend/email-panel-send-risk.test.tsx`, with spies on the mailbox-scoped hooks:

```tsx
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// /inbox has no :mailboxId route param, so EmailPanel/ComposePanel accept an
// explicit mailboxId that overrides the URL (spec 2026-09-26 unified inbox).

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import { renderWithProviders } from "./test-utils";
import type { Email } from "~/types";

vi.mock("~/lib/feedback", () => ({
	useFeedback: () => ({ info: vi.fn(), error: vi.fn(), success: vi.fn() }),
}));

vi.mock("~/services/api", async () => {
	const actual = await vi.importActual<typeof import("~/services/api")>("~/services/api");
	return {
		...actual,
		default: {
			...actual.default,
			preflightEmail: vi.fn().mockResolvedValue({ tier: 0, reasons: [] }),
			getEmail: vi.fn(),
		},
	};
});

vi.mock("~/lib/step-up-confirm", () => ({
	requestStepUpConfirmation: vi.fn(),
	StepUpNoPasskeyError: class StepUpNoPasskeyError extends Error {},
}));

const INBOX_EMAIL: Email = {
	id: "e1",
	folder_id: "inbox",
	recipient: "ops@b.test",
	subject: "Hello",
	body: "<p>Hi</p>",
	sender: "someone@ext.test",
	date: "2026-09-01T12:00:00.000Z",
	read: true,
	starred: false,
};

const useEmailSpy = vi.fn();
const useFoldersSpy = vi.fn();
const replyMutate = vi.fn().mockResolvedValue(undefined);

vi.mock("~/queries/emails", () => ({
	useSendEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useSaveDraft: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useReplyToEmail: () => ({ mutateAsync: replyMutate }),
	useForwardEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useDeleteEmail: () => ({ mutate: vi.fn(), mutateAsync: vi.fn() }),
	useUpdateEmail: () => ({ mutate: vi.fn() }),
	useMoveEmail: () => ({ mutate: vi.fn() }),
	useEmail: (mailboxId: string | undefined, emailId: string | undefined) => {
		useEmailSpy(mailboxId, emailId);
		return { data: INBOX_EMAIL };
	},
	useThreadReplies: () => ({ data: [] }),
}));

vi.mock("~/queries/folders", () => ({
	useFolders: (mailboxId: string | undefined) => {
		useFoldersSpy(mailboxId);
		return { data: [] };
	},
}));

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: (id: string | undefined) => ({
		data: id ? { id, email: id, name: id, settings: {} } : undefined,
	}),
}));

vi.mock("~/components/email-panel/SingleMessageView", () => ({ default: () => null }));
vi.mock("~/components/email-panel/ThreadMessage", () => ({ default: () => null }));
vi.mock("~/components/RichTextEditor", () => ({ default: () => null }));

import ComposePanel from "~/components/ComposePanel";
import EmailPanel from "~/components/EmailPanel";
import { useUIStore } from "~/hooks/useUIStore";

describe("mailboxId override", () => {
	beforeEach(() => {
		useEmailSpy.mockReset();
		useFoldersSpy.mockReset();
		replyMutate.mockReset().mockResolvedValue(undefined);
	});

	it("EmailPanel uses the prop when there is no route param", () => {
		renderWithProviders(
			<Routes>
				<Route path="/inbox" element={<EmailPanel emailId="e1" mailboxId="ops@b.test" folder="inbox" />} />
			</Routes>,
			{ initialEntries: ["/inbox"] },
		);
		expect(useEmailSpy).toHaveBeenCalledWith("ops@b.test", "e1");
		expect(useFoldersSpy).toHaveBeenCalledWith("ops@b.test");
	});

	it("EmailPanel still reads the route param when no prop is given", () => {
		renderWithProviders(
			<Routes>
				<Route path="/mailbox/:mailboxId/emails/:folder" element={<EmailPanel emailId="e1" />} />
			</Routes>,
			{ initialEntries: ["/mailbox/m1/emails/inbox"] },
		);
		expect(useEmailSpy).toHaveBeenCalledWith("m1", "e1");
	});

	it("ComposePanel replies from the prop mailbox", async () => {
		useUIStore.setState({
			isComposing: true,
			composeOptions: { mode: "reply", originalEmail: INBOX_EMAIL },
		});
		const user = userEvent.setup();
		renderWithProviders(
			<Routes>
				<Route path="/inbox" element={<ComposePanel mailboxId="ops@b.test" folder="inbox" />} />
			</Routes>,
			{ initialEntries: ["/inbox"] },
		);
		await user.click(await screen.findByTestId("send-button-tier0"));
		await waitFor(() => expect(replyMutate).toHaveBeenCalledTimes(1));
		expect(replyMutate.mock.calls[0][0]).toMatchObject({ mailboxId: "ops@b.test", emailId: "e1" });
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/frontend/panel-mailbox-override.test.tsx`
Expected: FAIL — first test: `useEmailSpy` called with `(undefined, "e1")`; third: reply never sent ("No mailbox selected.").

- [ ] **Step 3: Implement**

`app/components/EmailPanel.tsx` — replace lines 53–57:

```tsx
export default function EmailPanel({
	emailId,
	mailboxId: mailboxIdProp,
	folder: folderProp,
}: {
	emailId: string;
	/** Overrides :mailboxId — set by /inbox, which has no route param. */
	mailboxId?: string;
	folder?: string;
}) {
	const params = useParams<{ mailboxId: string; folder: string }>();
	const mailboxId = mailboxIdProp ?? params.mailboxId;
	const folder = folderProp ?? params.folder;
```

`app/components/ComposePanel.tsx` — replace lines 15–19:

```tsx
export interface ComposePanelProps {
	/** Overrides :mailboxId — set by /inbox, which has no route param. */
	mailboxId?: string;
	folder?: string;
}

export default function ComposePanel({ mailboxId: mailboxIdProp, folder: folderProp }: ComposePanelProps = {}) {
	const params = useParams<{ mailboxId: string; folder: string }>();
	const mailboxId = mailboxIdProp ?? params.mailboxId;
	const folder = folderProp ?? params.folder;
```

`app/components/MailboxSplitView.tsx` — extend the props and forward them:

```tsx
interface MailboxSplitViewProps {
	selectedEmailId: string | null;
	isComposing: boolean;
	children: ReactNode;
	/** /inbox only: mailbox owning the selected row. Per-mailbox pages omit it and the panels read :mailboxId. */
	mailboxId?: string;
	folder?: string;
}

export default function MailboxSplitView({
	selectedEmailId,
	isComposing,
	children,
	mailboxId,
	folder,
}: MailboxSplitViewProps) {
```

and replace the three panel renders (lines 61–72):

```tsx
					{isComposing && !selectedEmailId ? (
						<ComposePanel mailboxId={mailboxId} folder={folder} />
					) : isComposing && selectedEmailId ? (
						<div className="flex flex-col h-full overflow-y-auto">
							<ComposePanel mailboxId={mailboxId} folder={folder} />
							<div className="border-t border-line">
								<EmailPanel emailId={selectedEmailId} mailboxId={mailboxId} folder={folder} />
							</div>
						</div>
					) : selectedEmailId ? (
						<EmailPanel emailId={selectedEmailId} mailboxId={mailboxId} folder={folder} />
					) : null}
```

- [ ] **Step 4: Run the new test and neighbouring suites**

Run: `npx vitest run tests/frontend/panel-mailbox-override.test.tsx tests/frontend/email-panel-send-risk.test.tsx tests/frontend/compose-send-risk.test.tsx tests/frontend/email-list-deep-link.test.tsx`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/components/EmailPanel.tsx app/components/ComposePanel.tsx app/components/MailboxSplitView.tsx tests/frontend/panel-mailbox-override.test.tsx
git commit -m "feat(inbox): let reading and compose panels take an explicit mailbox

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Compose From picker

**Files:**
- Create: `app/lib/compose-from.ts`
- Modify: `app/components/ComposePanel.tsx` (props, picker row before the To row ~line 83, Send/Draft `disabled` ~lines 200–226)
- Modify: `app/components/MailboxSplitView.tsx` (forward `fromPicker`)
- Test: `tests/frontend/compose-from-picker.test.tsx`

**Interfaces:**
- Consumes: Task 6 `ComposePanelProps`, `MailboxSplitView` props.
- Produces:
  - `app/lib/compose-from.ts`: `LAST_FROM_STORAGE_KEY = "phishsoc-unified-last-from"`, `readLastFrom(): string | null`, `writeLastFrom(id: string): void`
  - `ComposePanel.tsx`: `export interface ComposeFromPicker { options: Array<{ id: string; email: string }>; defaultId: string | null }`; `ComposePanelProps.fromPicker?: ComposeFromPicker`
  - `MailboxSplitViewProps.fromPicker?: ComposeFromPicker`
- Behavior: the picker shows only when `fromPicker` is set AND `composeOptions.mode === "new"` AND no `composeOptions.draftEmail`. Then the effective mailbox is the picked id (not the `mailboxId` prop). Send and Save as Draft are disabled until one is picked. Picking writes `localStorage` (try/catch). Changing From does not reset typed fields. The signature is whatever `useComposeForm` inserted when compose opened; a later From change does not rewrite the body.

- [ ] **Step 1: Write the failing test**

Create `tests/frontend/compose-from-picker.test.tsx`:

```tsx
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import { renderWithProviders } from "./test-utils";

vi.mock("~/lib/feedback", () => ({
	useFeedback: () => ({ info: vi.fn(), error: vi.fn(), success: vi.fn() }),
}));
vi.mock("~/services/api", async () => {
	const actual = await vi.importActual<typeof import("~/services/api")>("~/services/api");
	return { ...actual, default: { ...actual.default, preflightEmail: vi.fn().mockResolvedValue({ tier: 0, reasons: [] }) } };
});
vi.mock("~/lib/step-up-confirm", () => ({
	requestStepUpConfirmation: vi.fn(),
	StepUpNoPasskeyError: class StepUpNoPasskeyError extends Error {},
}));

const sendMutate = vi.fn().mockResolvedValue(undefined);
vi.mock("~/queries/emails", () => ({
	useSendEmail: () => ({ mutateAsync: sendMutate }),
	useSaveDraft: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useReplyToEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useForwardEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useDeleteEmail: () => ({ mutate: vi.fn() }),
}));
vi.mock("~/queries/mailboxes", () => ({
	useMailbox: (id: string | undefined) => ({ data: id ? { id, email: id, name: id, settings: {} } : undefined }),
}));
vi.mock("~/components/RichTextEditor", () => ({ default: () => null }));

import ComposePanel from "~/components/ComposePanel";
import { useUIStore } from "~/hooks/useUIStore";
import { LAST_FROM_STORAGE_KEY } from "~/lib/compose-from";

const OPTIONS = [
	{ id: "ops@a.test", email: "ops@a.test" },
	{ id: "sales@b.test", email: "sales@b.test" },
];

function renderPicker(defaultId: string | null, mode: "new" | "reply" = "new") {
	useUIStore.setState({
		isComposing: true,
		composeOptions:
			mode === "new"
				? { mode: "new", originalEmail: null }
				: {
						mode: "reply",
						originalEmail: {
							id: "e1", subject: "Hi", sender: "x@ext.test", recipient: "ops@a.test",
							date: "2026-09-01T12:00:00.000Z", read: true, starred: false,
						},
					},
	});
	return renderWithProviders(
		<Routes>
			<Route path="/inbox" element={<ComposePanel mailboxId="ops@a.test" folder="inbox" fromPicker={{ options: OPTIONS, defaultId }} />} />
		</Routes>,
		{ initialEntries: ["/inbox"] },
	);
}

describe("Compose From picker", () => {
	beforeEach(() => {
		sendMutate.mockReset().mockResolvedValue(undefined);
		localStorage.clear();
	});

	it("disables Send until a mailbox is picked, then sends from it and remembers it", async () => {
		const user = userEvent.setup();
		renderPicker(null);
		const send = await screen.findByTestId("send-button-tier0");
		expect(send).toBeDisabled();
		await user.selectOptions(screen.getByLabelText("From"), "sales@b.test");
		await user.type(screen.getByPlaceholderText(/recipient@example.com/i), "dest@ext.test");
		await user.type(screen.getByPlaceholderText(/email subject/i), "Quote");
		expect(send).toBeEnabled();
		await user.click(send);
		await waitFor(() => expect(sendMutate).toHaveBeenCalledTimes(1));
		expect(sendMutate.mock.calls[0][0].mailboxId).toBe("sales@b.test");
		expect(localStorage.getItem(LAST_FROM_STORAGE_KEY)).toBe("sales@b.test");
	});

	it("pre-selects defaultId", async () => {
		renderPicker("ops@a.test");
		expect(await screen.findByLabelText("From")).toHaveValue("ops@a.test");
	});

	it("keeps typed To and Subject when From changes", async () => {
		const user = userEvent.setup();
		renderPicker("ops@a.test");
		await user.type(await screen.findByPlaceholderText(/recipient@example.com/i), "dest@ext.test");
		await user.type(screen.getByPlaceholderText(/email subject/i), "Quote");
		await user.selectOptions(screen.getByLabelText("From"), "sales@b.test");
		expect(screen.getByPlaceholderText(/recipient@example.com/i)).toHaveValue("dest@ext.test");
		expect(screen.getByPlaceholderText(/email subject/i)).toHaveValue("Quote");
	});

	it("hides the picker for replies", async () => {
		renderPicker("sales@b.test", "reply");
		await screen.findByTestId("send-button-tier0");
		expect(screen.queryByLabelText("From")).toBeNull();
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/frontend/compose-from-picker.test.tsx`
Expected: FAIL — `Failed to resolve import "~/lib/compose-from"`.

- [ ] **Step 3: Create `app/lib/compose-from.ts`**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Last-used From mailbox for the /inbox composer. Per-viewer convenience only:
 * storage can be blocked or empty, so every access is guarded and callers must
 * render correctly with `null`.
 */

export const LAST_FROM_STORAGE_KEY = "phishsoc-unified-last-from";

export function readLastFrom(): string | null {
	try {
		return localStorage.getItem(LAST_FROM_STORAGE_KEY);
	} catch {
		return null;
	}
}

export function writeLastFrom(id: string): void {
	try {
		localStorage.setItem(LAST_FROM_STORAGE_KEY, id);
	} catch {
		// storage blocked — the picker still works, it just won't remember
	}
}
```

- [ ] **Step 4: Add the picker to `ComposePanel`**

In `app/components/ComposePanel.tsx`:

1. Add imports: `import { useState } from "react";`, `import { useUIStore } from "~/hooks/useUIStore";`, `import { writeLastFrom } from "~/lib/compose-from";`.
2. Replace the Task 6 props/param block with:

```tsx
export interface ComposeFromPicker {
	/** Mailboxes the operator may send from (inbox-navigable, including ones hidden from All inboxes). */
	options: Array<{ id: string; email: string }>;
	/** Pre-selected mailbox id, or null to force a choice. */
	defaultId: string | null;
}

export interface ComposePanelProps {
	/** Overrides :mailboxId — set by /inbox, which has no route param. */
	mailboxId?: string;
	folder?: string;
	/** /inbox only: From picker for a new message. Ignored for replies, forwards and draft edits. */
	fromPicker?: ComposeFromPicker;
}

export default function ComposePanel({
	mailboxId: mailboxIdProp,
	folder: folderProp,
	fromPicker,
}: ComposePanelProps = {}) {
	const params = useParams<{ mailboxId: string; folder: string }>();
	const { composeOptions } = useUIStore();
	const showFromPicker = !!fromPicker && composeOptions.mode === "new" && !composeOptions.draftEmail;
	const [fromId, setFromId] = useState<string | null>(fromPicker?.defaultId ?? null);
	const mailboxId = showFromPicker ? (fromId ?? undefined) : (mailboxIdProp ?? params.mailboxId);
	const folder = folderProp ?? params.folder;
	const fromMissing = showFromPicker && !fromId;
```

3. Directly inside `<div className="space-y-3">`, before the To row (`<div className="flex items-center gap-2">` containing `htmlFor="compose-to"`), insert:

```tsx
						{showFromPicker && fromPicker && (
							<div className="flex items-center gap-2">
								<label htmlFor="compose-from" className="text-sm font-medium text-ink-3 w-14 shrink-0">
									From
								</label>
								<select
									id="compose-from"
									value={fromId ?? ""}
									onChange={(e) => {
										const v = e.target.value || null;
										setFromId(v);
										if (v) writeLastFrom(v);
									}}
									className="flex-1 min-w-0 rounded-md border border-line bg-paper px-2 py-1 text-sm text-ink"
								>
									<option value="" disabled>
										Choose a mailbox…
									</option>
									{fromPicker.options.map((o) => (
										<option key={o.id} value={o.id}>
											{o.email}
										</option>
									))}
								</select>
							</div>
						)}
```

4. Add `|| fromMissing` to the `disabled` expression of the Save as Draft button and the Send button (`disabled={isSavingDraft || isSending}` → `disabled={isSavingDraft || isSending || fromMissing}`). Apply the same to the draft button's existing `disabled` expression.

In `app/components/MailboxSplitView.tsx`: add `import type { ComposeFromPicker } from "~/components/ComposePanel";`, add `fromPicker?: ComposeFromPicker;` to the props interface and destructure, and pass `fromPicker={fromPicker}` on both `<ComposePanel ... />` renders.

- [ ] **Step 5: Run the new test and the compose suites**

Run: `npx vitest run tests/frontend/compose-from-picker.test.tsx tests/frontend/panel-mailbox-override.test.tsx tests/frontend/compose-send-risk.test.tsx`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/lib/compose-from.ts app/components/ComposePanel.tsx app/components/MailboxSplitView.tsx tests/frontend/compose-from-picker.test.tsx
git commit -m "feat(inbox): From picker for new mail composed from All inboxes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: `/inbox` page and data layer

**Files:**
- Modify: `app/routes.ts` (add route)
- Modify: `app/types/index.ts` (response types)
- Modify: `app/services/api.ts` (client call, next to `searchOrgEmails` ~line 277)
- Modify: `app/queries/keys.ts` (key factory)
- Create: `app/queries/inbox.ts`
- Modify: `app/queries/emails.ts` (invalidate the unified list after mutations: `useInvalidateEmailData` line 110, `useUpdateEmail` `onSettled` ~line 190, `useMarkThreadRead` `onSuccess` ~line 213)
- Create: `app/routes/unified-inbox.tsx`
- Test: `tests/frontend/unified-inbox.test.tsx`, `tests/frontend/unified-inbox-invalidation.test.tsx`

**Interfaces:**
- Consumes: Task 4 response; Task 5 `EmailListRow` / `hasUnread`; Tasks 6–7 `MailboxSplitView` props; `readLastFrom` (Task 7); `useMailboxes` (`app/queries/mailboxes.ts:10`); `useUpdateEmail`, `useMarkThreadRead`, `useDeleteEmail` (`app/queries/emails.ts`).
- Produces:
  - `app/types/index.ts`: `interface UnifiedInboxRow extends Email { mailbox_id: string; mailbox_email: string }`, `interface UnifiedInboxResponse { emails: UnifiedInboxRow[]; nextCursor: string | null; failed: string[]; mailboxCount: number }`
  - `api.listUnifiedInbox(opts: { before: string | null }): Promise<UnifiedInboxResponse>`
  - `queryKeys.unifiedInbox.all = ["unified-inbox"]`, `queryKeys.unifiedInbox.page(before: string | null) = ["unified-inbox", before ?? "head"]`
  - `useUnifiedInbox(before: string | null)`, `UNIFIED_INBOX_REFRESH_MS = 30_000`
  - Route `/inbox` → `app/routes/unified-inbox.tsx`

- [ ] **Step 1: Write the failing invalidation test**

Create `tests/frontend/unified-inbox-invalidation.test.tsx`:

```tsx
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("~/services/api", async () => {
	const actual = await vi.importActual<typeof import("~/services/api")>("~/services/api");
	return {
		...actual,
		default: {
			...actual.default,
			deleteEmail: vi.fn().mockResolvedValue(undefined),
			updateEmail: vi.fn().mockResolvedValue(undefined),
			markThreadRead: vi.fn().mockResolvedValue(undefined),
		},
	};
});

import { useDeleteEmail, useMarkThreadRead, useUpdateEmail } from "~/queries/emails";

function setup() {
	const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
	const spy = vi.spyOn(qc, "invalidateQueries");
	const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
	return { spy, wrapper };
}

const invalidatedUnified = (spy: ReturnType<typeof vi.spyOn>) =>
	spy.mock.calls.some(([arg]) => JSON.stringify((arg as { queryKey?: unknown })?.queryKey) === JSON.stringify(["unified-inbox"]));

describe("email mutations refresh All inboxes", () => {
	it.each([
		["delete", () => useDeleteEmail(), { mailboxId: "ops@a.test", id: "e1" }],
		["update", () => useUpdateEmail(), { mailboxId: "ops@a.test", id: "e1", data: { read: true } }],
		["mark thread read", () => useMarkThreadRead(), { mailboxId: "ops@a.test", threadId: "t1" }],
	])("%s invalidates the unified-inbox query", async (_label, hook, vars) => {
		const { spy, wrapper } = setup();
		const { result } = renderHook(hook as () => { mutateAsync: (v: unknown) => Promise<unknown> }, { wrapper });
		await act(async () => {
			await result.current.mutateAsync(vars);
		});
		expect(invalidatedUnified(spy)).toBe(true);
	});
});
```

Before writing it, confirm the api method names with `grep -n "deleteEmail:\|updateEmail:\|markThreadRead:" app/services/api.ts` and adjust the mock keys if they differ.

- [ ] **Step 2: Run it to verify it fails**

Run: `npx vitest run tests/frontend/unified-inbox-invalidation.test.tsx`
Expected: FAIL — `expected false to be true` for all three.

- [ ] **Step 3: Implement the data layer**

`app/types/index.ts` — after `interface Email { ... }`:

```ts
/** Row from GET /api/v1/inbox: a threaded inbox row tagged with its owning mailbox. */
export interface UnifiedInboxRow extends Email {
	mailbox_id: string;
	mailbox_email: string;
}

export interface UnifiedInboxResponse {
	emails: UnifiedInboxRow[];
	/** Opaque keyset cursor for the next (older) page; null on the last page. */
	nextCursor: string | null;
	/** Mailboxes (visible to the caller) whose inbox could not be read. */
	failed: string[];
	/** Mailboxes included in the merge (0 when every mailbox is hidden). */
	mailboxCount: number;
}
```

`app/services/api.ts` — add `UnifiedInboxResponse` to the `~/types` import, and after `searchOrgEmails`:

```ts
	// Unified All inboxes (spec 2026-09-26).
	listUnifiedInbox: ({ before }: { before: string | null }) =>
		get<UnifiedInboxResponse>("/api/v1/inbox", { params: before ? { before } : {} }),
```

`app/queries/keys.ts` — after the `emails` block:

```ts
	unifiedInbox: {
		all: ["unified-inbox"] as const,
		page: (before: string | null) => ["unified-inbox", before ?? "head"] as const,
	},
```

Create `app/queries/inbox.ts`:

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { useQuery } from "@tanstack/react-query";
import api from "~/services/api";
import type { UnifiedInboxResponse } from "~/types";
import { queryKeys } from "./keys";

/**
 * Polling instead of per-mailbox WebSockets: one socket per mailbox does not
 * scale to the operator's >10 mailboxes. React Query pauses the interval
 * while the tab is hidden.
 */
export const UNIFIED_INBOX_REFRESH_MS = 30_000;

export function useUnifiedInbox(before: string | null) {
	return useQuery<UnifiedInboxResponse>({
		queryKey: queryKeys.unifiedInbox.page(before),
		queryFn: () => api.listUnifiedInbox({ before }),
		refetchInterval: UNIFIED_INBOX_REFRESH_MS,
		refetchOnWindowFocus: true,
	});
}
```

`app/queries/emails.ts` — add `qc.invalidateQueries({ queryKey: queryKeys.unifiedInbox.all });` as the last line inside:
1. the closure returned by `useInvalidateEmailData` (covers send, delete, move, save draft, reply, forward);
2. `useUpdateEmail`'s `onSettled`;
3. `useMarkThreadRead`'s `onSuccess`.

- [ ] **Step 4: Run it to verify it passes**

Run: `npx vitest run tests/frontend/unified-inbox-invalidation.test.tsx`
Expected: PASS (3 cases).

- [ ] **Step 5: Write the failing page test**

Create `tests/frontend/unified-inbox.test.tsx`:

```tsx
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import { renderWithProviders } from "./test-utils";
import { useUIStore } from "~/hooks/useUIStore";
import type { UnifiedInboxResponse, UnifiedInboxRow } from "~/types";

function row(id: string, mailbox: string, extra: Partial<UnifiedInboxRow> = {}): UnifiedInboxRow {
	return {
		id,
		subject: `Subject ${id}`,
		sender: "someone@ext.test",
		recipient: mailbox,
		date: "2026-09-01T12:00:00.000Z",
		read: false,
		starred: false,
		thread_count: 1,
		thread_unread_count: 1,
		mailbox_id: mailbox,
		mailbox_email: mailbox,
		...extra,
	};
}

let response: UnifiedInboxResponse;
const useUnifiedInboxSpy = vi.fn();
vi.mock("~/queries/inbox", () => ({
	useUnifiedInbox: (before: string | null) => {
		useUnifiedInboxSpy(before);
		return { data: response, isFetching: false, isError: false };
	},
}));

vi.mock("~/queries/mailboxes", () => ({
	useMailboxes: () => ({
		data: [
			{ id: "ops@a.test", email: "ops@a.test", name: "ops@a.test" },
			{ id: "sales@b.test", email: "sales@b.test", name: "sales@b.test" },
			{ id: "gw@c.test", email: "gw@c.test", name: "gw@c.test", sidecar: true },
		],
	}),
}));

const updateMutate = vi.fn();
const deleteMutate = vi.fn();
vi.mock("~/queries/emails", () => ({
	useUpdateEmail: () => ({ mutate: updateMutate }),
	useMarkThreadRead: () => ({ mutate: vi.fn() }),
	useDeleteEmail: () => ({ mutate: deleteMutate }),
}));

vi.mock("~/lib/feedback", () => ({
	useFeedback: () => ({ error: vi.fn(), info: vi.fn(), success: vi.fn() }),
}));

vi.mock("~/components/phishsoc/Shell", () => ({
	default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock("~/components/EmailPanel", () => ({
	default: ({ emailId, mailboxId }: { emailId: string; mailboxId?: string }) => (
		<div data-testid="email-panel">{`${mailboxId}|${emailId}`}</div>
	),
}));

vi.mock("~/components/ComposePanel", () => ({
	default: ({ fromPicker }: { fromPicker?: { options: Array<{ id: string }>; defaultId: string | null } }) => (
		<div data-testid="compose-panel">{`${fromPicker?.options.map((o) => o.id).join(",")}|${fromPicker?.defaultId}`}</div>
	),
}));

import UnifiedInboxRoute from "~/routes/unified-inbox";

function renderInbox(path = "/inbox") {
	return renderWithProviders(
		<Routes>
			<Route path="/inbox" element={<UnifiedInboxRoute />} />
			<Route path="/mailboxes" element={<div>mailboxes page</div>} />
		</Routes>,
		{ initialEntries: [path] },
	);
}

describe("/inbox", () => {
	beforeEach(() => {
		useUnifiedInboxSpy.mockReset();
		updateMutate.mockReset();
		deleteMutate.mockReset();
		localStorage.clear();
		useUIStore.setState({ selectedEmailId: null, isComposing: false });
		response = {
			emails: [row("e1", "ops@a.test"), row("e2", "sales@b.test")],
			nextCursor: "CUR1",
			failed: [],
			mailboxCount: 2,
		};
	});

	it("renders merged rows with mailbox chips", () => {
		renderInbox();
		const chips = screen.getAllByTestId("row-mailbox").map((c) => c.textContent);
		expect(chips).toEqual(["ops@a.test", "sales@b.test"]);
	});

	it("opens a row against its own mailbox and marks it read there", async () => {
		const user = userEvent.setup();
		renderInbox();
		await user.click(screen.getByText("Subject e2"));
		expect(screen.getByTestId("email-panel")).toHaveTextContent("sales@b.test|e2");
		expect(updateMutate.mock.calls[0][0]).toMatchObject({ mailboxId: "sales@b.test", id: "e2", data: { read: true } });
	});

	it("pages older and back to newer via the cursor", async () => {
		const user = userEvent.setup();
		renderInbox();
		expect(useUnifiedInboxSpy).toHaveBeenLastCalledWith(null);
		expect(screen.getByRole("button", { name: /newer/i })).toBeDisabled();
		await user.click(screen.getByRole("button", { name: /older/i }));
		expect(useUnifiedInboxSpy).toHaveBeenLastCalledWith("CUR1");
		await user.click(screen.getByRole("button", { name: /newer/i }));
		expect(useUnifiedInboxSpy).toHaveBeenLastCalledWith(null);
	});

	it("disables Older on the last page", () => {
		response = { ...response, nextCursor: null };
		renderInbox();
		expect(screen.getByRole("button", { name: /older/i })).toBeDisabled();
	});

	it("shows a banner naming mailboxes that failed to load", () => {
		response = { ...response, failed: ["broken@z.test"] };
		renderInbox();
		expect(screen.getByText(/1 mailbox didn't load/i)).toHaveTextContent("broken@z.test");
	});

	it("shows the no-mailboxes empty state with a link to /mailboxes", async () => {
		response = { emails: [], nextCursor: null, failed: [], mailboxCount: 0 };
		const user = userEvent.setup();
		renderInbox();
		await user.click(screen.getByRole("link", { name: /manage mailboxes/i }));
		expect(screen.getByText("mailboxes page")).toBeInTheDocument();
	});

	it("opens the ?mailbox=&email= deep link", () => {
		renderInbox("/inbox?mailbox=ops%2Btag%40a.test&email=e9");
		expect(screen.getByTestId("email-panel")).toHaveTextContent("ops+tag@a.test|e9");
	});

	it("clears a selection carried over from a per-mailbox page", () => {
		useUIStore.setState({ selectedEmailId: "stale", isComposing: false });
		renderInbox();
		expect(screen.queryByTestId("email-panel")).toBeNull();
	});

	it("closes the reading pane when the open row is deleted", async () => {
		const user = userEvent.setup();
		vi.spyOn(window, "confirm").mockReturnValue(true);
		renderInbox();
		await user.click(screen.getByText("Subject e1"));
		expect(screen.getByTestId("email-panel")).toBeInTheDocument();
		const rowEl = screen.getByText("Subject e1").closest('[role="button"]') as HTMLElement;
		await user.click(within(rowEl).getByRole("button", { name: /delete/i }));
		expect(deleteMutate.mock.calls[0][0]).toMatchObject({ mailboxId: "ops@a.test", id: "e1" });
		expect(screen.queryByTestId("email-panel")).toBeNull();
	});

	it("offers inbox-navigable mailboxes in the From picker, defaulting to the open row's mailbox", async () => {
		const user = userEvent.setup();
		renderInbox();
		await user.click(screen.getByText("Subject e2"));
		await user.click(screen.getByRole("button", { name: /compose/i }));
		expect(screen.getByTestId("compose-panel")).toHaveTextContent("ops@a.test,sales@b.test|sales@b.test");
	});
});
```

- [ ] **Step 6: Run it to verify it fails**

Run: `npx vitest run tests/frontend/unified-inbox.test.tsx`
Expected: FAIL — `Failed to resolve import "~/routes/unified-inbox"`.

- [ ] **Step 7: Write the page**

Create `app/routes/unified-inbox.tsx`:

```tsx
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * All inboxes (/inbox): merged Inbox conversations across every mailbox the
 * caller can see, minus honeypot, sidecar and hideFromAllInboxes mailboxes
 * (filtering is server-side, GET /api/v1/inbox).
 * Spec: docs/superpowers/specs/2026-09-26-unified-inbox-design.md
 *
 * There is no :mailboxId route param here, so the selected row's mailbox is
 * held in local state and passed to MailboxSplitView explicitly. Every row
 * action goes to the row's own mailbox through the existing per-mailbox
 * mutations.
 */

import { Banner, Button, Tooltip } from "@cloudflare/kumo";
import { ArrowsClockwiseIcon, PencilSimpleIcon } from "@phosphor-icons/react";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { Folders } from "shared/folders";
import EmailListRow, { hasUnread } from "~/components/EmailListRow";
import MailboxSplitView from "~/components/MailboxSplitView";
import Shell from "~/components/phishsoc/Shell";
import { useUIStore } from "~/hooks/useUIStore";
import { readLastFrom } from "~/lib/compose-from";
import { useFeedback } from "~/lib/feedback";
import { useDeleteEmail, useMarkThreadRead, useUpdateEmail } from "~/queries/emails";
import { useUnifiedInbox } from "~/queries/inbox";
import { queryKeys } from "~/queries/keys";
import { useMailboxes } from "~/queries/mailboxes";
import type { UnifiedInboxRow } from "~/types";

export default function UnifiedInboxRoute() {
	const { selectedEmailId, isComposing, selectEmail, closePanel, startCompose } = useUIStore();
	const [selectedMailboxId, setSelectedMailboxId] = useState<string | null>(null);
	// Stack of cursors for pages older than the head. [] = head page.
	const [cursorStack, setCursorStack] = useState<string[]>([]);
	const before = cursorStack.length > 0 ? cursorStack[cursorStack.length - 1] : null;
	const [searchParams, setSearchParams] = useSearchParams();

	const queryClient = useQueryClient();
	const { data, isFetching } = useUnifiedInbox(before);
	const { data: mailboxes } = useMailboxes();
	const updateEmail = useUpdateEmail();
	const markThreadRead = useMarkThreadRead();
	const deleteEmail = useDeleteEmail();
	const feedback = useFeedback();

	const emails = data?.emails ?? [];
	const failed = data?.failed ?? [];
	const isPanelOpen = selectedEmailId !== null || isComposing;

	// A selection made on a per-mailbox page belongs to that mailbox; drop it so
	// it can't open here against the wrong one. Must run before the deep-link effect.
	useEffect(() => {
		closePanel();
	}, [closePanel]);

	// Deep link: /inbox?mailbox=<id>&email=<id> opens that message, then drops the params.
	useEffect(() => {
		const mb = searchParams.get("mailbox");
		const em = searchParams.get("email");
		if (!mb || !em) return;
		setSelectedMailboxId(mb);
		selectEmail(em);
		setSearchParams(
			(prev) => {
				const next = new URLSearchParams(prev);
				next.delete("mailbox");
				next.delete("email");
				return next;
			},
			{ replace: true },
		);
	}, [searchParams, selectEmail, setSearchParams]);

	const fromOptions = useMemo(
		() => (mailboxes ?? []).filter((m) => !m.sidecar).map((m) => ({ id: m.id, email: m.email })),
		[mailboxes],
	);
	const lastFrom = readLastFrom();
	const defaultFrom =
		selectedMailboxId ?? (lastFrom && fromOptions.some((o) => o.id === lastFrom) ? lastFrom : null);

	const handleRowClick = (email: UnifiedInboxRow) => {
		setSelectedMailboxId(email.mailbox_id);
		selectEmail(email.id);
		if (!hasUnread(email)) return;
		if (email.thread_id && email.thread_count && email.thread_count > 1) {
			markThreadRead.mutate(
				{ mailboxId: email.mailbox_id, threadId: email.thread_id },
				{ onError: () => feedback.error("Couldn't mark thread read.") },
			);
		} else {
			updateEmail.mutate(
				{ mailboxId: email.mailbox_id, id: email.id, data: { read: true } },
				{ onError: () => feedback.error("Couldn't update email.") },
			);
		}
	};

	const toggleStar = (email: UnifiedInboxRow) =>
		updateEmail.mutate(
			{ mailboxId: email.mailbox_id, id: email.id, data: { starred: !email.starred } },
			{ onError: () => feedback.error("Couldn't update email.") },
		);

	const toggleRead = (email: UnifiedInboxRow) =>
		updateEmail.mutate(
			{ mailboxId: email.mailbox_id, id: email.id, data: { read: !email.read } },
			{ onError: () => feedback.error("Couldn't update email.") },
		);

	const handleDelete = (email: UnifiedInboxRow) => {
		if (!window.confirm("Are you sure you want to delete this email?")) return;
		deleteEmail.mutate(
			{ mailboxId: email.mailbox_id, id: email.id },
			{ onError: () => feedback.error("Couldn't delete email.") },
		);
		if (selectedEmailId === email.id && selectedMailboxId === email.mailbox_id) closePanel();
	};

	return (
		<Shell>
			<MailboxSplitView
				selectedEmailId={selectedEmailId}
				isComposing={isComposing}
				mailboxId={selectedMailboxId ?? undefined}
				folder={Folders.INBOX}
				fromPicker={{ options: fromOptions, defaultId: defaultFrom }}
			>
				<div className="flex items-center justify-between px-4 py-3.5 border-b border-line shrink-0 md:px-5">
					<h1 className="pp-serif text-ink">All inboxes</h1>
					<div className="flex items-center gap-1">
						<Tooltip content="Compose" side="bottom" asChild>
							<Button
								variant="ghost"
								shape="square"
								size="sm"
								icon={<PencilSimpleIcon size={18} />}
								onClick={() => startCompose()}
								aria-label="Compose"
							/>
						</Tooltip>
						<Tooltip content={isFetching ? "Refreshing..." : "Refresh"} side="bottom" asChild>
							<Button
								variant="ghost"
								shape="square"
								size="sm"
								icon={<ArrowsClockwiseIcon size={18} className={isFetching ? "animate-spin" : ""} />}
								onClick={() => queryClient.invalidateQueries({ queryKey: queryKeys.unifiedInbox.all })}
								disabled={isFetching}
								aria-label="Refresh"
							/>
						</Tooltip>
					</div>
				</div>

				{failed.length > 0 && (
					<div className="px-4 pt-3 md:px-5">
						<Banner
							variant="error"
							text={`${failed.length} mailbox${failed.length === 1 ? "" : "es"} didn't load: ${failed.join(", ")}`}
						/>
					</div>
				)}

				<div className="flex-1 overflow-y-auto">
					{emails.length > 0 ? (
						emails.map((email) => (
							<EmailListRow
								key={`${email.mailbox_id}:${email.id}`}
								email={email}
								mailboxLabel={email.mailbox_email}
								isSelected={selectedEmailId === email.id && selectedMailboxId === email.mailbox_id}
								compact={isPanelOpen}
								onOpen={() => handleRowClick(email)}
								onToggleStar={() => toggleStar(email)}
								onToggleRead={() => toggleRead(email)}
								onDelete={() => handleDelete(email)}
							/>
						))
					) : data && data.mailboxCount === 0 ? (
						<div className="px-6 py-12 text-center text-sm text-ink-3">
							<div className="text-ink font-medium">No mailboxes in All inboxes</div>
							<div className="mt-1">
								Every mailbox is hidden or none exist yet.{" "}
								<Link to="/mailboxes" className="text-accent hover:underline">
									Manage mailboxes
								</Link>
							</div>
						</div>
					) : data ? (
						<div className="px-6 py-12 text-center text-sm text-ink-3">No mail in any inbox.</div>
					) : null}
				</div>

				<div className="flex justify-center gap-2 py-3 border-t border-line shrink-0">
					<Button
						variant="ghost"
						size="sm"
						onClick={() => setCursorStack((s) => s.slice(0, -1))}
						disabled={cursorStack.length === 0}
					>
						Newer
					</Button>
					<Button
						variant="ghost"
						size="sm"
						onClick={() => data?.nextCursor && setCursorStack((s) => [...s, data.nextCursor as string])}
						disabled={!data?.nextCursor}
					>
						Older
					</Button>
				</div>
			</MailboxSplitView>
		</Shell>
	);
}
```

`app/routes.ts` — after `route("search", "routes/search-results-org.tsx"),`:

```ts
	route("inbox", "routes/unified-inbox.tsx"),
```

- [ ] **Step 8: Run the page test**

Run: `npx vitest run tests/frontend/unified-inbox.test.tsx`
Expected: PASS (10 tests). If the kumo `Banner` does not render `text` as visible text in jsdom, assert on `screen.getByText(/didn't load/i)` via its container instead, and do not drop the assertion.

- [ ] **Step 9: Typecheck**

Run: `npm run typecheck`
Expected: exit 0 (`react-router typegen` picks up the new route).

- [ ] **Step 10: Commit**

```bash
git add app/routes.ts app/types/index.ts app/services/api.ts app/queries/keys.ts app/queries/inbox.ts app/queries/emails.ts app/routes/unified-inbox.tsx tests/frontend/unified-inbox.test.tsx tests/frontend/unified-inbox-invalidation.test.tsx
git commit -m "feat(inbox): /inbox All inboxes page

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Entry points — sidebar nav and mailbox switcher

**Files:**
- Modify: `app/components/phishsoc/Shell.tsx` (~line 446, after the "Org overview" `NavItem`)
- Modify: `app/components/phishsoc/MailboxSwitcher.tsx` (popup, before the `list.length === 0 ? ...` branch ~line 171)
- Modify: `tests/frontend/shell-mailbox-switcher.test.tsx` (three existing menuitem counts)
- Test: `tests/frontend/shell-all-inboxes-entry.test.tsx`

**Interfaces:**
- Consumes: route `/inbox` (Task 8).
- Behavior:
  - Sidebar: `NavItem to="/inbox"` labelled "All inboxes" with `TrayIcon` (already imported in `Shell.tsx`), always rendered among the org-scoped entries.
  - Switcher: a `Menu.Item` "All inboxes" above the mailbox rows, rendered only when `list.length > 0 && query === ""`. Selecting it calls `onClose()` and navigates to `/inbox`. Shows the `CheckIcon` when the current path is `/inbox`.

- [ ] **Step 1: Write the failing test**

Create `tests/frontend/shell-all-inboxes-entry.test.tsx`. Mocks copied from `tests/frontend/shell-mailbox-switcher.test.tsx:14-38`:

```tsx
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { fireEvent, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Route, Routes, useLocation } from "react-router";

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({ data: undefined }),
	useMailboxes: () => ({
		data: [
			{ id: "m1", email: "alice@acme.com", name: "Alice" },
			{ id: "m2", email: "bob@acme.com", name: "Bob" },
		],
	}),
}));
vi.mock("~/queries/domains", () => ({ useDomainStats: () => ({ data: undefined, isLoading: false, isError: false }) }));
vi.mock("~/queries/dashboard", () => ({ useDashboardSummary: () => ({ data: undefined, isLoading: false, isError: false }) }));
vi.mock("~/queries/folders", () => ({ useFolders: () => ({ data: [] }) }));

import Shell from "~/components/phishsoc/Shell";
import { renderWithProviders } from "./test-utils";

function LocationReporter() {
	return <div data-testid="location">{useLocation().pathname}</div>;
}

function renderAt(path: string) {
	return renderWithProviders(
		<Routes>
			<Route path="/" element={<Shell><LocationReporter /></Shell>} />
			<Route path="/inbox" element={<Shell><LocationReporter /></Shell>} />
		</Routes>,
		{ initialEntries: [path] },
	);
}

async function openMenu(trigger: HTMLElement) {
	fireEvent.mouseDown(trigger);
	await new Promise((r) => setTimeout(r, 0));
}

describe("All inboxes entry points", () => {
	it("sidebar links to /inbox", () => {
		renderAt("/");
		const links = screen.getAllByRole("link", { name: /all inboxes/i });
		expect(links[0]).toHaveAttribute("href", "/inbox");
	});

	it("switcher item navigates to /inbox", async () => {
		const user = userEvent.setup();
		renderAt("/");
		await openMenu(screen.getAllByRole("button", { name: /select mailbox/i })[0]);
		const menu = await screen.findByRole("menu");
		await user.click(within(menu).getByRole("menuitem", { name: /all inboxes/i }));
		expect(screen.getByTestId("location")).toHaveTextContent("/inbox");
	});
});
```

Copy the body of `openMenu` from `tests/frontend/shell-mailbox-switcher.test.tsx:100-110` if the one-tick wait above is not enough for base-ui's popup to open.

- [ ] **Step 2: Run it to verify it fails**

Run: `npx vitest run tests/frontend/shell-all-inboxes-entry.test.tsx`
Expected: FAIL — no link or menuitem named "All inboxes".

- [ ] **Step 3: Implement**

`app/components/phishsoc/Shell.tsx`, directly after the "Org overview" `NavItem` (the one with `to="/"`):

```tsx
				<NavItem to="/inbox" icon={<TrayIcon size={16} />} label="All inboxes" />
```

`app/components/phishsoc/MailboxSwitcher.tsx`:

1. Add `useLocation` to the `react-router` import and, in the component body, `const { pathname } = useLocation();`.
2. Add a handler next to `handlePick`:

```tsx
	const handleAllInboxes = () => {
		onClose();
		if (pathname === "/inbox") return;
		navigate("/inbox");
	};
```

3. Inside `<Menu.Popup>`, after the `{showSearch && (...)}` block and before `{list.length === 0 ? (`:

```tsx
						{list.length > 0 && query === "" && (
							<Menu.Item
								onClick={handleAllInboxes}
								className={`mx-1 flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-[12.5px] outline-none data-[highlighted]:bg-paper-2 border-b border-line mb-1 ${
									pathname === "/inbox" ? "text-ink" : "text-ink-2"
								}`}
							>
								<span className="flex-1 min-w-0 block truncate font-medium">All inboxes</span>
								{pathname === "/inbox" && (
									<CheckIcon size={12} weight="bold" aria-label="Active view" className="text-accent shrink-0" />
								)}
							</Menu.Item>
						)}
```

Check the name of the search-state variable in `MailboxSwitcher.tsx` (`grep -n "useState" app/components/phishsoc/MailboxSwitcher.tsx`). The plan assumes `query`, as used in the `filtered` memo at line ~170.

4. Update the three assertions in `tests/frontend/shell-mailbox-switcher.test.tsx` that count menuitems with an empty query, adding one for the new item: line 222 `toHaveLength(8)` → `toHaveLength(9)`; line 245 `toHaveLength(12)` → `toHaveLength(13)`; line 297 `toHaveLength(12)` → `toHaveLength(13)`. Leave the filtered-query counts (lines 251, 275, 292) and the zero-mailbox count (line 190) unchanged — the item is hidden in those states.

- [ ] **Step 4: Run the new test and all shell suites**

Run: `npx vitest run tests/frontend/shell-all-inboxes-entry.test.tsx tests/frontend/shell-mailbox-switcher.test.tsx tests/frontend/shell-mobile-drawer.test.tsx tests/frontend/shell-folder-nav.test.tsx`
Expected: PASS. If a switcher test that presses ↓ from the search input now lands on "All inboxes" instead of the first mailbox, that is the intended order (All inboxes is first while the query is empty). Update that assertion and say so in the commit body.

- [ ] **Step 5: Commit**

```bash
git add app/components/phishsoc/Shell.tsx app/components/phishsoc/MailboxSwitcher.tsx tests/frontend/shell-all-inboxes-entry.test.tsx tests/frontend/shell-mailbox-switcher.test.tsx
git commit -m "feat(inbox): All inboxes entries in sidebar and mailbox switcher

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Full gates and browser check

**Files:** none unless a gate fails. Fix failures in the task that owns the code, with its own commit.

- [ ] **Step 1: Full suite, typecheck, build**

Run each and record the counts for the PR description:

```bash
npm test 2>&1 | tail -15
```

```bash
npm run typecheck
```

```bash
npm run build 2>&1 | tail -5
```

Expected: `npm test` reports 0 failed across the node, frontend and workers projects; typecheck exit 0; build exit 0.

- [ ] **Step 2: Seed local data**

Start the dev server with the Browser pane's `preview_start` (create `.claude/launch.json` with `npm run dev` on port 5173 if it does not exist). Local dev has no Access in front, so the API is in dev mode. Seed two mailboxes on different domains, with one inbox message each, by creating a draft and moving it to the inbox. This is a dev-only shortcut, not the receive pipeline:

```bash
for mb in ops@alpha.test sales@beta.test; do
  curl -s -X POST localhost:5173/api/v1/mailboxes -H 'content-type: application/json' -d "{\"email\":\"$mb\",\"name\":\"$mb\"}" >/dev/null
  id=$(curl -s -X POST "localhost:5173/api/v1/mailboxes/$mb/drafts" -H 'content-type: application/json' -d "{\"to\":\"x@ext.test\",\"subject\":\"hello $mb\",\"body\":\"hi\"}" | sed -E 's/.*"id":"([^"]+)".*/\1/')
  curl -s -X POST "localhost:5173/api/v1/mailboxes/$mb/emails/$id/move" -H 'content-type: application/json' -d '{"folderId":"inbox"}'
done
```

Then check the API directly:

```bash
curl -s localhost:5173/api/v1/inbox
```

Expected: two rows, one per mailbox, `failed: []`, `mailboxCount: 2`.

- [ ] **Step 3: Browser check**

In the Browser pane:
1. Open `/` → sidebar shows "All inboxes"; click it → `/inbox` lists both rows with mailbox chips.
2. Open the `sales@beta.test` row → reading pane shows it; the page URL stays `/inbox`.
3. Click Compose → From picker lists both mailboxes, pre-selected to `sales@beta.test`.
4. Go to `/mailbox/sales@beta.test/settings`, switch on "Hide from All inboxes", save, return to `/inbox` → only the `ops@alpha.test` row remains.
5. Check at mobile width (375px) that the list and "Back to list" work.

Take a screenshot of steps 1 and 4 for the PR. If any step fails, fix it in the owning task and re-run Step 1.

- [ ] **Step 4: Report**

Summarize in the PR description: test counts from Step 1, the `curl /api/v1/inbox` output from Step 2, and the screenshots. State plainly anything not verified (for example, the real Email Routing receive path was not exercised locally; seeding used draft + move).

---

## Follow-ups (from the spec — file as issues, not in this branch)

- Reply or forward from a different mailbox than the one that received the mail.
- Threaded inbox query omits `security_verdict` (verdict pills appear not to render in the threaded per-mailbox inbox; `/inbox` inherits it). Verify in the running app first.
- Unread count badge on the "All inboxes" entry.
- Write-time inbox index — only if measured fan-out latency at the real mailbox count is unacceptable.
- Domain-tier "hide all mailboxes on this domain" — only if asked for.
