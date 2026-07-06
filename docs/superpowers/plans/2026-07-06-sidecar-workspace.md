# API-Sidecar Mode (Core + Google Workspace Provider) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Score inbound mail in an operator's existing Google Workspace mailbox — no MX change — by polling the Gmail API on a minutely cron, running each new message through the existing security pipeline, and (in active mode) writing verdicts back as Gmail labels.

**Architecture:** A stateless cron fan-out polls each sidecar-enabled mailbox via Gmail `history.list` on a `historyId` cursor stored in that mailbox's existing `MailboxDO`. Normalized messages enter the unchanged pipeline via `receiveEmail()`; the poller (not the pipeline) applies verdict labels, writes audit rows, and auto-creates Cases for flagged mail. Bodies persist at ingest and are reaped after a per-mailbox retention window.

**Tech Stack:** Cloudflare Workers (Hono), Durable Objects (raw SQLite via `ctx.storage.sql`), Zod schemas in `shared/`, PostalMime, `crypto.subtle` RS256 for DWD service-account JWTs, Vitest (node pool, mocked `fetch`), React 19 / React Router v7 frontend.

**Spec:** `docs/superpowers/specs/2026-07-06-sidecar-workspace-design.md` (read it before starting any task).

## Global Constraints

- **No edits to `workers/security/`, `workers/intel/`, or `workers/agent/`** (#30 provider contract).
- **Workers runtime only** in `workers/`: no `node:` imports, no `Buffer`, no `process.env` (`node:sqlite` is allowed in *test* files only, which run in the Vitest node pool).
- **Every settings-tier write runs `stripDefaultEqual`** — the sidecar field flows through the existing mailbox POST/PUT endpoints, so do NOT add a new settings write path.
- **Test mocks route `fetch` by parsed hostname** (`new URL(url).hostname === "gmail.googleapis.com"`), never `startsWith`/`includes` — CodeQL gates PRs on this (CLAUDE.md).
- **Secret-name prefix:** `credentials_secret_name` must start with `SIDECAR_SECRET_` (confused-deputy guard, mirrors `HUB_SECRET_`).
- **Defaults live in resolvers, not Zod schemas** (absent key = inherit; #106 convention).
- **Observe mode is the default**; only active mode writes to the tenant inbox.
- **TDD:** every task writes its failing test first. Run `npm test` and `npm run typecheck` from the repo root.
- **Conventional commits** (`feat:`, `fix:`, `docs:`, `test:`), each ending with the `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` trailer.
- **Gmail API hosts:** OAuth token endpoint `https://oauth2.googleapis.com/token`; API base `https://gmail.googleapis.com`.
- **Verdict actions** are `allow | tag | quarantine | block` (`workers/security/verdict.ts:234-237`).

## File Structure

| File | Status | Responsibility |
| --- | --- | --- |
| `shared/mailbox-settings.ts` | modify | `SidecarSettings` Zod schema, added to `MailboxSettings` |
| `workers/lib/sidecar-config.ts` | create | Validate + default-fill a raw `sidecar` block → `SidecarConfig \| null` (mirrors `validateHubConfig`) |
| `workers/durableObject/migrations.ts` | modify | Migration `26_sidecar_state_audit` (2 tables + 1 column) |
| `workers/durableObject/sidecar-state.ts` | create | `_xImpl(sql, ...)` functions: state get/put, audit append, Message-ID dedupe lookup, reap list/mark |
| `workers/durableObject/index.ts` | modify | Thin `MailboxDO` methods delegating to the impls |
| `workers/providers/gmail-client.ts` | create | Service-account JWT mint + Gmail REST wrappers (profile, history, raw message, labels, modify) |
| `workers/providers/workspace.ts` | create | `WorkspaceProvider`, verdict→label mapping, `pollWorkspaceMailbox`, `pollSidecarMailboxes`, `reapSidecarBodies` |
| `workers/providers/types.ts` | modify | Optional `providerMessageId` on `MailboxInbound` |
| `workers/index.ts` | modify | `receiveEmail` returns `{ messageId, verdict }`; sidecar auto-draft skip; mailbox list annotation; mount sidecar route |
| `workers/routes/sidecar.ts` | create | `POST /test` connection-test endpoint; health read |
| `workers/app.ts` + `wrangler.jsonc` | modify | Minutely cron trigger + `event.cron` branch |
| `app/components/SidecarSettingsCard.tsx` | create | Self-contained settings card (controlled component) |
| `app/routes/settings.tsx` | modify | Wire the card into form state + save payload |
| `app/routes/mailboxes.tsx` | modify | Sidecar badge; exclude sidecar mailboxes from inbox navigation |
| `docs/sidecar-credentials.md` | create | DWD setup, secret provisioning, rotation, revocation |
| `CLAUDE.md` (root) | modify | Add `workers/providers/` row to the subsystem map |

Tests: `tests/lib/sidecar-config.test.ts`, `test/durableObject/sidecar-state.test.ts`, `tests/providers/gmail-client.test.ts`, `tests/providers/workspace-verdict.test.ts`, `tests/providers/workspace-poll.test.ts`, `tests/providers/sidecar-cron.test.ts`, `tests/routes/sidecar-test-endpoint.test.ts`, `tests/workers/receive-email-result.test.ts` — all in the existing Vitest node-pool projects (they are picked up by glob; check `vitest.config.ts` `include` patterns before creating a new directory and mirror an existing project's glob if `tests/providers/` is not matched).

---

### Task 1: `SidecarSettings` schema + `sidecarConfigOf` resolver

**Files:**
- Modify: `shared/mailbox-settings.ts` (add schema after `HoneypotSettings`, ~line 243; add field to `MailboxSettings` ~line 273)
- Create: `workers/lib/sidecar-config.ts`
- Test: `tests/lib/sidecar-config.test.ts`

**Interfaces:**
- Consumes: existing `MailboxSettings` Zod object (`.passthrough()`, all fields optional).
- Produces (later tasks import these):
  ```ts
  // shared/mailbox-settings.ts
  export const SidecarSettings: z.ZodType; export type SidecarSettings;
  // workers/lib/sidecar-config.ts
  export interface SidecarConfig {
    provider: "workspace";
    credentials_secret_name: string;
    mode: "observe" | "active";
    quarantine_behavior: "label-only" | "label-and-archive";
    retention_days: number; // 0 = keep forever
  }
  export function sidecarConfigOf(raw: unknown): SidecarConfig | null;
  ```

- [ ] **Step 1: Write the failing test**

```ts
// tests/lib/sidecar-config.test.ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import { MailboxSettings, SidecarSettings } from "../../shared/mailbox-settings";
import { sidecarConfigOf } from "../../workers/lib/sidecar-config";

describe("SidecarSettings schema", () => {
	it("accepts a minimal valid block", () => {
		const r = SidecarSettings.safeParse({
			provider: "workspace",
			credentials_secret_name: "SIDECAR_SECRET_acme",
		});
		expect(r.success).toBe(true);
	});

	it("rejects a secret name without the SIDECAR_SECRET_ prefix", () => {
		const r = SidecarSettings.safeParse({
			provider: "workspace",
			credentials_secret_name: "HUB_SECRET_acme",
		});
		expect(r.success).toBe(false);
	});

	it("rejects unknown providers", () => {
		const r = SidecarSettings.safeParse({
			provider: "m365",
			credentials_secret_name: "SIDECAR_SECRET_acme",
		});
		expect(r.success).toBe(false);
	});

	it("round-trips through MailboxSettings", () => {
		const r = MailboxSettings.safeParse({
			sidecar: {
				provider: "workspace",
				credentials_secret_name: "SIDECAR_SECRET_acme",
				mode: "active",
				retention_days: 30,
			},
		});
		expect(r.success).toBe(true);
		if (r.success) expect(r.data.sidecar?.mode).toBe("active");
	});

	it("rejects negative retention_days", () => {
		const r = SidecarSettings.safeParse({
			provider: "workspace",
			credentials_secret_name: "SIDECAR_SECRET_acme",
			retention_days: -1,
		});
		expect(r.success).toBe(false);
	});
});

describe("sidecarConfigOf", () => {
	it("returns null when the settings have no sidecar block", () => {
		expect(sidecarConfigOf({})).toBeNull();
		expect(sidecarConfigOf(undefined)).toBeNull();
		expect(sidecarConfigOf(null)).toBeNull();
	});

	it("returns null on an invalid block (bad prefix) instead of throwing", () => {
		expect(
			sidecarConfigOf({ sidecar: { provider: "workspace", credentials_secret_name: "nope" } }),
		).toBeNull();
	});

	it("applies defaults: observe, label-only, 7-day retention", () => {
		const cfg = sidecarConfigOf({
			sidecar: { provider: "workspace", credentials_secret_name: "SIDECAR_SECRET_acme" },
		});
		expect(cfg).toEqual({
			provider: "workspace",
			credentials_secret_name: "SIDECAR_SECRET_acme",
			mode: "observe",
			quarantine_behavior: "label-only",
			retention_days: 7,
		});
	});

	it("preserves explicit values including retention_days 0 (keep forever)", () => {
		const cfg = sidecarConfigOf({
			sidecar: {
				provider: "workspace",
				credentials_secret_name: "SIDECAR_SECRET_acme",
				mode: "active",
				quarantine_behavior: "label-and-archive",
				retention_days: 0,
			},
		});
		expect(cfg?.mode).toBe("active");
		expect(cfg?.quarantine_behavior).toBe("label-and-archive");
		expect(cfg?.retention_days).toBe(0);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/lib/sidecar-config.test.ts`
Expected: FAIL — `SidecarSettings` is not exported / `sidecar-config` module not found.

- [ ] **Step 3: Add the schema to `shared/mailbox-settings.ts`**

Insert after the `HoneypotSettings` type export (~line 243), following the file's doc-comment style:

```ts
/**
 * API-sidecar configuration (issue #31). When present, this mailbox is a
 * *sidecar* mailbox: its authoritative message store is the operator's
 * existing Google Workspace inbox, and PhishSOC only polls, scores, and
 * (in active mode) labels it. Absence of this block = a normal local
 * mailbox. Defaults (observe mode, label-only, 7-day retention) are NOT
 * set here — `workers/lib/sidecar-config.ts` applies them at read time,
 * per the #106 absent-key-inherits convention.
 *
 * The service-account JSON is NEVER persisted in R2 — only the *name* of a
 * worker secret (`credentials_secret_name`), resolved from `env` at call
 * time. Same pattern (and same confused-deputy rationale) as
 * `HubConfig.api_key_secret_name`.
 */
export const SidecarSettings = z
  .object({
    provider: z.literal("workspace"),
    credentials_secret_name: z
      .string()
      .min(1)
      .startsWith("SIDECAR_SECRET_", { message: "Secret name must start with SIDECAR_SECRET_" }),
    mode: z.enum(["observe", "active"]).optional(),
    quarantine_behavior: z.enum(["label-only", "label-and-archive"]).optional(),
    retention_days: z.number().int().min(0).optional(),
  })
  .passthrough();

export type SidecarSettings = z.infer<typeof SidecarSettings>;
```

Then add the field to the `MailboxSettings` object (after `honeypot`, ~line 273):

```ts
  honeypot: HoneypotSettings.optional(),
  sidecar: SidecarSettings.optional(),
```

- [ ] **Step 4: Create `workers/lib/sidecar-config.ts`**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sidecar-config resolution (issue #31). Validates the raw `sidecar` block
 * off a mailbox-settings blob and fills defaults, mirroring
 * `validateHubConfig` in `workers/lib/hub-config.ts`: invalid or absent
 * config resolves to null (feature off) rather than throwing, so a
 * malformed blob can never crash the cron loop or the receive path.
 */

import { SidecarSettings } from "../../shared/mailbox-settings";

export interface SidecarConfig {
	provider: "workspace";
	credentials_secret_name: string;
	mode: "observe" | "active";
	quarantine_behavior: "label-only" | "label-and-archive";
	/** Days to keep message bodies before the reap job strips them. 0 = keep forever. */
	retention_days: number;
}

export const SIDECAR_DEFAULT_RETENTION_DAYS = 7;

/**
 * Resolve the sidecar config from a raw mailbox-settings object (the
 * unresolved per-mailbox tier — `resolveMailboxSettings(...).raw` or a
 * freshly parsed blob). Returns null when absent or invalid.
 */
export function sidecarConfigOf(raw: unknown): SidecarConfig | null {
	if (!raw || typeof raw !== "object") return null;
	const block = (raw as { sidecar?: unknown }).sidecar;
	if (!block) return null;
	const parsed = SidecarSettings.safeParse(block);
	if (!parsed.success) return null;
	return {
		provider: parsed.data.provider,
		credentials_secret_name: parsed.data.credentials_secret_name,
		mode: parsed.data.mode ?? "observe",
		quarantine_behavior: parsed.data.quarantine_behavior ?? "label-only",
		retention_days: parsed.data.retention_days ?? SIDECAR_DEFAULT_RETENTION_DAYS,
	};
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/lib/sidecar-config.test.ts`
Expected: PASS (all cases).

- [ ] **Step 6: Verify `stripDefaultEqual` doesn't mangle the block**

`stripDefaultEqual` (`workers/lib/mailbox-settings.ts:439`) compares against `DEFAULT_MAILBOX_SETTINGS`, which has no `sidecar` key — so the block passes through untouched. Add one regression test to the same file pinning this:

```ts
import { stripDefaultEqual } from "../../workers/lib/mailbox-settings";

describe("stripDefaultEqual x sidecar", () => {
	it("passes the sidecar block through untouched (no system default to strip against)", () => {
		const input = {
			sidecar: { provider: "workspace", credentials_secret_name: "SIDECAR_SECRET_acme" },
		};
		const out = stripDefaultEqual(input as Record<string, unknown>);
		expect(out.sidecar).toEqual(input.sidecar);
	});
});
```

Run: `npx vitest run tests/lib/sidecar-config.test.ts` → PASS. (If `stripDefaultEqual`'s actual signature differs — check `workers/lib/mailbox-settings.ts:439` — adapt the call, not the assertion.)

- [ ] **Step 7: Typecheck and commit**

Run: `npm run typecheck` → clean.

```bash
git add shared/mailbox-settings.ts workers/lib/sidecar-config.ts tests/lib/sidecar-config.test.ts
git commit -m "feat(sidecar): SidecarSettings schema + sidecarConfigOf resolver (#31)"
```

---

### Task 2: MailboxDO migration + sidecar state/audit/dedupe/reap methods

**Files:**
- Modify: `workers/durableObject/migrations.ts` (append to `mailboxMigrations`, after `25_consumed_jti` ~line 536)
- Create: `workers/durableObject/sidecar-state.ts`
- Modify: `workers/durableObject/index.ts` (thin delegate methods on `MailboxDO`)
- Test: `test/durableObject/sidecar-state.test.ts`

**Interfaces:**
- Consumes: `SqlLike` type + the `node:sqlite` test-adapter pattern — read `workers/durableObject/catchall-intel.ts` and `test/durableObject/catchall-intel.test.ts` FIRST and mirror their `_xImpl(sql, ...)` style and `makeSqlLike()` adapter exactly (import `SqlLike` from `./catchall-intel` if exported there; otherwise declare the identical structural type locally).
- Produces (later tasks call these on the DO stub):
  ```ts
  interface SidecarStateRow {
    history_cursor: string | null;
    access_token: string | null;
    token_expires_at: number | null;   // epoch ms
    label_ids: string | null;          // JSON: Record<labelName, labelId>
    last_poll_at: number | null;       // epoch ms
    last_error: string | null;
    consecutive_failures: number;
  }
  MailboxDO.getSidecarState(): Promise<SidecarStateRow | null>
  MailboxDO.putSidecarState(patch: Partial<SidecarStateRow>): Promise<void>   // upsert singleton
  MailboxDO.appendSidecarAudit(row: { ts: string; gmail_message_id: string; email_id: string; action: string; score: number | null; labels_applied: string; mode: string }): Promise<void>
  MailboxDO.findEmailIdByMessageId(messageId: string): Promise<string | null>
  MailboxDO.listReapableSidecarEmails(cutoffIso: string): Promise<Array<{ id: string; attachments: Array<{ id: string; filename: string }> }>>
  MailboxDO.markBodiesReaped(ids: string[], reapedAtIso: string): Promise<number>
  ```

- [ ] **Step 1: Write the failing test**

Copy the `makeSqlLike()` adapter from `test/durableObject/catchall-intel.test.ts`, but create these tables in it (the migration SQL from Step 3, plus the minimal slice of `emails`/`attachments` the reap functions touch):

```ts
// test/durableObject/sidecar-state.test.ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { DatabaseSync } from "node:sqlite";
import { describe, expect, it, beforeEach } from "vitest";
import {
	_getSidecarStateImpl,
	_putSidecarStateImpl,
	_appendSidecarAuditImpl,
	_findEmailIdByMessageIdImpl,
	_listReapableEmailsImpl,
	_markBodiesReapedImpl,
} from "../../workers/durableObject/sidecar-state";

// makeSqlLike(): adapt node:sqlite DatabaseSync to the SqlLike interface —
// copy the adapter implementation from test/durableObject/catchall-intel.test.ts
// verbatim, with this schema:
//   <sidecar_state + sidecar_audit CREATE TABLEs from migration 26>
//   CREATE TABLE emails (id TEXT PRIMARY KEY, folder_id TEXT, date TEXT,
//     body TEXT, message_id TEXT, body_reaped_at TEXT);
//   CREATE TABLE attachments (id TEXT PRIMARY KEY, email_id TEXT, filename TEXT);

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
	beforeEach(() => { /* fresh sql per test via makeSqlLike() inside each it() */ });

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
```

(The exact row-read style — `[...sql.exec(...)]` vs `.toArray()` — must match the `SqlLike` adapter you copied; align the test helpers with it.)

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/durableObject/sidecar-state.test.ts`
Expected: FAIL — module `workers/durableObject/sidecar-state` not found.

- [ ] **Step 3: Append migration 26 to `mailboxMigrations`**

In `workers/durableObject/migrations.ts`, after the `25_consumed_jti` entry:

```ts
	{
		// API-sidecar mode (issue #31). `sidecar_state` is a singleton row
		// (id=1) holding the Gmail history cursor, cached DWD access token,
		// cached label-name→id map, and poll health counters. `sidecar_audit`
		// records every verdict decision the poller makes — including
		// observe-mode decisions that wrote no labels — so promotion to
		// active labeling can be justified from the recorded mix.
		// `emails.body_reaped_at` marks bodies stripped by the retention
		// reap; verdict/metadata columns are never touched by the reap.
		name: "26_sidecar_state_audit",
		sql: `
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

            ALTER TABLE emails ADD COLUMN body_reaped_at TEXT;
        `,
	},
```

- [ ] **Step 4: Create `workers/durableObject/sidecar-state.ts`**

Mirror the query style of `workers/durableObject/catchall-intel.ts` (read it first; use the same `SqlLike` type and cursor-iteration idiom):

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sidecar poll-state, audit, dedupe, and retention-reap logic (issue #31).
 * Pure `_xImpl(sql, ...)` functions so the business logic is testable
 * against node:sqlite without a Workers runtime — same pattern as
 * `catchall-intel.ts`. `MailboxDO` exposes thin async delegates.
 */

import type { SqlLike } from "./catchall-intel";

export interface SidecarStateRow {
	history_cursor: string | null;
	access_token: string | null;
	token_expires_at: number | null;
	label_ids: string | null;
	last_poll_at: number | null;
	last_error: string | null;
	consecutive_failures: number;
}

const STATE_COLUMNS = [
	"history_cursor", "access_token", "token_expires_at",
	"label_ids", "last_poll_at", "last_error", "consecutive_failures",
] as const;

export function _getSidecarStateImpl(sql: SqlLike): SidecarStateRow | null {
	const rows = [...sql.exec(`SELECT ${STATE_COLUMNS.join(", ")} FROM sidecar_state WHERE id = 1`)];
	if (rows.length === 0) return null;
	return rows[0] as unknown as SidecarStateRow;
}

/** Upsert the singleton row, patching only the provided keys. */
export function _putSidecarStateImpl(sql: SqlLike, patch: Partial<SidecarStateRow>): void {
	const keys = STATE_COLUMNS.filter((k) => k in patch);
	if (keys.length === 0) return;
	sql.exec(`INSERT OR IGNORE INTO sidecar_state (id) VALUES (1)`);
	const sets = keys.map((k) => `${k} = ?`).join(", ");
	const values = keys.map((k) => patch[k] as unknown);
	sql.exec(`UPDATE sidecar_state SET ${sets} WHERE id = 1`, ...values);
}

export function _appendSidecarAuditImpl(
	sql: SqlLike,
	row: { ts: string; gmail_message_id: string; email_id: string; action: string; score: number | null; labels_applied: string; mode: string },
): void {
	sql.exec(
		`INSERT INTO sidecar_audit (ts, gmail_message_id, email_id, action, score, labels_applied, mode)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
		row.ts, row.gmail_message_id, row.email_id, row.action, row.score, row.labels_applied, row.mode,
	);
}

export function _findEmailIdByMessageIdImpl(sql: SqlLike, messageId: string): string | null {
	const rows = [...sql.exec(`SELECT id FROM emails WHERE message_id = ? LIMIT 1`, messageId)];
	return rows.length > 0 ? (rows[0] as { id: string }).id : null;
}

export function _listReapableEmailsImpl(
	sql: SqlLike,
	cutoffIso: string,
): Array<{ id: string; attachments: Array<{ id: string; filename: string }> }> {
	const emails = [...sql.exec(
		`SELECT id FROM emails WHERE body_reaped_at IS NULL AND date < ? LIMIT 200`,
		cutoffIso,
	)] as Array<{ id: string }>;
	return emails.map((e) => ({
		id: e.id,
		attachments: [...sql.exec(
			`SELECT id, filename FROM attachments WHERE email_id = ?`, e.id,
		)] as Array<{ id: string; filename: string }>,
	}));
}

export function _markBodiesReapedImpl(sql: SqlLike, ids: string[], reapedAtIso: string): number {
	let n = 0;
	for (const id of ids) {
		sql.exec(`UPDATE emails SET body = '', body_reaped_at = ? WHERE id = ? AND body_reaped_at IS NULL`, reapedAtIso, id);
		sql.exec(`DELETE FROM attachments WHERE email_id = ?`, id);
		n += 1;
	}
	return n;
}
```

(If `SqlLike` is not exported from `catchall-intel.ts`, declare the identical structural type here and note it in the commit message. Adjust the empty-ids early return so the test's `toBe(0)` passes: `if (ids.length === 0) return 0;` before the loop.)

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run test/durableObject/sidecar-state.test.ts`
Expected: PASS.

- [ ] **Step 6: Add thin delegates on `MailboxDO`**

In `workers/durableObject/index.ts`, add near the other email methods (after `moveEmail`, ~line 715), importing the impls at the top of the file:

```ts
	// ── API-sidecar mode (issue #31) ────────────────────────────────────

	async getSidecarState() {
		return _getSidecarStateImpl(this.ctx.storage.sql);
	}

	async putSidecarState(patch: Partial<SidecarStateRow>) {
		_putSidecarStateImpl(this.ctx.storage.sql, patch);
	}

	async appendSidecarAudit(row: { ts: string; gmail_message_id: string; email_id: string; action: string; score: number | null; labels_applied: string; mode: string }) {
		_appendSidecarAuditImpl(this.ctx.storage.sql, row);
	}

	async findEmailIdByMessageId(messageId: string) {
		return _findEmailIdByMessageIdImpl(this.ctx.storage.sql, messageId);
	}

	async listReapableSidecarEmails(cutoffIso: string) {
		return _listReapableEmailsImpl(this.ctx.storage.sql, cutoffIso);
	}

	async markBodiesReaped(ids: string[], reapedAtIso: string) {
		return _markBodiesReapedImpl(this.ctx.storage.sql, ids, reapedAtIso);
	}
```

(`this.ctx.storage.sql` is `SqlStorage`; if its cursor type doesn't structurally satisfy `SqlLike`, cast at the call boundary the same way `catchall-intel.ts`'s DO wrapper does — copy its idiom.)

- [ ] **Step 7: Run full gates and commit**

Run: `npm test` → all suites PASS (report the count). Run: `npm run typecheck` → clean.

```bash
git add workers/durableObject/migrations.ts workers/durableObject/sidecar-state.ts workers/durableObject/index.ts test/durableObject/sidecar-state.test.ts
git commit -m "feat(sidecar): MailboxDO sidecar_state/sidecar_audit migration + state, audit, dedupe, reap methods (#31)"
```

---

### Task 3: Gmail client — service-account auth

**Files:**
- Create: `workers/providers/gmail-client.ts`
- Test: `tests/providers/gmail-client.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks (standalone module; Workers-runtime crypto only).
- Produces:
  ```ts
  export interface ServiceAccount { client_email: string; private_key: string }
  export class GmailApiError extends Error { status: number; body: string }
  export function parseServiceAccountJson(raw: unknown): ServiceAccount | null;
  export async function mintAccessToken(sa: ServiceAccount, impersonate: string): Promise<{ token: string; expiresAt: number }>;
  ```

- [ ] **Step 1: Write the failing test**

The test generates a real RSA keypair with `crypto.subtle` (available globally in Vitest's node pool on Node 18+), exports it as PKCS8 PEM, and verifies the JWT the client signs. Mock `fetch` routed by **parsed hostname**.

```ts
// tests/providers/gmail-client.test.ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	parseServiceAccountJson,
	mintAccessToken,
	GmailApiError,
} from "../../workers/providers/gmail-client";

function b64urlToBytes(s: string): Uint8Array {
	const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
	return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function makeTestServiceAccount(): Promise<{ sa: { client_email: string; private_key: string }; publicKey: CryptoKey }> {
	const kp = await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	);
	const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
	const b64 = btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
	const pem = `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
	return { sa: { client_email: "svc@proj.iam.gserviceaccount.com", private_key: pem }, publicKey: kp.publicKey };
}

describe("parseServiceAccountJson", () => {
	it("accepts a JSON string with client_email and private_key", () => {
		const sa = parseServiceAccountJson(JSON.stringify({ client_email: "a@b.iam", private_key: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----" }));
		expect(sa?.client_email).toBe("a@b.iam");
	});
	it("returns null on malformed JSON, missing fields, or non-string input", () => {
		expect(parseServiceAccountJson("{nope")).toBeNull();
		expect(parseServiceAccountJson(JSON.stringify({ client_email: "a@b" }))).toBeNull();
		expect(parseServiceAccountJson(42)).toBeNull();
	});
});

describe("mintAccessToken", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("POSTs a signed RS256 assertion to oauth2.googleapis.com and returns the token", async () => {
		const { sa, publicKey } = await makeTestServiceAccount();
		let capturedBody = "";
		vi.stubGlobal("fetch", vi.fn(async (url: string | URL, init?: RequestInit) => {
			const u = new URL(String(url));
			if (u.hostname === "oauth2.googleapis.com" && u.pathname === "/token") {
				capturedBody = String(init?.body);
				return new Response(JSON.stringify({ access_token: "tok-123", expires_in: 3600, token_type: "Bearer" }), { status: 200 });
			}
			throw new Error(`unexpected fetch: ${u.hostname}`);
		}));

		const before = Date.now();
		const { token, expiresAt } = await mintAccessToken(sa, "user@tenant.example");
		expect(token).toBe("tok-123");
		expect(expiresAt).toBeGreaterThan(before + 3000_000); // ~3600s minus safety margin

		// Decode + verify the assertion we sent.
		const params = new URLSearchParams(capturedBody);
		expect(params.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
		const assertion = params.get("assertion")!;
		const [h, c, sig] = assertion.split(".");
		const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h)));
		const claims = JSON.parse(new TextDecoder().decode(b64urlToBytes(c)));
		expect(header).toEqual({ alg: "RS256", typ: "JWT" });
		expect(claims.iss).toBe(sa.client_email);
		expect(claims.sub).toBe("user@tenant.example");
		expect(claims.aud).toBe("https://oauth2.googleapis.com/token");
		expect(claims.scope).toBe("https://www.googleapis.com/auth/gmail.modify");
		expect(claims.exp - claims.iat).toBeLessThanOrEqual(3600);
		const ok = await crypto.subtle.verify(
			"RSASSA-PKCS1-v1_5", publicKey,
			b64urlToBytes(sig).buffer as ArrayBuffer,
			new TextEncoder().encode(`${h}.${c}`),
		);
		expect(ok).toBe(true);
	});

	it("throws GmailApiError with the response status on a non-200 token response", async () => {
		const { sa } = await makeTestServiceAccount();
		vi.stubGlobal("fetch", vi.fn(async (url: string | URL) => {
			const u = new URL(String(url));
			if (u.hostname === "oauth2.googleapis.com") {
				return new Response(JSON.stringify({ error: "unauthorized_client" }), { status: 401 });
			}
			throw new Error("unexpected fetch");
		}));
		await expect(mintAccessToken(sa, "user@tenant.example")).rejects.toThrowError(GmailApiError);
		await expect(mintAccessToken(sa, "user@tenant.example")).rejects.toMatchObject({ status: 401 });
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/providers/gmail-client.test.ts`
Expected: FAIL — module not found. (If Vitest reports "no test files found", the `tests/providers/` glob isn't in a project's `include` — open `vitest.config.ts`, find the node project's `include` array, and add the matching glob alongside the existing `tests/**` entries before continuing.)

- [ ] **Step 3: Implement auth in `workers/providers/gmail-client.ts`**

```ts
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Minimal Gmail REST client for the Workspace sidecar provider (issue #31).
 *
 * Auth is a Google service account with domain-wide delegation (DWD): we
 * sign an RS256 JWT assertion with the account's private key, setting
 * `sub` to the monitored user, and exchange it at the OAuth token endpoint
 * for a ~1h access token. Workers-runtime only: crypto.subtle, no node:.
 *
 * Scope is gmail.modify (read + label writes). Observe-only tenants may
 * grant gmail.readonly instead; label writes will then 403 until the DWD
 * grant is widened — see docs/sidecar-credentials.md.
 */

export const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me";

export interface ServiceAccount {
	client_email: string;
	private_key: string;
}

export class GmailApiError extends Error {
	constructor(
		public status: number,
		public body: string,
		message?: string,
	) {
		super(message ?? `Gmail API error ${status}: ${body.slice(0, 200)}`);
		this.name = "GmailApiError";
	}
}

export function parseServiceAccountJson(raw: unknown): ServiceAccount | null {
	if (typeof raw !== "string") return null;
	try {
		const parsed = JSON.parse(raw) as Partial<ServiceAccount>;
		if (typeof parsed.client_email !== "string" || !parsed.client_email) return null;
		if (typeof parsed.private_key !== "string" || !parsed.private_key.includes("PRIVATE KEY")) return null;
		return { client_email: parsed.client_email, private_key: parsed.private_key };
	} catch {
		return null;
	}
}

function b64url(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlJson(obj: unknown): string {
	return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
	const body = pem
		.replace(/-----BEGIN PRIVATE KEY-----/, "")
		.replace(/-----END PRIVATE KEY-----/, "")
		.replace(/\s+/g, "");
	const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
	return crypto.subtle.importKey(
		"pkcs8",
		der.buffer as ArrayBuffer,
		{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		false,
		["sign"],
	);
}

/**
 * Exchange a DWD-signed JWT assertion for an access token impersonating
 * `impersonate`. Returns the token and its expiry (epoch ms, with a 60s
 * safety margin subtracted).
 */
export async function mintAccessToken(
	sa: ServiceAccount,
	impersonate: string,
): Promise<{ token: string; expiresAt: number }> {
	const iat = Math.floor(Date.now() / 1000);
	const header = b64urlJson({ alg: "RS256", typ: "JWT" });
	const claims = b64urlJson({
		iss: sa.client_email,
		sub: impersonate,
		scope: GMAIL_SCOPE,
		aud: TOKEN_URL,
		iat,
		exp: iat + 3600,
	});
	const signingInput = `${header}.${claims}`;
	const key = await importPrivateKey(sa.private_key);
	const sig = await crypto.subtle.sign(
		"RSASSA-PKCS1-v1_5",
		key,
		new TextEncoder().encode(signingInput),
	);
	const assertion = `${signingInput}.${b64url(new Uint8Array(sig))}`;

	const res = await fetch(TOKEN_URL, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
			assertion,
		}).toString(),
	});
	if (!res.ok) throw new GmailApiError(res.status, await res.text());
	const data = (await res.json()) as { access_token: string; expires_in: number };
	return {
		token: data.access_token,
		expiresAt: Date.now() + (data.expires_in - 60) * 1000,
	};
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/providers/gmail-client.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/providers/gmail-client.ts tests/providers/gmail-client.test.ts
git commit -m "feat(sidecar): Gmail DWD service-account auth — RS256 assertion + token exchange (#31)"
```

---

### Task 4: Gmail client — API surface (profile, history, raw message, labels, modify)

**Files:**
- Modify: `workers/providers/gmail-client.ts` (append)
- Test: `tests/providers/gmail-client.test.ts` (append)

**Interfaces:**
- Produces (Task 6/7/9 consume):
  ```ts
  export async function getProfile(token: string): Promise<{ emailAddress: string; historyId: string }>;
  export type HistoryResult =
    | { ok: true; messageIds: string[]; historyId: string }
    | { ok: false; expired: true };
  export async function listNewMessageIds(token: string, startHistoryId: string): Promise<HistoryResult>;
  export async function getRawMessage(token: string, id: string): Promise<Uint8Array>;
  export async function ensureLabels(token: string, names: string[], cached: Record<string, string> | null): Promise<Record<string, string>>;
  export async function modifyMessage(token: string, id: string, addLabelIds: string[], removeLabelIds: string[]): Promise<void>;
  ```

- [ ] **Step 1: Write the failing tests (append to `tests/providers/gmail-client.test.ts`)**

Build one hostname-routed mock dispatcher per test group. Key behaviors to pin:

```ts
import {
	getProfile, listNewMessageIds, getRawMessage, ensureLabels, modifyMessage,
} from "../../workers/providers/gmail-client";

function gmailDispatcher(routes: Record<string, (u: URL, init?: RequestInit) => Response | Promise<Response>>) {
	return vi.fn(async (url: string | URL, init?: RequestInit) => {
		const u = new URL(String(url));
		if (u.hostname !== "gmail.googleapis.com") throw new Error(`unexpected host: ${u.hostname}`);
		for (const [prefix, handler] of Object.entries(routes)) {
			if (u.pathname.startsWith(`/gmail/v1/users/me${prefix}`)) return handler(u, init);
		}
		throw new Error(`unexpected path: ${u.pathname}`);
	});
}

describe("getProfile", () => {
	afterEach(() => vi.unstubAllGlobals());
	it("returns emailAddress and historyId", async () => {
		vi.stubGlobal("fetch", gmailDispatcher({
			"/profile": () => new Response(JSON.stringify({ emailAddress: "u@t.example", historyId: "4711", messagesTotal: 9 }), { status: 200 }),
		}));
		expect(await getProfile("tok")).toEqual({ emailAddress: "u@t.example", historyId: "4711" });
	});
});

describe("listNewMessageIds", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("collects messagesAdded across pages, skipping DRAFT/SENT/CHAT, deduped", async () => {
		let page = 0;
		vi.stubGlobal("fetch", gmailDispatcher({
			"/history": (u) => {
				expect(u.searchParams.get("startHistoryId")).toBe("100");
				expect(u.searchParams.get("historyTypes")).toBe("messageAdded");
				expect(u.searchParams.get("labelId")).toBe("INBOX");
				page += 1;
				if (page === 1) {
					return new Response(JSON.stringify({
						historyId: "200",
						nextPageToken: "p2",
						history: [{ messagesAdded: [
							{ message: { id: "m1", labelIds: ["INBOX"] } },
							{ message: { id: "m2", labelIds: ["SENT"] } },
						] }],
					}), { status: 200 });
				}
				return new Response(JSON.stringify({
					historyId: "200",
					history: [{ messagesAdded: [
						{ message: { id: "m1", labelIds: ["INBOX"] } }, // dupe
						{ message: { id: "m3", labelIds: ["INBOX", "UNREAD"] } },
					] }],
				}), { status: 200 });
			},
		}));
		const r = await listNewMessageIds("tok", "100");
		expect(r).toEqual({ ok: true, messageIds: ["m1", "m3"], historyId: "200" });
	});

	it("returns { ok: false, expired: true } on a 404 (cursor too old)", async () => {
		vi.stubGlobal("fetch", gmailDispatcher({
			"/history": () => new Response("Not Found", { status: 404 }),
		}));
		expect(await listNewMessageIds("tok", "1")).toEqual({ ok: false, expired: true });
	});

	it("returns an empty list when the history response has no history key", async () => {
		vi.stubGlobal("fetch", gmailDispatcher({
			"/history": () => new Response(JSON.stringify({ historyId: "150" }), { status: 200 }),
		}));
		expect(await listNewMessageIds("tok", "100")).toEqual({ ok: true, messageIds: [], historyId: "150" });
	});
});

describe("getRawMessage", () => {
	afterEach(() => vi.unstubAllGlobals());
	it("decodes the base64url raw payload to bytes", async () => {
		const raw = "Subject: hi\r\n\r\nbody";
		const b64 = btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
		vi.stubGlobal("fetch", gmailDispatcher({
			"/messages/m1": (u) => {
				expect(u.searchParams.get("format")).toBe("raw");
				return new Response(JSON.stringify({ id: "m1", raw: b64 }), { status: 200 });
			},
		}));
		const bytes = await getRawMessage("tok", "m1");
		expect(new TextDecoder().decode(bytes)).toBe(raw);
	});
});

describe("ensureLabels", () => {
	afterEach(() => vi.unstubAllGlobals());
	it("returns the cache when it already covers every name (no fetch)", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("must not fetch"); }));
		const cached = { "PhishPilot/Allow": "L1", "PhishPilot/Suspicious": "L2", "PhishPilot/Quarantine": "L3" };
		expect(await ensureLabels("tok", Object.keys(cached), cached)).toEqual(cached);
	});
	it("lists existing labels and creates only the missing ones", async () => {
		const created: string[] = [];
		vi.stubGlobal("fetch", gmailDispatcher({
			"/labels": async (u, init) => {
				if (init?.method === "POST") {
					const body = JSON.parse(String(init.body)) as { name: string };
					created.push(body.name);
					return new Response(JSON.stringify({ id: `NEW-${body.name}`, name: body.name }), { status: 200 });
				}
				return new Response(JSON.stringify({ labels: [{ id: "L1", name: "PhishPilot/Allow" }, { id: "X", name: "INBOX" }] }), { status: 200 });
			},
		}));
		const map = await ensureLabels("tok", ["PhishPilot/Allow", "PhishPilot/Quarantine"], null);
		expect(map["PhishPilot/Allow"]).toBe("L1");
		expect(map["PhishPilot/Quarantine"]).toBe("NEW-PhishPilot/Quarantine");
		expect(created).toEqual(["PhishPilot/Quarantine"]);
	});
});

describe("modifyMessage", () => {
	afterEach(() => vi.unstubAllGlobals());
	it("POSTs addLabelIds/removeLabelIds and throws GmailApiError on failure", async () => {
		let body: unknown;
		vi.stubGlobal("fetch", gmailDispatcher({
			"/messages/m1/modify": async (_u, init) => {
				body = JSON.parse(String(init?.body));
				return new Response("{}", { status: 200 });
			},
		}));
		await modifyMessage("tok", "m1", ["L3"], ["INBOX"]);
		expect(body).toEqual({ addLabelIds: ["L3"], removeLabelIds: ["INBOX"] });

		vi.stubGlobal("fetch", gmailDispatcher({
			"/messages/m1/modify": () => new Response("denied", { status: 403 }),
		}));
		await expect(modifyMessage("tok", "m1", ["L3"], [])).rejects.toMatchObject({ status: 403 });
	});
});
```

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `npx vitest run tests/providers/gmail-client.test.ts`
Expected: Task-3 tests PASS; new tests FAIL (functions not exported).

- [ ] **Step 3: Implement the API surface (append to `workers/providers/gmail-client.ts`)**

```ts
async function gmailFetch(token: string, pathAndQuery: string, init?: RequestInit): Promise<Response> {
	const res = await fetch(`${API_BASE}${pathAndQuery}`, {
		...init,
		headers: {
			Authorization: `Bearer ${token}`,
			...(init?.body ? { "Content-Type": "application/json" } : {}),
			...(init?.headers ?? {}),
		},
	});
	return res;
}

async function gmailJson<T>(token: string, pathAndQuery: string, init?: RequestInit): Promise<T> {
	const res = await gmailFetch(token, pathAndQuery, init);
	if (!res.ok) throw new GmailApiError(res.status, await res.text());
	return (await res.json()) as T;
}

export async function getProfile(token: string): Promise<{ emailAddress: string; historyId: string }> {
	const p = await gmailJson<{ emailAddress: string; historyId: string | number }>(token, "/profile");
	return { emailAddress: p.emailAddress, historyId: String(p.historyId) };
}

export type HistoryResult =
	| { ok: true; messageIds: string[]; historyId: string }
	| { ok: false; expired: true };

/** Gmail-internal labels that mark non-inbound messages we must never score. */
const SKIP_LABELS = new Set(["DRAFT", "SENT", "CHAT"]);
const MAX_HISTORY_PAGES = 3;

/**
 * List message ids added to INBOX since `startHistoryId`. A 404 means the
 * cursor is older than Gmail's history retention — the caller must
 * re-initialize from getProfile() and accept the gap.
 */
export async function listNewMessageIds(token: string, startHistoryId: string): Promise<HistoryResult> {
	const ids: string[] = [];
	const seen = new Set<string>();
	let latestHistoryId = startHistoryId;
	let pageToken: string | undefined;
	for (let page = 0; page < MAX_HISTORY_PAGES; page++) {
		const qs = new URLSearchParams({
			startHistoryId,
			historyTypes: "messageAdded",
			labelId: "INBOX",
		});
		if (pageToken) qs.set("pageToken", pageToken);
		const res = await gmailFetch(token, `/history?${qs.toString()}`);
		if (res.status === 404) return { ok: false, expired: true };
		if (!res.ok) throw new GmailApiError(res.status, await res.text());
		const data = (await res.json()) as {
			historyId?: string | number;
			nextPageToken?: string;
			history?: Array<{ messagesAdded?: Array<{ message?: { id?: string; labelIds?: string[] } }> }>;
		};
		if (data.historyId !== undefined) latestHistoryId = String(data.historyId);
		for (const h of data.history ?? []) {
			for (const added of h.messagesAdded ?? []) {
				const m = added.message;
				if (!m?.id || seen.has(m.id)) continue;
				if ((m.labelIds ?? []).some((l) => SKIP_LABELS.has(l))) continue;
				seen.add(m.id);
				ids.push(m.id);
			}
		}
		if (!data.nextPageToken) break;
		pageToken = data.nextPageToken;
	}
	return { ok: true, messageIds: ids, historyId: latestHistoryId };
}

export async function getRawMessage(token: string, id: string): Promise<Uint8Array> {
	const data = await gmailJson<{ raw: string }>(token, `/messages/${encodeURIComponent(id)}?format=raw`);
	const b64 = data.raw.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(data.raw.length / 4) * 4, "=");
	return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/**
 * Resolve label names → ids, creating any that don't exist yet. `cached`
 * short-circuits everything when it already covers all names (the poller
 * persists the map in sidecar_state.label_ids).
 */
export async function ensureLabels(
	token: string,
	names: string[],
	cached: Record<string, string> | null,
): Promise<Record<string, string>> {
	if (cached && names.every((n) => typeof cached[n] === "string" && cached[n])) return cached;
	const listed = await gmailJson<{ labels?: Array<{ id: string; name: string }> }>(token, "/labels");
	const map: Record<string, string> = {};
	for (const l of listed.labels ?? []) map[l.name] = l.id;
	const out: Record<string, string> = {};
	for (const name of names) {
		if (map[name]) {
			out[name] = map[name];
			continue;
		}
		const created = await gmailJson<{ id: string }>(token, "/labels", {
			method: "POST",
			body: JSON.stringify({ name, labelListVisibility: "labelShow", messageListVisibility: "show" }),
		});
		out[name] = created.id;
	}
	return out;
}

export async function modifyMessage(
	token: string,
	id: string,
	addLabelIds: string[],
	removeLabelIds: string[],
): Promise<void> {
	await gmailJson(token, `/messages/${encodeURIComponent(id)}/modify`, {
		method: "POST",
		body: JSON.stringify({ addLabelIds, removeLabelIds }),
	});
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/providers/gmail-client.test.ts`
Expected: PASS (all groups).

- [ ] **Step 5: Commit**

```bash
git add workers/providers/gmail-client.ts tests/providers/gmail-client.test.ts
git commit -m "feat(sidecar): Gmail API surface — profile, history cursor, raw fetch, labels, modify (#31)"
```

---

### Task 5: `receiveEmail` returns the verdict; sidecar mailboxes skip auto-draft; `providerMessageId` on `MailboxInbound`

**Files:**
- Modify: `workers/providers/types.ts` (add optional field to `MailboxInbound`, ~line 30)
- Modify: `workers/index.ts` (`receiveEmail`, lines ~1492-1839)
- Test: `tests/workers/receive-email-result.test.ts`

**Interfaces:**
- Consumes: existing `receiveEmail(normalized, env, ctx)`; the mock harness in `tests/routes/honeypot-receive-guard.test.ts` (read it FIRST — copy its `vi.mock` set, `makeStub()`, and `makeEnv()` helpers).
- Produces:
  ```ts
  // workers/providers/types.ts — MailboxInbound gains:
  /** Provider-native message id (e.g. Gmail message id). Set by API-sidecar
   *  providers so applyVerdict can address the source message; undefined
   *  for CF Email Routing. */
  providerMessageId?: string;

  // workers/index.ts
  export interface ReceiveEmailResult { messageId: string; verdict: FinalVerdict | null }
  // receiveEmail: Promise<void> → Promise<ReceiveEmailResult | null>
  // (null = not processed: unknown mailbox, honeypot divert, DMARC/TLS-RPT/RUF divert)
  ```

- [ ] **Step 1: Write the failing test**

Copy the entire mock preamble (the four `vi.mock` calls), `makeNormalized()`, `makeStub()`, and `makeEnv()` from `tests/routes/honeypot-receive-guard.test.ts` into the new file, then add:

```ts
// tests/workers/receive-email-result.test.ts  (after the copied harness)

describe("receiveEmail result value (issue #31)", () => {
	it("returns { messageId, verdict } when the pipeline runs", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		mockedResolve.mockResolvedValue(makeResolvedSettings({}));  // helper below
		mockedPipeline.mockResolvedValue({ verdict: { action: "quarantine", score: 80, explanation: "x", signals: [], confidence: 0.9 }, skipped: false, stageTrace: [] } as never);
		const result = await receiveEmail(makeNormalized(), env, makeCtx());
		expect(result).not.toBeNull();
		expect(result!.verdict?.action).toBe("quarantine");
		expect(typeof result!.messageId).toBe("string");
	});

	it("returns null for an unknown mailbox (no settings blob)", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		(env.BUCKET.head as ReturnType<typeof vi.fn>).mockResolvedValue(null);
		const result = await receiveEmail(makeNormalized(), env, makeCtx());
		expect(result).toBeNull();
	});

	it("skips auto-draft dispatch when the mailbox has a sidecar block", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		mockedResolve.mockResolvedValue(makeResolvedSettings({
			raw: { sidecar: { provider: "workspace", credentials_secret_name: "SIDECAR_SECRET_x" } },
			autoDraft: { enabled: true },
		}));
		mockedPipeline.mockResolvedValue({ verdict: null, skipped: true, stageTrace: [] } as never);
		await receiveEmail(makeNormalized(), env, makeCtx());
		// EMAIL_AGENT.get must never be called for a sidecar mailbox.
		expect(env.EMAIL_AGENT.get).not.toHaveBeenCalled();
	});
});
```

Build `makeResolvedSettings(overrides)` in the test to return the same shape the copied harness already stubs for `resolveMailboxSettings` (look at what the honeypot test returns and extend it with `raw` / `autoDraft` overrides). `makeCtx()` returns `{ waitUntil: vi.fn() } as unknown as ExecutionContext`. If `makeEnv` in the source file doesn't mock `EMAIL_AGENT`, add `EMAIL_AGENT: { idFromName: vi.fn().mockReturnValue("id"), get: vi.fn() }` to your copy.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/workers/receive-email-result.test.ts`
Expected: FAIL — `receiveEmail` returns `undefined`, `result` is not an object.

- [ ] **Step 3: Implement**

1. `workers/providers/types.ts` — add to `MailboxInbound` (after `mailboxId`):

```ts
	/**
	 * Provider-native message id (e.g. Gmail message id). Set by API-sidecar
	 * providers so `applyVerdict` can address the source message; undefined
	 * for CF Email Routing, which has no writable source inbox.
	 */
	providerMessageId?: string;
```

2. `workers/index.ts` — at the top, extend the existing `./security/verdict` import (or add one) with `type FinalVerdict`, and declare above `receiveEmail`:

```ts
export interface ReceiveEmailResult {
	messageId: string;
	verdict: FinalVerdict | null;
}
```

3. Change the signature (line ~1492):

```ts
async function receiveEmail(normalized: MailboxInbound, env: Env, ctx: ExecutionContext): Promise<ReceiveEmailResult | null> {
```

4. Convert every early `return;` in the function body to `return null;` — there are five: unknown mailbox (~1499), honeypot divert (~1586), DMARC RUA divert (~1597), TLS-RPT divert (~1613), DMARC RUF divert (~1631).

5. After the auto-draft gate (~line 1821), thread the result through. Replace:

```ts
	const mailboxSettings = await resolveMailboxSettings(env, mailboxId);
	if (!mailboxSettings.autoDraft.enabled) {
		return;
	}
```

with:

```ts
	const result: ReceiveEmailResult = { messageId, verdict: securityVerdict };

	// Sidecar mailboxes (issue #31) never auto-draft: replies happen in the
	// tenant's own inbox, and an agent draft in PhishSOC would be invisible
	// there. This also keeps the read-only promise of observe mode.
	const mailboxSettings = await resolveMailboxSettings(env, mailboxId);
	if (mailboxSettings.raw?.sidecar || !mailboxSettings.autoDraft.enabled) {
		return result;
	}
```

and add `return result;` as the function's final statement (after the agent `ctx.waitUntil` dispatch, ~line 1839).

6. `workers/app.ts` calls `receiveEmail` inside the `email()` handler and ignores the return value — no change needed there; confirm by reading the call site.

- [ ] **Step 4: Run the new test and the full suite**

Run: `npx vitest run tests/workers/receive-email-result.test.ts` → PASS.
Run: `npm test` → all suites PASS (the honeypot guard test and any other `receiveEmail` consumers must be green — a `Promise<void>` caller is unaffected by the richer return type).
Run: `npm run typecheck` → clean.

- [ ] **Step 5: Commit**

```bash
git add workers/providers/types.ts workers/index.ts tests/workers/receive-email-result.test.ts
git commit -m "feat(sidecar): receiveEmail returns { messageId, verdict }; sidecar mailboxes skip auto-draft (#31)"
```

---

### Task 6: `WorkspaceProvider` + verdict→label mapping

**Files:**
- Create: `workers/providers/workspace.ts`
- Test: `tests/providers/workspace-verdict.test.ts`

**Interfaces:**
- Consumes: `ensureLabels`, `modifyMessage`, `GmailApiError` (Task 4); `MailProvider`, `MailboxInbound` (`workers/providers/types.ts`).
- Produces (Task 7/8 build in this same file):
  ```ts
  export const SIDECAR_LABEL_NAMES = ["PhishPilot/Quarantine", "PhishPilot/Suspicious", "PhishPilot/Allow"] as const;
  export function verdictLabelName(action: string): string;   // block|quarantine → Quarantine, tag → Suspicious, allow → Allow
  export async function applyVerdictLabels(token: string, gmailMessageId: string, action: string,
    quarantineBehavior: "label-only" | "label-and-archive",
    labelIds: Record<string, string>): Promise<string[]>;     // returns applied label names (for the audit row)
  export class WorkspaceProvider implements MailProvider;      // id: "workspace-api"
  ```

- [ ] **Step 1: Write the failing test**

```ts
// tests/providers/workspace-verdict.test.ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	SIDECAR_LABEL_NAMES,
	verdictLabelName,
	applyVerdictLabels,
	WorkspaceProvider,
} from "../../workers/providers/workspace";

describe("verdictLabelName", () => {
	it("maps every action to exactly one label", () => {
		expect(verdictLabelName("block")).toBe("PhishPilot/Quarantine");
		expect(verdictLabelName("quarantine")).toBe("PhishPilot/Quarantine");
		expect(verdictLabelName("tag")).toBe("PhishPilot/Suspicious");
		expect(verdictLabelName("allow")).toBe("PhishPilot/Allow");
	});
	it("treats an unknown action as allow (fail-open on labeling, never on scoring)", () => {
		expect(verdictLabelName("weird-future-action")).toBe("PhishPilot/Allow");
	});
});

describe("applyVerdictLabels", () => {
	afterEach(() => vi.unstubAllGlobals());
	const LABEL_IDS = { "PhishPilot/Quarantine": "LQ", "PhishPilot/Suspicious": "LS", "PhishPilot/Allow": "LA" };

	function captureModify() {
		const calls: Array<{ path: string; body: { addLabelIds: string[]; removeLabelIds: string[] } }> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string | URL, init?: RequestInit) => {
			const u = new URL(String(url));
			if (u.hostname !== "gmail.googleapis.com") throw new Error(`unexpected host ${u.hostname}`);
			calls.push({ path: u.pathname, body: JSON.parse(String(init?.body)) });
			return new Response("{}", { status: 200 });
		}));
		return calls;
	}

	it("label-only quarantine adds the quarantine label and removes nothing", async () => {
		const calls = captureModify();
		const applied = await applyVerdictLabels("tok", "g1", "quarantine", "label-only", LABEL_IDS);
		expect(applied).toEqual(["PhishPilot/Quarantine"]);
		expect(calls[0].body).toEqual({ addLabelIds: ["LQ"], removeLabelIds: [] });
	});

	it("label-and-archive quarantine also removes INBOX", async () => {
		const calls = captureModify();
		await applyVerdictLabels("tok", "g1", "block", "label-and-archive", LABEL_IDS);
		expect(calls[0].body).toEqual({ addLabelIds: ["LQ"], removeLabelIds: ["INBOX"] });
	});

	it("allow and tag never archive, regardless of quarantine_behavior", async () => {
		const calls = captureModify();
		await applyVerdictLabels("tok", "g1", "tag", "label-and-archive", LABEL_IDS);
		expect(calls[0].body).toEqual({ addLabelIds: ["LS"], removeLabelIds: [] });
	});
});

describe("WorkspaceProvider", () => {
	it("has id workspace-api and send() rejects (read-only sidecar)", async () => {
		const p = new WorkspaceProvider();
		expect(p.id).toBe("workspace-api");
		await expect(p.send({} as never, {} as never)).rejects.toThrow(/read-only|unsupported/i);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/providers/workspace-verdict.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Create `workers/providers/workspace.ts`**

```ts
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Google Workspace API-sidecar provider (issue #31).
 *
 * Inbound is pull-based: `pollSidecarMailboxes` (minutely cron) walks every
 * sidecar-enabled mailbox, fetches new messages via the Gmail history API,
 * and hands them to the shared pipeline (`receiveEmail`). The POLLER — not
 * the pipeline — applies verdict labels (active mode only), writes audit
 * rows, and auto-creates Cases for flagged mail. See the design spec:
 * docs/superpowers/specs/2026-07-06-sidecar-workspace-design.md.
 *
 * Per #30's contract this file plus gmail-client.ts is the whole provider:
 * no edits to workers/security/, workers/intel/, or workers/agent/.
 */

import type { Env } from "../types";
import type { MailProvider, MailboxInbound, NormalizedOutbound } from "./types";
import { ensureLabels, modifyMessage } from "./gmail-client";

export const SIDECAR_LABEL_NAMES = [
	"PhishPilot/Quarantine",
	"PhishPilot/Suspicious",
	"PhishPilot/Allow",
] as const;

/**
 * Verdict action → Gmail label. Unknown actions map to Allow: labeling is a
 * UX affordance, and a future action value must degrade to "visible but not
 * quarantined" rather than throw inside the poll loop.
 */
export function verdictLabelName(action: string): string {
	if (action === "block" || action === "quarantine") return "PhishPilot/Quarantine";
	if (action === "tag") return "PhishPilot/Suspicious";
	return "PhishPilot/Allow";
}

/**
 * Write the verdict label to the source message. Quarantine-class verdicts
 * optionally archive (remove INBOX) per the mailbox's quarantine_behavior.
 * Returns the label names applied, for the audit row.
 */
export async function applyVerdictLabels(
	token: string,
	gmailMessageId: string,
	action: string,
	quarantineBehavior: "label-only" | "label-and-archive",
	labelIds: Record<string, string>,
): Promise<string[]> {
	const name = verdictLabelName(action);
	const isQuarantine = name === "PhishPilot/Quarantine";
	const removeLabelIds = isQuarantine && quarantineBehavior === "label-and-archive" ? ["INBOX"] : [];
	await modifyMessage(token, gmailMessageId, [labelIds[name]], removeLabelIds);
	return [name];
}

export class WorkspaceProvider implements MailProvider {
	readonly id = "workspace-api";

	async send(_env: Env, _msg: NormalizedOutbound): Promise<{ messageId: string }> {
		throw new Error("workspace-api provider is read-only sidecar; outbound send is unsupported (see issue #32)");
	}

	/**
	 * MailProvider.applyVerdict for callers that hold a MailboxInbound with
	 * providerMessageId. The poll loop calls applyVerdictLabels directly with
	 * its cached token/label ids; this interface method exists so future
	 * pipeline hooks can stay provider-agnostic.
	 */
	async applyVerdict(env: Env, msg: MailboxInbound, verdict: unknown): Promise<void> {
		if (!msg.providerMessageId) return;
		const v = verdict as { action?: string } | null;
		if (!v?.action) return;
		const creds = await sidecarCredentials(env, msg.mailboxId);
		if (!creds) return;
		const labelIds = await ensureLabels(creds.token, [...SIDECAR_LABEL_NAMES], creds.cachedLabelIds);
		await applyVerdictLabels(creds.token, msg.providerMessageId, v.action, creds.cfg.quarantine_behavior, labelIds);
	}
}
```

`sidecarCredentials` doesn't exist yet — Task 7 creates it. For THIS task to compile and pass, add the minimal version now (Task 7 fleshes out state caching):

```ts
import { sidecarConfigOf, type SidecarConfig } from "../lib/sidecar-config";
import { getMailboxSettings } from "../lib/mailbox-settings";
import { mintAccessToken, parseServiceAccountJson } from "./gmail-client";

/**
 * Resolve config + a live access token for a sidecar mailbox, or null when
 * the mailbox isn't sidecar-configured / the secret is unset or malformed.
 */
export async function sidecarCredentials(
	env: Env,
	mailboxId: string,
): Promise<{ cfg: SidecarConfig; token: string; expiresAt: number; cachedLabelIds: Record<string, string> | null } | null> {
	const raw = await getMailboxSettings(env, mailboxId);
	const cfg = sidecarConfigOf(raw);
	if (!cfg) return null;
	const secret = (env as unknown as Record<string, unknown>)[cfg.credentials_secret_name];
	const sa = parseServiceAccountJson(secret);
	if (!sa) return null;
	const { token, expiresAt } = await mintAccessToken(sa, mailboxId);
	return { cfg, token, expiresAt, cachedLabelIds: null };
}
```

(Check `getMailboxSettings`'s exact export name/signature in `workers/lib/mailbox-settings.ts` — it is the single-tier read used by `resolveMailboxSettings`; if it is not exported, use `(await resolveMailboxSettings(env, mailboxId)).raw` instead.)

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/providers/workspace-verdict.test.ts` → PASS.
Run: `npm run typecheck` → clean.

- [ ] **Step 5: Commit**

```bash
git add workers/providers/workspace.ts tests/providers/workspace-verdict.test.ts
git commit -m "feat(sidecar): WorkspaceProvider with verdict-to-Gmail-label mapping (#31)"
```

---

### Task 7: `pollWorkspaceMailbox` — the per-mailbox poll step

**Files:**
- Modify: `workers/providers/workspace.ts` (append)
- Test: `tests/providers/workspace-poll.test.ts`

**Interfaces:**
- Consumes: DO stub methods from Task 2 (`getSidecarState`, `putSidecarState`, `appendSidecarAudit`, `findEmailIdByMessageId`, `createCase`); `receiveEmail` + `ReceiveEmailResult` (Task 5); gmail-client functions (Tasks 3-4); `SidecarConfig` (Task 1).
- Produces:
  ```ts
  export interface PollResult { processed: number; deduped: number; error: string | null }
  export async function pollWorkspaceMailbox(env: Env, ctx: ExecutionContext, mailboxId: string, cfg: SidecarConfig): Promise<PollResult>;
  export const SIDECAR_BACKOFF_THRESHOLD = 5;      // consecutive failures
  export const SIDECAR_BACKOFF_INTERVAL_MS = 15 * 60 * 1000;
  export const MAX_MESSAGES_PER_POLL = 25;
  ```

**Poll algorithm (implement exactly this; each numbered behavior has a test):**

1. Read `sidecar_state` from the mailbox's DO (`env.MAILBOX.get(env.MAILBOX.idFromName(mailboxId))`).
2. **Backoff:** if `consecutive_failures >= SIDECAR_BACKOFF_THRESHOLD` and `last_poll_at` is newer than `SIDECAR_BACKOFF_INTERVAL_MS` ago, return `{ processed: 0, deduped: 0, error: null }` without touching Gmail.
3. **Token:** reuse `state.access_token` when `token_expires_at` is more than 5 minutes away; otherwise mint a fresh one (`parseServiceAccountJson(env[cfg.credentials_secret_name])` → `mintAccessToken(sa, mailboxId)`) and persist it in the state patch at the end.
4. **First run** (no `history_cursor`): `getProfile(token)` → persist `history_cursor = profile.historyId`, `last_poll_at`, reset failures → return. No backfill.
5. **Steady state:** `listNewMessageIds(token, cursor)`. On `{ expired: true }`: re-init the cursor from `getProfile`, set `last_error = "history gap: cursor expired; monitoring reinitialized from current historyId"`, do NOT increment failures, return.
6. Cap the batch at `MAX_MESSAGES_PER_POLL`. If capped, process the slice but do NOT advance the cursor (next tick re-lists; Message-ID dedupe absorbs the overlap). If not capped, advance the cursor to the returned `historyId` after the batch succeeds.
7. Per message id: `getRawMessage` → `new PostalMime().parse(bytes)` → skip when `parsed.messageId` (RFC Message-ID, angle-brackets stripped with the same `extractMsgId` regex `receiveEmail` uses: `/<([^>]+)>/`) already exists via `stub.findEmailIdByMessageId` (count as `deduped`) → build `MailboxInbound { kind: "mailbox", rawEmail: bytes.buffer, parsedEmail: parsed, mailboxId, providerMessageId: id }` → `await receiveEmail(normalized, env, ctx)`.
8. When `receiveEmail` returns a result with a non-null verdict:
   a. **Active mode:** `ensureLabels(token, SIDECAR_LABEL_NAMES, cachedLabelIdsFromState)` (persist the map back to state) → `applyVerdictLabels(...)`.
   b. **Both modes:** `stub.appendSidecarAudit({ ts: new Date().toISOString(), gmail_message_id: id, email_id: result.messageId, action: verdict.action, score: verdict.score ?? null, labels_applied: JSON.stringify(appliedNamesOrEmpty), mode: cfg.mode })`.
   c. **Both modes, quarantine/block only:** `stub.createCase({ title: \`Sidecar flagged: ${subject || "(no subject)"}\`, notes: \`Auto-created by the Workspace sidecar poller. Gmail message ${id}.\`, emailId: result.messageId, score: verdict.score ?? null, confidence: verdict.confidence ?? null })` (signature: `workers/durableObject/index.ts:1552`).
   d. Null verdict (security disabled): no label, no audit row, no case.
9. **Success:** one `putSidecarState` patch: cursor (per rule 6), token cache, label-id cache, `last_poll_at: Date.now()`, `last_error: null`, `consecutive_failures: 0`.
10. **Any throw:** catch it; `putSidecarState({ last_poll_at: Date.now(), last_error: String((e as Error).message).slice(0, 500), consecutive_failures: state.consecutive_failures + 1 })` — cursor untouched (at-least-once) — and return `{ processed, deduped, error: message }`. Never rethrow into the cron loop.

- [ ] **Step 1: Write the failing test**

Mock `receiveEmail` at module level (so the poll test doesn't need the whole pipeline harness), stub `fetch` by hostname for Gmail, and fake the DO stub:

```ts
// tests/providers/workspace-poll.test.ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../workers/index", () => ({
	receiveEmail: vi.fn(),
}));

import { receiveEmail } from "../../workers/index";
import { pollWorkspaceMailbox, MAX_MESSAGES_PER_POLL } from "../../workers/providers/workspace";
import type { SidecarConfig } from "../../workers/lib/sidecar-config";

const mockedReceive = vi.mocked(receiveEmail);

const CFG: SidecarConfig = {
	provider: "workspace",
	credentials_secret_name: "SIDECAR_SECRET_test",
	mode: "observe",
	quarantine_behavior: "label-only",
	retention_days: 7,
};

// Build a raw RFC-5322 message and its base64url encoding for messages.get.
function rawMessage(msgId: string, subject: string): string {
	const raw = `Message-ID: <${msgId}>\r\nSubject: ${subject}\r\nFrom: a@evil.example\r\nTo: user@tenant.example\r\n\r\nbody`;
	return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function makeStub(state: Record<string, unknown> | null) {
	return {
		getSidecarState: vi.fn().mockResolvedValue(state),
		putSidecarState: vi.fn().mockResolvedValue(undefined),
		appendSidecarAudit: vi.fn().mockResolvedValue(undefined),
		findEmailIdByMessageId: vi.fn().mockResolvedValue(null),
		createCase: vi.fn().mockResolvedValue({ id: "case-1" }),
	};
}

function makeEnv(stub: ReturnType<typeof makeStub>) {
	return {
		MAILBOX: { idFromName: vi.fn().mockReturnValue("do-id"), get: vi.fn().mockReturnValue(stub) },
		BUCKET: { get: vi.fn(), head: vi.fn(), put: vi.fn(), list: vi.fn() },
		SIDECAR_SECRET_test: JSON.stringify({
			client_email: "svc@p.iam.gserviceaccount.com",
			// Tests never reach real signing when access_token is cached in state;
			// tests that DO mint use the generated key helper from gmail-client.test.ts.
			private_key: "-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----",
		}),
	} as never;
}

const ctx = { waitUntil: vi.fn() } as never;

/** Cached-token state so no token minting happens in most tests. */
function freshState(cursor: string | null) {
	return {
		history_cursor: cursor,
		access_token: "cached-tok",
		token_expires_at: Date.now() + 3600_000,
		label_ids: null,
		last_poll_at: null,
		last_error: null,
		consecutive_failures: 0,
	};
}

function gmailFetch(routes: Record<string, (u: URL, init?: RequestInit) => Response>) {
	vi.stubGlobal("fetch", vi.fn(async (url: string | URL, init?: RequestInit) => {
		const u = new URL(String(url));
		if (u.hostname !== "gmail.googleapis.com") throw new Error(`unexpected host ${u.hostname}`);
		for (const [prefix, handler] of Object.entries(routes)) {
			if (u.pathname.startsWith(`/gmail/v1/users/me${prefix}`)) return handler(u, init);
		}
		throw new Error(`unexpected path ${u.pathname}`);
	}));
}

afterEach(() => { vi.unstubAllGlobals(); vi.clearAllMocks(); });

describe("pollWorkspaceMailbox", () => {
	it("first run initializes the cursor from getProfile and processes nothing", async () => {
		const stub = makeStub(freshState(null));
		gmailFetch({ "/profile": () => new Response(JSON.stringify({ emailAddress: "u@t", historyId: "500" }), { status: 200 }) });
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r).toEqual({ processed: 0, deduped: 0, error: null });
		expect(mockedReceive).not.toHaveBeenCalled();
		const patch = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch.history_cursor).toBe("500");
		expect(patch.consecutive_failures).toBe(0);
	});

	it("steady state: fetches new messages, calls receiveEmail with providerMessageId, advances cursor", async () => {
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-1", verdict: null });
		gmailFetch({
			"/history": () => new Response(JSON.stringify({
				historyId: "200",
				history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }],
			}), { status: 200 }),
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "hello") }), { status: 200 }),
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r.processed).toBe(1);
		expect(mockedReceive).toHaveBeenCalledTimes(1);
		const normalized = mockedReceive.mock.calls[0][0];
		expect(normalized.kind).toBe("mailbox");
		expect(normalized.mailboxId).toBe("user@tenant.example");
		expect(normalized.providerMessageId).toBe("g1");
		expect(stub.putSidecarState.mock.calls.at(-1)![0].history_cursor).toBe("200");
	});

	it("dedupes on RFC Message-ID and still advances the cursor", async () => {
		const stub = makeStub(freshState("100"));
		stub.findEmailIdByMessageId.mockResolvedValue("already-there");
		gmailFetch({
			"/history": () => new Response(JSON.stringify({
				historyId: "200",
				history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }],
			}), { status: 200 }),
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "hello") }), { status: 200 }),
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r).toMatchObject({ processed: 0, deduped: 1 });
		expect(mockedReceive).not.toHaveBeenCalled();
	});

	it("observe mode: quarantine verdict writes audit + case but NO Gmail modify", async () => {
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-1", verdict: { action: "quarantine", score: 85, confidence: 0.8, explanation: "", signals: [] } as never });
		const modifyCalls: string[] = [];
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "200", history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }] }), { status: 200 }),
			"/messages/g1/modify": (u) => { modifyCalls.push(u.pathname); return new Response("{}", { status: 200 }); },
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "phish!") }), { status: 200 }),
			"/labels": () => new Response(JSON.stringify({ labels: [] }), { status: 200 }),
		});
		await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(modifyCalls).toEqual([]); // observe mode never touches the tenant
		expect(stub.appendSidecarAudit).toHaveBeenCalledWith(expect.objectContaining({
			gmail_message_id: "g1", action: "quarantine", mode: "observe", labels_applied: "[]",
		}));
		expect(stub.createCase).toHaveBeenCalledWith(expect.objectContaining({ emailId: "local-1", score: 85 }));
	});

	it("active mode: quarantine verdict ensures labels and modifies the message", async () => {
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-1", verdict: { action: "block", score: 95, confidence: 0.9, explanation: "", signals: [] } as never });
		let modified: unknown = null;
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "200", history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }] }), { status: 200 }),
			"/messages/g1/modify": (_u, init) => { modified = JSON.parse(String(init?.body)); return new Response("{}", { status: 200 }); },
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "phish!") }), { status: 200 }),
			"/labels": (_u, init) => init?.method === "POST"
				? new Response(JSON.stringify({ id: "NEW", name: JSON.parse(String(init.body)).name }), { status: 200 })
				: new Response(JSON.stringify({ labels: [{ id: "LQ", name: "PhishPilot/Quarantine" }, { id: "LS", name: "PhishPilot/Suspicious" }, { id: "LA", name: "PhishPilot/Allow" }] }), { status: 200 }),
		});
		await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", { ...CFG, mode: "active" });
		expect(modified).toEqual({ addLabelIds: ["LQ"], removeLabelIds: [] });
		expect(stub.appendSidecarAudit).toHaveBeenCalledWith(expect.objectContaining({
			mode: "active", labels_applied: JSON.stringify(["PhishPilot/Quarantine"]),
		}));
	});

	it("null verdict: no audit row, no case, no label", async () => {
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-1", verdict: null });
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "200", history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }] }), { status: 200 }),
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "ok") }), { status: 200 }),
		});
		await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(stub.appendSidecarAudit).not.toHaveBeenCalled();
		expect(stub.createCase).not.toHaveBeenCalled();
	});

	it("expired cursor (404): reinitializes from getProfile, records gap, does not count a failure", async () => {
		const stub = makeStub(freshState("1"));
		gmailFetch({
			"/history": () => new Response("Not Found", { status: 404 }),
			"/profile": () => new Response(JSON.stringify({ emailAddress: "u@t", historyId: "900" }), { status: 200 }),
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r.error).toBeNull();
		const patch = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch.history_cursor).toBe("900");
		expect(patch.consecutive_failures).toBe(0);
		expect(patch.last_error).toMatch(/history gap/);
	});

	it("a Gmail failure freezes the cursor, increments consecutive_failures, records last_error", async () => {
		const stub = makeStub({ ...freshState("100"), consecutive_failures: 1 });
		gmailFetch({ "/history": () => new Response("upstream boom", { status: 503 }) });
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r.error).toMatch(/503/);
		const patch = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch.consecutive_failures).toBe(2);
		expect(patch.history_cursor).toBeUndefined(); // cursor key absent from the patch = frozen
	});

	it("backoff: >=5 consecutive failures + recent poll → skips without calling Gmail", async () => {
		const stub = makeStub({ ...freshState("100"), consecutive_failures: 5, last_poll_at: Date.now() - 60_000 });
		vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("must not fetch"); }));
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r).toEqual({ processed: 0, deduped: 0, error: null });
	});

	it("caps the batch at MAX_MESSAGES_PER_POLL and does not advance the cursor when capped", async () => {
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-x", verdict: null });
		const many = Array.from({ length: MAX_MESSAGES_PER_POLL + 5 }, (_, i) => ({ message: { id: `g${i}`, labelIds: ["INBOX"] } }));
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "999", history: [{ messagesAdded: many }] }), { status: 200 }),
			"/messages/": (u) => {
				const id = u.pathname.split("/").pop()!;
				return new Response(JSON.stringify({ id, raw: rawMessage(`${id}@x`, "s") }), { status: 200 });
			},
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r.processed).toBe(MAX_MESSAGES_PER_POLL);
		expect(stub.putSidecarState.mock.calls.at(-1)![0].history_cursor).toBeUndefined();
	});
});
```

(Route-matching note: `"/messages/g1/modify"` must be checked before `"/messages/g1"` in the dispatcher's route table when both are present — object entries preserve insertion order; put the more specific prefix first, as shown.)

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/providers/workspace-poll.test.ts`
Expected: FAIL — `pollWorkspaceMailbox` not exported.

- [ ] **Step 3: Implement `pollWorkspaceMailbox` (append to `workers/providers/workspace.ts`)**

Implement the 10-step algorithm above. Skeleton with all state-handling decisions made:

```ts
import PostalMime from "postal-mime";
import { receiveEmail } from "../index";
import { getProfile, getRawMessage, listNewMessageIds } from "./gmail-client";

export const SIDECAR_BACKOFF_THRESHOLD = 5;
export const SIDECAR_BACKOFF_INTERVAL_MS = 15 * 60 * 1000;
export const MAX_MESSAGES_PER_POLL = 25;
const TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000;

export interface PollResult { processed: number; deduped: number; error: string | null }

interface SidecarStub {
	getSidecarState(): Promise<{
		history_cursor: string | null; access_token: string | null; token_expires_at: number | null;
		label_ids: string | null; last_poll_at: number | null; last_error: string | null; consecutive_failures: number;
	} | null>;
	putSidecarState(patch: Record<string, unknown>): Promise<void>;
	appendSidecarAudit(row: Record<string, unknown>): Promise<void>;
	findEmailIdByMessageId(messageId: string): Promise<string | null>;
	createCase(input: Record<string, unknown>): Promise<{ id: string }>;
}

const extractMsgId = (s: string) => { const m = s.match(/<([^>]+)>/); return m ? m[1] : s.trim().split(/\s+/)[0]; };

export async function pollWorkspaceMailbox(
	env: Env, ctx: ExecutionContext, mailboxId: string, cfg: SidecarConfig,
): Promise<PollResult> {
	const stub = env.MAILBOX.get(env.MAILBOX.idFromName(mailboxId)) as unknown as SidecarStub;
	const state = (await stub.getSidecarState()) ?? {
		history_cursor: null, access_token: null, token_expires_at: null,
		label_ids: null, last_poll_at: null, last_error: null, consecutive_failures: 0,
	};

	// Backoff gate (rule 2).
	if (
		state.consecutive_failures >= SIDECAR_BACKOFF_THRESHOLD &&
		state.last_poll_at !== null &&
		Date.now() - state.last_poll_at < SIDECAR_BACKOFF_INTERVAL_MS
	) {
		return { processed: 0, deduped: 0, error: null };
	}

	let processed = 0;
	let deduped = 0;
	try {
		// Token (rule 3).
		let token = state.access_token;
		let tokenExpiresAt = state.token_expires_at;
		if (!token || !tokenExpiresAt || tokenExpiresAt - Date.now() < TOKEN_REFRESH_MARGIN_MS) {
			const secret = (env as unknown as Record<string, unknown>)[cfg.credentials_secret_name];
			const sa = parseServiceAccountJson(secret);
			if (!sa) throw new Error(`secret ${cfg.credentials_secret_name} is unset or not service-account JSON (auth)`);
			const minted = await mintAccessToken(sa, mailboxId);
			token = minted.token;
			tokenExpiresAt = minted.expiresAt;
		}

		let labelIds: Record<string, string> | null = state.label_ids
			? (JSON.parse(state.label_ids) as Record<string, string>)
			: null;

		const patch: Record<string, unknown> = {
			access_token: token, token_expires_at: tokenExpiresAt,
			last_poll_at: Date.now(), last_error: null, consecutive_failures: 0,
		};

		if (!state.history_cursor) {
			// First run (rule 4): anchor the cursor to "now"; no backfill.
			const profile = await getProfile(token);
			patch.history_cursor = profile.historyId;
			await stub.putSidecarState(patch);
			return { processed: 0, deduped: 0, error: null };
		}

		const history = await listNewMessageIds(token, state.history_cursor);
		if (!history.ok) {
			// Rule 5: cursor older than Gmail's history retention. Re-anchor and
			// record the gap — informational, NOT a failure (failures gate backoff).
			const profile = await getProfile(token);
			patch.history_cursor = profile.historyId;
			patch.last_error = "history gap: cursor expired; monitoring reinitialized from current historyId";
			await stub.putSidecarState(patch);
			return { processed: 0, deduped: 0, error: null };
		}

		const capped = history.messageIds.length > MAX_MESSAGES_PER_POLL;
		const messageIds = history.messageIds;

		// ...the per-message loop from below goes here, mutating
		// `processed`, `deduped`, and `labelIds`...

		// Rule 6: advance the cursor only when the batch was complete.
		if (!capped) patch.history_cursor = history.historyId;
		if (labelIds) patch.label_ids = JSON.stringify(labelIds);
		await stub.putSidecarState(patch);
		return { processed, deduped, error: null };
	} catch (e) {
		const message = String((e as Error).message).slice(0, 500);
		await stub.putSidecarState({
			last_poll_at: Date.now(), last_error: message,
			consecutive_failures: state.consecutive_failures + 1,
		}).catch((pe) => console.error("sidecar state write failed:", (pe as Error).message));
		return { processed, deduped, error: message };
	}
}
```

Fill in rules 4–8 exactly as specified in the algorithm block; the tests in Step 1 pin every branch (first-run, gap re-init with `last_error` but zero failures, dedupe, observe vs active, null verdict, cap-no-advance). The per-message loop body:

```ts
		for (const gmailId of messageIds.slice(0, MAX_MESSAGES_PER_POLL)) {
			const bytes = await getRawMessage(token, gmailId);
			const parsed = await new PostalMime().parse(bytes);
			const rfcId = parsed.messageId ? extractMsgId(parsed.messageId) : null;
			if (rfcId && (await stub.findEmailIdByMessageId(rfcId))) { deduped += 1; continue; }
			const normalized: MailboxInbound = {
				kind: "mailbox",
				rawEmail: bytes.buffer as ArrayBuffer,
				parsedEmail: parsed,
				mailboxId,
				providerMessageId: gmailId,
			};
			const result = await receiveEmail(normalized, env, ctx);
			processed += 1;
			if (!result?.verdict) continue;
			const verdict = result.verdict;
			let applied: string[] = [];
			if (cfg.mode === "active") {
				labelIds = await ensureLabels(token, [...SIDECAR_LABEL_NAMES], labelIds);
				applied = await applyVerdictLabels(token, gmailId, verdict.action, cfg.quarantine_behavior, labelIds);
			}
			await stub.appendSidecarAudit({
				ts: new Date().toISOString(), gmail_message_id: gmailId, email_id: result.messageId,
				action: verdict.action, score: verdict.score ?? null,
				labels_applied: JSON.stringify(applied), mode: cfg.mode,
			});
			if (verdict.action === "quarantine" || verdict.action === "block") {
				await stub.createCase({
					title: `Sidecar flagged: ${parsed.subject || "(no subject)"}`,
					notes: `Auto-created by the Workspace sidecar poller. Gmail message ${gmailId}.`,
					emailId: result.messageId,
					score: verdict.score ?? null,
					confidence: (verdict as { confidence?: number | null }).confidence ?? null,
				});
			}
		}
```

**Import-cycle check:** `workspace.ts` imports `receiveEmail` from `../index`, and `../index` does NOT import `workspace.ts` (only `app.ts` will, in Task 8) — no cycle. Verify with `npm run typecheck`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/providers/workspace-poll.test.ts` → PASS (all 10 behaviors).
Run: `npm test` → full suite PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/providers/workspace.ts tests/providers/workspace-poll.test.ts
git commit -m "feat(sidecar): pollWorkspaceMailbox — cursor poll, dedupe, verdict labeling, audit, auto-cases (#31)"
```

---

### Task 8: Cron fan-out, retention reap, minutely trigger

**Files:**
- Modify: `workers/providers/workspace.ts` (append `pollSidecarMailboxes` + `reapSidecarBodies`)
- Modify: `workers/app.ts` (`scheduled()`, lines 187-227)
- Modify: `wrangler.jsonc` (`triggers.crons`)
- Test: `tests/providers/sidecar-cron.test.ts`

**Interfaces:**
- Consumes: `listMailboxes(bucket)` (`workers/lib/email-helpers.ts:38`, returns `{ id, email }[]`); `getMailboxSettings`/`resolveMailboxSettings(...).raw`; `sidecarConfigOf` (Task 1); `pollWorkspaceMailbox` (Task 7); DO reap methods (Task 2); `attachmentObjectKey` (`workers/lib/` — same helper `receiveEmail` uses at `workers/index.ts:1516`).
- Produces:
  ```ts
  export async function pollSidecarMailboxes(env: Env, ctx: ExecutionContext): Promise<{ polled: number; processed: number; failures: number }>;
  export async function reapSidecarBodies(env: Env): Promise<{ mailboxes: number; reaped: number }>;
  ```

- [ ] **Step 1: Write the failing test**

```ts
// tests/providers/sidecar-cron.test.ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it, vi, afterEach } from "vitest";

vi.mock("../../workers/index", () => ({ receiveEmail: vi.fn() }));

import { pollSidecarMailboxes, reapSidecarBodies } from "../../workers/providers/workspace";

afterEach(() => vi.clearAllMocks());

/**
 * env.BUCKET fake: mailboxes/<id>.json blobs; list() returns their keys.
 * Two mailboxes: one sidecar-enabled, one plain.
 */
function makeBucketEnv(stubs: Record<string, unknown>) {
	const blobs: Record<string, unknown> = {
		"mailboxes/side@t.example.json": { sidecar: { provider: "workspace", credentials_secret_name: "SIDECAR_SECRET_t", retention_days: 7 } },
		"mailboxes/plain@t.example.json": {},
		"org/settings.json": {},
	};
	return {
		BUCKET: {
			list: vi.fn(async ({ prefix }: { prefix: string }) => ({
				objects: Object.keys(blobs).filter((k) => k.startsWith(prefix)).map((key) => ({ key })),
			})),
			get: vi.fn(async (key: string) =>
				blobs[key] ? { json: async () => blobs[key], text: async () => JSON.stringify(blobs[key]) } : null),
			head: vi.fn(async (key: string) => (blobs[key] ? {} : null)),
			delete: vi.fn(async () => undefined),
		},
		MAILBOX: {
			idFromName: vi.fn((n: string) => n),
			get: vi.fn((n: string) => stubs[n]),
		},
		SIDECAR_SECRET_t: JSON.stringify({ client_email: "svc@p.iam", private_key: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----" }),
	} as never;
}

const ctx = { waitUntil: vi.fn() } as never;

describe("pollSidecarMailboxes", () => {
	it("polls only sidecar-configured mailboxes; a per-mailbox failure doesn't stop the loop", async () => {
		// Backoff-armed state so the poll returns without touching Gmail —
		// this test pins mailbox SELECTION, not poll mechanics (Task 7 covers those).
		const sideStub = {
			getSidecarState: vi.fn().mockResolvedValue({
				history_cursor: "1", access_token: "t", token_expires_at: Date.now() + 3600_000,
				label_ids: null, last_poll_at: Date.now(), last_error: null, consecutive_failures: 99,
			}),
			putSidecarState: vi.fn(),
		};
		const plainStub = { getSidecarState: vi.fn() };
		const env = makeBucketEnv({ "side@t.example": sideStub, "plain@t.example": plainStub });
		const r = await pollSidecarMailboxes(env, ctx);
		expect(r.polled).toBe(1);
		expect(sideStub.getSidecarState).toHaveBeenCalled();
		expect(plainStub.getSidecarState).not.toHaveBeenCalled();
	});
});

describe("reapSidecarBodies", () => {
	it("reaps old bodies for sidecar mailboxes, deletes R2 attachment objects, skips retention_days=0", async () => {
		const sideStub = {
			listReapableSidecarEmails: vi.fn().mockResolvedValue([
				{ id: "e1", attachments: [{ id: "a1", filename: "x.pdf" }] },
			]),
			markBodiesReaped: vi.fn().mockResolvedValue(1),
		};
		const env = makeBucketEnv({ "side@t.example": sideStub });
		const r = await reapSidecarBodies(env);
		expect(r).toEqual({ mailboxes: 1, reaped: 1 });
		// cutoff passed to the DO is ~7 days ago (the mailbox's retention_days)
		const cutoffIso = sideStub.listReapableSidecarEmails.mock.calls[0][0] as string;
		const ageDays = (Date.now() - Date.parse(cutoffIso)) / 86_400_000;
		expect(ageDays).toBeGreaterThan(6.9);
		expect(ageDays).toBeLessThan(7.1);
		// R2 attachment object deleted with the canonical key
		expect((env as never as { BUCKET: { delete: ReturnType<typeof vi.fn> } }).BUCKET.delete).toHaveBeenCalledTimes(1);
		expect(sideStub.markBodiesReaped).toHaveBeenCalledWith(["e1"], expect.any(String));
	});
});
```

(If the real `getMailboxSettings` read path uses a different `BUCKET.get` return shape than this fake, open `workers/lib/mailbox-settings.ts`, check how it reads the blob — `.json()` vs `.text()` — and align the fake. The fake provides both.)

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/providers/sidecar-cron.test.ts`
Expected: FAIL — functions not exported.

- [ ] **Step 3: Implement (append to `workers/providers/workspace.ts`)**

```ts
import { listMailboxes } from "../lib/email-helpers";
import { attachmentObjectKey } from "../lib/attachments"; // exact module: grep "export function attachmentObjectKey" workers/lib/

/**
 * Minutely cron entry: poll every sidecar-configured mailbox sequentially.
 * Sequential (not Promise.all) keeps the subrequest burst bounded; per-
 * mailbox failures are contained by pollWorkspaceMailbox and never abort
 * the loop.
 */
export async function pollSidecarMailboxes(
	env: Env, ctx: ExecutionContext,
): Promise<{ polled: number; processed: number; failures: number }> {
	const mailboxes = await listMailboxes(env.BUCKET);
	let polled = 0, processed = 0, failures = 0;
	for (const m of mailboxes) {
		const raw = await getMailboxSettings(env, m.id).catch(() => null);
		const cfg = sidecarConfigOf(raw);
		if (!cfg) continue;
		polled += 1;
		const r = await pollWorkspaceMailbox(env, ctx, m.id, cfg);
		processed += r.processed;
		if (r.error) failures += 1;
	}
	return { polled, processed, failures };
}

/**
 * Hourly cron entry: strip message bodies (and R2 attachments) from sidecar
 * mailboxes past their retention window. Verdicts, headers, audit rows, and
 * case links survive — see the design spec's Storage & retention section.
 */
export async function reapSidecarBodies(env: Env): Promise<{ mailboxes: number; reaped: number }> {
	const mailboxes = await listMailboxes(env.BUCKET);
	let touched = 0, reaped = 0;
	for (const m of mailboxes) {
		const raw = await getMailboxSettings(env, m.id).catch(() => null);
		const cfg = sidecarConfigOf(raw);
		if (!cfg || cfg.retention_days === 0) continue;
		touched += 1;
		const cutoffIso = new Date(Date.now() - cfg.retention_days * 86_400_000).toISOString();
		const stub = env.MAILBOX.get(env.MAILBOX.idFromName(m.id)) as unknown as {
			listReapableSidecarEmails(cutoff: string): Promise<Array<{ id: string; attachments: Array<{ id: string; filename: string }> }>>;
			markBodiesReaped(ids: string[], ts: string): Promise<number>;
		};
		const rows = await stub.listReapableSidecarEmails(cutoffIso);
		if (rows.length === 0) continue;
		// Delete R2 attachment objects BEFORE marking, so a partial failure
		// re-lists the email next hour instead of orphaning blobs.
		for (const row of rows) {
			for (const att of row.attachments) {
				await env.BUCKET.delete(attachmentObjectKey(row.id, att.id, att.filename));
			}
		}
		reaped += await stub.markBodiesReaped(rows.map((r) => r.id), new Date().toISOString());
	}
	return { mailboxes: touched, reaped };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/providers/sidecar-cron.test.ts` → PASS.

- [ ] **Step 5: Wire the cron branch in `workers/app.ts`**

Replace the `scheduled` member (lines 187-227) — the existing three jobs move under the hourly branch; note the parameter rename `_event` → `event`:

```ts
	async scheduled(
		event: ScheduledController,
		env: Env,
		ctx: ExecutionContext,
	) {
		// Minutely tick (issue #31): sidecar mailbox polling ONLY. Everything
		// else stays on the hourly tick. An unknown cron string falls through
		// to the hourly branch so `wrangler dev --test-scheduled` and future
		// triggers keep today's behavior.
		if (event.cron === "* * * * *") {
			ctx.waitUntil(
				pollSidecarMailboxes(env, ctx).then(
					(r) => {
						if (r.polled > 0) console.log(`sidecar: polled ${r.polled} mailboxes, ${r.processed} messages, ${r.failures} failures`);
					},
					(e) => console.error("sidecar poll failed:", (e as Error).message),
				),
			);
			return;
		}

		ctx.waitUntil(
			refreshAllFeeds(env).then(
				(r) => console.log(`intel: refreshed ${r.feeds} feeds, ${r.entries} entries`),
				(e) => console.error("intel feed refresh failed:", (e as Error).message),
			),
		);
		// ... (WebAuthn reap and honeypot reap blocks stay exactly as they are) ...

		// Strip sidecar message bodies past their retention window (issue #31).
		// Separate waitUntil so a reap failure never breaks the other cron jobs.
		ctx.waitUntil(
			reapSidecarBodies(env).then(
				(r) => {
					if (r.reaped > 0) console.log(`sidecar: reaped ${r.reaped} bodies across ${r.mailboxes} mailboxes`);
				},
				(e) => console.error("sidecar body reap failed:", (e as Error).message),
			),
		);
	},
```

Add the import at the top of `app.ts`:

```ts
import { pollSidecarMailboxes, reapSidecarBodies } from "./providers/workspace";
```

- [ ] **Step 6: Add the minutely trigger to `wrangler.jsonc`**

```jsonc
	"triggers": {
		"crons": [
			// Refresh threat-intel feeds hourly. Individual feeds respect their
			// own refreshHours via ETag caching — the cron just wakes the worker.
			"0 * * * *",
			// Sidecar mailbox poll (issue #31). No-ops (one R2 list) when no
			// mailbox has a `sidecar` settings block.
			"* * * * *"
		]
	},
```

- [ ] **Step 7: Full gates and commit**

Run: `npm test` → PASS. Run: `npm run typecheck` → clean.

```bash
git add workers/providers/workspace.ts workers/app.ts wrangler.jsonc tests/providers/sidecar-cron.test.ts
git commit -m "feat(sidecar): minutely poll cron, hourly retention reap, cron branching (#31)"
```

---

### Task 9: Test-connection endpoint, health surfacing, list annotation

**Files:**
- Create: `workers/routes/sidecar.ts`
- Modify: `workers/index.ts` (mount route ~line 160; annotate list endpoint ~lines 269-314; add `sidecar_health` to the single-mailbox GET — locate with `grep -n 'app.get("/api/v1/mailboxes/:mailboxId"' workers/index.ts`)
- Test: `tests/routes/sidecar-test-endpoint.test.ts`

**Interfaces:**
- Consumes: `sidecarConfigOf` (Task 1), `parseServiceAccountJson`/`mintAccessToken`/`getProfile`/`GmailApiError` (Tasks 3-4), `getSidecarState` (Task 2).
- Produces:
  - `POST /api/v1/mailboxes/:mailboxId/sidecar/test` → `200 { ok: true, emailAddress, historyId }` or `200 { ok: false, stage: "config" | "secret" | "auth" | "api", error }` (200 even on failure — the UI renders the stage; only infra errors 5xx).
  - Mailbox list items gain `sidecar: boolean`.
  - Single-mailbox GET gains `sidecar_health: { healthy: boolean; last_poll_at: number | null; last_error: string | null } | null` (null when not a sidecar mailbox). `healthy` = `consecutive_failures < 3` AND (`last_poll_at` is null — never polled yet — or newer than 15 minutes).

- [ ] **Step 1: Write the failing test**

Before writing it, read the top 60 lines of `workers/routes/cases.ts` and one of its tests (`ls tests/routes/`) to copy the sub-app scaffolding (Hono generics, how `mailboxId` is read from `c.req.param`, how tests build the app + env). Then:

```ts
// tests/routes/sidecar-test-endpoint.test.ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
// Scaffold the Hono test app the same way the cases route tests do.

import { afterEach, describe, expect, it, vi } from "vitest";
import { sidecarRoutes } from "../../workers/routes/sidecar";

// ...app/env scaffolding copied from an existing routes test...

describe("POST /sidecar/test", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("returns ok:false stage:config when the mailbox has no sidecar block", async () => {
		// settings blob = {}
		const res = await request("POST", "/test", { mailboxId: "plain@t.example" });
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ ok: false, stage: "config" });
	});

	it("returns ok:false stage:secret when the named secret is unset", async () => {
		// settings blob has sidecar block; env lacks SIDECAR_SECRET_t
		const res = await request("POST", "/test", { mailboxId: "side@t.example" });
		expect(await res.json()).toMatchObject({ ok: false, stage: "secret" });
	});

	it("returns ok:false stage:auth when the token exchange is rejected", async () => {
		vi.stubGlobal("fetch", vi.fn(async (url: string | URL) => {
			const u = new URL(String(url));
			if (u.hostname === "oauth2.googleapis.com") return new Response("denied", { status: 401 });
			throw new Error(`unexpected ${u.hostname}`);
		}));
		const res = await request("POST", "/test", { mailboxId: "side@t.example", withSecret: true });
		expect(await res.json()).toMatchObject({ ok: false, stage: "auth" });
	});

	it("returns ok:true with profile fields when auth and getProfile succeed", async () => {
		vi.stubGlobal("fetch", vi.fn(async (url: string | URL) => {
			const u = new URL(String(url));
			if (u.hostname === "oauth2.googleapis.com") return new Response(JSON.stringify({ access_token: "t", expires_in: 3600 }), { status: 200 });
			if (u.hostname === "gmail.googleapis.com") return new Response(JSON.stringify({ emailAddress: "side@t.example", historyId: "42" }), { status: 200 });
			throw new Error(`unexpected ${u.hostname}`);
		}));
		const res = await request("POST", "/test", { mailboxId: "side@t.example", withSecret: true });
		expect(await res.json()).toEqual({ ok: true, emailAddress: "side@t.example", historyId: "42" });
	});
});
```

(The `stage:auth` test needs a real-ish private key for signing to reach the fetch — reuse the `makeTestServiceAccount()` helper from `tests/providers/gmail-client.test.ts`; export it from a small shared test helper `tests/providers/helpers.ts` rather than duplicating.)

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/routes/sidecar-test-endpoint.test.ts` → FAIL (module not found).

- [ ] **Step 3: Implement `workers/routes/sidecar.ts`**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sidecar operator endpoints (issue #31). Mounted under
 * /api/v1/mailboxes/:mailboxId/sidecar — behind the same CF Access + ACL
 * middleware as every other mailbox-scoped route (mount order in
 * workers/index.ts is the guarantee; keep this mount adjacent to `cases`).
 *
 * POST /test — resolve the sidecar config, mint a DWD token, call
 * users.getProfile, and report exactly which stage failed. Never persists
 * anything; safe to call repeatedly from the settings UI.
 */

import { Hono } from "hono";
import type { Env } from "../types";
import { sidecarConfigOf } from "../lib/sidecar-config";
import { getMailboxSettings } from "../lib/mailbox-settings";
import { GmailApiError, getProfile, mintAccessToken, parseServiceAccountJson } from "../providers/gmail-client";

// Match the Hono generics/Variables used by workers/routes/cases.ts.
export const sidecarRoutes = new Hono<{ Bindings: Env }>();

sidecarRoutes.post("/test", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const raw = await getMailboxSettings(c.env, mailboxId).catch(() => null);
	const cfg = sidecarConfigOf(raw);
	if (!cfg) return c.json({ ok: false, stage: "config", error: "mailbox has no valid sidecar configuration" });

	const secret = (c.env as unknown as Record<string, unknown>)[cfg.credentials_secret_name];
	const sa = parseServiceAccountJson(secret);
	if (!sa) return c.json({ ok: false, stage: "secret", error: `worker secret ${cfg.credentials_secret_name} is unset or is not service-account JSON` });

	let token: string;
	try {
		token = (await mintAccessToken(sa, mailboxId)).token;
	} catch (e) {
		const detail = e instanceof GmailApiError ? `token exchange failed (HTTP ${e.status}) — check the DWD grant and scopes` : (e as Error).message;
		return c.json({ ok: false, stage: "auth", error: detail });
	}

	try {
		const profile = await getProfile(token);
		return c.json({ ok: true, emailAddress: profile.emailAddress, historyId: profile.historyId });
	} catch (e) {
		const detail = e instanceof GmailApiError ? `Gmail API error (HTTP ${e.status})` : (e as Error).message;
		return c.json({ ok: false, stage: "api", error: detail });
	}
});
```

Mount it in `workers/index.ts` next to the cases mount (line ~160):

```ts
app.route("/api/v1/mailboxes/:mailboxId/sidecar", sidecarRoutes);
```

- [ ] **Step 4: Annotate the mailbox list + single-mailbox GET**

1. **List** (`workers/index.ts:269-314`): the endpoint already resolves settings per mailbox for the honeypot filter. Widen that read to capture both flags in one pass — replace the `honeypotFlags` block with:

```ts
	const flags = await Promise.all(
		rawMailboxes.map(async (m) => {
			try {
				const raw = (await resolveMailboxSettings(c.env, m.id)).raw;
				return { honeypot: !!raw?.honeypot?.enabled, sidecar: !!sidecarConfigOf(raw) };
			} catch {
				return { honeypot: false, sidecar: false };
			}
		}),
	);
	// Sidecar mailboxes also carry poll health so the list can render a
	// warning badge (spec: "renewal/poll failure raises a Settings warning
	// within one cycle"). One extra DO call per SIDECAR mailbox only.
	const healths = await Promise.all(
		rawMailboxes.map(async (m, i) => {
			if (!flags[i].sidecar) return null;
			try {
				const stub = c.env.MAILBOX.get(c.env.MAILBOX.idFromName(m.id));
				const state = await (stub as unknown as { getSidecarState(): Promise<{ consecutive_failures: number; last_poll_at: number | null; last_error: string | null } | null> }).getSidecarState();
				const stale = state?.last_poll_at != null && Date.now() - state.last_poll_at > 15 * 60 * 1000;
				return {
					healthy: (state?.consecutive_failures ?? 0) < 3 && !stale,
					last_poll_at: state?.last_poll_at ?? null,
					last_error: state?.last_error ?? null,
				};
			} catch {
				return { healthy: false, last_poll_at: null, last_error: "state unavailable" };
			}
		}),
	);
	const allMailboxes = rawMailboxes
		.map((m, i) => ({ ...m, sidecar: flags[i].sidecar, sidecar_health: healths[i] }))
		.filter((_, i) => !flags[i].honeypot);
```

(Both response branches spread `...m`, so `sidecar` and `sidecar_health` flow through automatically; keep the `acls` indexing aligned with the filtered array as it is today. Extract the health computation into a small shared helper — it is used verbatim in the single-mailbox GET below — e.g. `sidecarHealthOf(state)` exported from `workers/lib/sidecar-config.ts`.)

2. **Single-mailbox GET**: in the handler, after settings are loaded, add:

```ts
	const sidecarCfg = sidecarConfigOf(settings /* the raw mailbox-tier blob in this handler's scope */);
	let sidecar_health: { healthy: boolean; last_poll_at: number | null; last_error: string | null } | null = null;
	if (sidecarCfg) {
		const state = await c.var.mailboxStub.getSidecarState().catch(() => null);
		const stale = state?.last_poll_at != null && Date.now() - state.last_poll_at > 15 * 60 * 1000;
		sidecar_health = {
			healthy: (state?.consecutive_failures ?? 0) < 3 && !stale,
			last_poll_at: state?.last_poll_at ?? null,
			last_error: state?.last_error ?? null,
		};
	}
```

and include `sidecar_health` in the JSON response object. (Read the handler first; use whatever local variable holds the raw mailbox settings blob.)

Add a list-annotation assertion to an existing mailbox-list test if one exists (`grep -rl "api/v1/mailboxes" tests/ | head`); otherwise cover via the typecheck + the frontend task's manual verification.

- [ ] **Step 5: Run gates and commit**

Run: `npx vitest run tests/routes/sidecar-test-endpoint.test.ts` → PASS. Run: `npm test` → PASS. Run: `npm run typecheck` → clean.

```bash
git add workers/routes/sidecar.ts workers/index.ts tests/routes/sidecar-test-endpoint.test.ts tests/providers/helpers.ts
git commit -m "feat(sidecar): test-connection endpoint, sidecar_health, mailbox-list annotation (#31)"
```

---

### Task 10: Frontend — sidecar settings card + mailbox-list handling

**Files:**
- Create: `app/components/SidecarSettingsCard.tsx`
- Modify: `app/routes/settings.tsx` (state init ~lines 160-300, `handleSave` ~lines 307-370, render section)
- Modify: `app/routes/mailboxes.tsx`
- Test: `npm run typecheck` + build + manual verification (this repo's frontend suites live in `tests/frontend/` — add a component test ONLY if an existing card there has one to mirror; do not invent a new harness)

**Interfaces:**
- Consumes: mailbox GET payload (`settings.sidecar`, `sidecar_health` from Task 9), `POST .../sidecar/test`, the `settings.tsx` save flow (`const settings = { ...mailbox.settings, ... }` → `updateMailboxMutation.mutateAsync({ mailboxId, settings })` at ~line 354-368).
- Produces: controlled component `<SidecarSettingsCard value={sidecar} onChange={setSidecar} health={sidecarHealth} onTest={...} />`.

- [ ] **Step 1: Read the integration surface**

Read `app/routes/settings.tsx` in full (943 lines) noting: (a) how a card section is laid out (copy the exact wrapper/heading classes of the Yaramail or Honeypot section), (b) how form state initializes from `mailbox.settings` (~lines 160-300), (c) how `handleSave` assembles the payload (~lines 307-370).

- [ ] **Step 2: Create the card component**

`app/components/SidecarSettingsCard.tsx` — a controlled component with NO fetch of its own except the test button. Shape (adapt classNames to what Step 1 found; the structure and behaviors below are the contract):

```tsx
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { useState } from "react";

export interface SidecarFormValue {
	provider: "workspace";
	credentials_secret_name: string;
	mode: "observe" | "active";
	quarantine_behavior: "label-only" | "label-and-archive";
	retention_days: number;
}

export interface SidecarHealth {
	healthy: boolean;
	last_poll_at: number | null;
	last_error: string | null;
}

export function SidecarSettingsCard(props: {
	/** null = sidecar not configured (card shows an enable toggle) */
	value: SidecarFormValue | null;
	onChange: (v: SidecarFormValue | null) => void;
	health: SidecarHealth | null;
	/** true when the saved settings already contain a sidecar block —
	 *  gates the observe→active toggle (promotion only after first save) */
	savedConfigExists: boolean;
	mailboxId: string;
}) {
	const { value, onChange, health, savedConfigExists, mailboxId } = props;
	const [testResult, setTestResult] = useState<null | { ok: boolean; detail: string }>(null);
	const [testing, setTesting] = useState(false);

	const runTest = async () => {
		setTesting(true);
		setTestResult(null);
		try {
			const res = await fetch(`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/sidecar/test`, { method: "POST" });
			const data = (await res.json()) as { ok: boolean; emailAddress?: string; stage?: string; error?: string };
			setTestResult(data.ok
				? { ok: true, detail: `Connected as ${data.emailAddress}` }
				: { ok: false, detail: `${data.stage}: ${data.error}` });
		} catch (e) {
			setTestResult({ ok: false, detail: (e as Error).message });
		} finally {
			setTesting(false);
		}
	};

	const secretValid = !value || value.credentials_secret_name.startsWith("SIDECAR_SECRET_");

	if (!value) {
		return (
			<section /* copy card wrapper classes from an existing settings.tsx section */>
				<h2>Workspace sidecar</h2>
				<p>Score this mailbox's Google Workspace inbox via the Gmail API — no MX change. See docs/sidecar-credentials.md for the service-account setup.</p>
				<button type="button" onClick={() => onChange({
					provider: "workspace", credentials_secret_name: "SIDECAR_SECRET_",
					mode: "observe", quarantine_behavior: "label-only", retention_days: 7,
				})}>
					Configure sidecar
				</button>
			</section>
		);
	}

	return (
		<section>
			<h2>Workspace sidecar</h2>
			{health && (
				<p role="status">
					{health.healthy ? "● Healthy" : "▲ Attention needed"}
					{health.last_poll_at ? ` — last poll ${new Date(health.last_poll_at).toLocaleString()}` : " — not polled yet"}
					{health.last_error ? ` — ${health.last_error}` : ""}
				</p>
			)}

			<label>
				Service-account secret name
				<input
					value={value.credentials_secret_name}
					onChange={(e) => onChange({ ...value, credentials_secret_name: e.target.value })}
					placeholder="SIDECAR_SECRET_yourorg"
					aria-invalid={!secretValid}
				/>
			</label>
			{!secretValid && <p role="alert">Secret name must start with SIDECAR_SECRET_.</p>}
			<p>The service-account JSON itself lives in a Worker secret (`wrangler secret put <name>`), never in settings.</p>

			<label>
				Mode
				<select
					value={value.mode}
					disabled={!savedConfigExists}
					onChange={(e) => onChange({ ...value, mode: e.target.value as "observe" | "active" })}
				>
					<option value="observe">Observe only (record verdicts, write nothing)</option>
					<option value="active">Active (write PhishPilot labels to the inbox)</option>
				</select>
			</label>
			{!savedConfigExists && <p>New sidecar mailboxes start in observe mode. Save first, review the verdict mix, then promote.</p>}

			<label>
				Quarantine behavior
				<select
					value={value.quarantine_behavior}
					onChange={(e) => onChange({ ...value, quarantine_behavior: e.target.value as "label-only" | "label-and-archive" })}
				>
					<option value="label-only">Label only</option>
					<option value="label-and-archive">Label and archive (remove from Inbox)</option>
				</select>
			</label>

			<label>
				Body retention (days, 0 = keep forever)
				<input
					type="number" min={0}
					value={value.retention_days}
					onChange={(e) => onChange({ ...value, retention_days: Math.max(0, Number(e.target.value) || 0) })}
				/>
			</label>

			<div>
				<button type="button" onClick={runTest} disabled={testing || !secretValid}>
					{testing ? "Testing…" : "Test connection"}
				</button>
				{testResult && <span role={testResult.ok ? "status" : "alert"}>{testResult.detail}</span>}
				<button type="button" onClick={() => onChange(null)}>Remove sidecar config</button>
			</div>
		</section>
	);
}
```

- [ ] **Step 3: Wire into `settings.tsx`**

Following the patterns found in Step 1:
1. State: `const [sidecar, setSidecar] = useState<SidecarFormValue | null>(null);` initialized in the same effect that seeds the other sections: `setSidecar((mailbox.settings as { sidecar?: SidecarFormValue } | undefined)?.sidecar ?? null)` — normalizing absent optional fields to the card's defaults (`mode: "observe"`, `quarantine_behavior: "label-only"`, `retention_days: 7`) when a partial block is present.
2. Save: in `handleSave`'s payload assembly (~line 354), include the block only when configured, and **delete the key** when removed:
```ts
		const settings = {
			...mailbox.settings,
			// ...existing fields...
			...(sidecar ? { sidecar } : {}),
		};
		if (!sidecar) delete (settings as Record<string, unknown>).sidecar;
```
3. Render `<SidecarSettingsCard value={sidecar} onChange={setSidecar} health={mailboxSidecarHealth} savedConfigExists={!!mailbox.settings?.sidecar} mailboxId={mailboxId} />` alongside the other cards, where `mailboxSidecarHealth` comes off the mailbox GET payload (Task 9's `sidecar_health`).

- [ ] **Step 4: Mailbox list handling in `app/routes/mailboxes.tsx`**

Read the file (438 lines). The list API now returns `sidecar: boolean` and `sidecar_health: { healthy, last_poll_at, last_error } | null` per item. Changes:
1. Split the rendered list: plain mailboxes render as today; sidecar mailboxes render in a separate "Sidecar mailboxes" group whose rows link to `/mailboxes/<id>/settings` (or this app's settings path for the mailbox — copy the existing settings link) instead of the inbox view, with a "Sidecar" badge, no unread count, and a warning indicator (`▲` + `last_error` as the title/tooltip) when `sidecar_health && !sidecar_health.healthy`.
2. If a shared nav/sidebar component also lists mailboxes for inbox navigation (`grep -rn "api/v1/mailboxes" app/ --include="*.tsx" -l`), apply the same `!m.sidecar` filter there.

- [ ] **Step 5: Verify**

Run: `npm run typecheck` → clean. Run: `npm test` → PASS (frontend suites included).
Run the dev server (`npm run dev` or the project's launch config) and manually verify: the card renders on a mailbox settings page; configuring a block round-trips a save; the mode select is disabled pre-first-save; the list shows the sidecar group. Screenshot or describe what was verified in the commit body.

- [ ] **Step 6: Commit**

```bash
git add app/components/SidecarSettingsCard.tsx app/routes/settings.tsx app/routes/mailboxes.tsx
git commit -m "feat(sidecar): settings card with connection test, sidecar mailbox list group (#31)"
```

---

### Task 11: Operator docs + CLAUDE.md subsystem row

**Files:**
- Create: `docs/sidecar-credentials.md`
- Modify: `CLAUDE.md` (root — add a `workers/providers/` row to the `workers/` subsystems table)

- [ ] **Step 1: Write `docs/sidecar-credentials.md`**

Full document (this is the complete content — adjust only if earlier tasks changed a name):

```markdown
# Workspace Sidecar: Credentials Setup, Rotation, Revocation

The Workspace sidecar (issue #31) scores an existing Google Workspace
mailbox without an MX change. It authenticates as a **Google service
account with domain-wide delegation (DWD)**, impersonating each monitored
user. This document is the operator runbook.

## One-time setup

### 1. Create the service account (Google Cloud console)

1. Pick or create a GCP project (any project; no Pub/Sub needed for the
   poll-based sidecar).
2. IAM & Admin → Service Accounts → Create. No project roles are required.
3. Enable the **Gmail API** on the project (APIs & Services → Library).
4. Keys → Add key → JSON. Download the key file. Treat it as a domain
   credential: anyone holding it plus the DWD grant below can read the
   delegated mailboxes.

### 2. Grant domain-wide delegation (Workspace Admin console)

1. Admin console → Security → Access and data control → API controls →
   Domain-wide delegation → Add new.
2. Client ID: the service account's **Unique ID** (numeric).
3. OAuth scopes:
   - `https://www.googleapis.com/auth/gmail.modify` — required for active
     mode (read + label writes). Observe-only-forever tenants may grant
     `https://www.googleapis.com/auth/gmail.readonly` instead, but
     promotion to active labeling will 403 until the grant is widened to
     gmail.modify (edit the grant, then re-run Test connection).

### 3. Store the key as a Worker secret

The JSON key is NEVER stored in PhishSOC settings or R2 — settings hold
only the secret *name*, which must start with `SIDECAR_SECRET_`:

    wrangler secret put SIDECAR_SECRET_yourorg
    # paste the full JSON key file content as the value

One secret can serve many monitored mailboxes in the same tenant.

### 4. Configure the mailbox

1. Create (or open) the PhishSOC mailbox whose id **is** the monitored
   address (e.g. `user@yourdomain.com`).
2. Settings → Workspace sidecar → Configure: enter the secret name, leave
   mode on **observe**, save.
3. Click **Test connection** — it reports exactly which stage fails
   (config / secret / auth / api) if something is wrong.
4. Within a minute the poller initializes its cursor; new inbound mail
   appears with verdicts (flagged mail auto-creates Cases). After
   reviewing the verdict mix, promote the mailbox to **active** to start
   labeling.

## Rotation

1. Create a new JSON key on the same service account.
2. `wrangler secret put SIDECAR_SECRET_yourorg` with the new key.
3. Delete the old key in the GCP console. No settings change needed; the
   next poll mints tokens with the new key.

## Revocation / teardown

- **Immediate:** delete the DWD grant in the Admin console (kills all
  impersonation), then delete the service-account key.
- **Per mailbox:** remove the sidecar block in mailbox settings — the
  poller skips the mailbox on its next tick.
- Recorded verdicts, audit rows, and Cases are retained; message bodies
  follow the mailbox's retention setting.

## Troubleshooting

| Symptom | Meaning |
| --- | --- |
| Test connection: stage `secret` | Secret unset, or value isn't the service-account JSON |
| Test connection: stage `auth` (401) | DWD grant missing/wrong client ID, or scope not granted |
| Label writes fail with 403, reads fine | Grant is `gmail.readonly`; widen to `gmail.modify` |
| Settings warning: "history gap" | Poll cursor expired (Gmail retains history ~1 week); monitoring reinitialized from now — mail during the gap was not scored |
| Health: unhealthy, `consecutive_failures` ≥ 5 | Poller backed off to 15-minute retries; fix the recorded `last_error`, next success resets it |
```

- [ ] **Step 2: Add the CLAUDE.md subsystem row**

In root `CLAUDE.md`, `### workers/ subsystems` table, add after the `workers/routes/` row:

```markdown
| `workers/providers/` | Pluggable mail ingress/egress adapters (#30): CF Email Routing + Resend defaults, Google Workspace API-sidecar poller (#31) |
```

- [ ] **Step 3: Commit**

```bash
git add docs/sidecar-credentials.md CLAUDE.md
git commit -m "docs(sidecar): operator credential runbook + providers subsystem map row (#31)"
```

---

### Task 12: Final verification against the spec + branch finish

**Files:** none created — verification only.

- [ ] **Step 1: Run every gate**

Run: `npm test` — record the exact pass/fail counts.
Run: `npm run typecheck` — clean.
Run: `npm run build` if a build script exists (`grep '"build"' package.json`) — clean.

- [ ] **Step 2: Spec-coverage checklist**

Open `docs/superpowers/specs/2026-07-06-sidecar-workspace-design.md` and verify each item maps to shipped code; list any gap explicitly rather than hand-waving:

| Spec requirement | Where it landed |
| --- | --- |
| Settings schema, mailbox-tier only, stripDefaultEqual-safe | Task 1 |
| `SIDECAR_SECRET_` prefix + secret-name indirection | Tasks 1, 6, 9 |
| DO state/audit/reap tables + methods | Task 2 |
| DWD JWT auth + token cache | Tasks 3, 7 |
| history.list poll, first-run from-now, gap re-init, dedupe, cap | Task 7 |
| Verdict→3-label mapping, quarantine archive option, observe writes nothing | Tasks 6, 7 |
| Audit row for every decision incl. observe | Task 7 |
| Auto-case for quarantine/block | Task 7 |
| Auto-draft skipped for sidecar mailboxes | Task 5 |
| Minutely cron branch + hourly retention reap + wrangler trigger | Task 8 |
| Health surfacing (≥3 failures or >15 min stale) + backoff | Tasks 7, 9 |
| Test-connection endpoint with stage-precise errors | Task 9 |
| Settings card, observe-first promotion gate, list group/badge, inbox-nav hiding | Task 10 |
| Operator docs (setup/rotation/revocation) | Task 11 |
| No edits to workers/security, workers/intel, workers/agent | `git diff main --stat` shows none |

- [ ] **Step 3: Follow-up issues**

Per the spec's out-of-scope list, offer to file (via the `/issue` skill; do NOT auto-file): M365/Graph provider on this core; Pub/Sub push transport; onboarding wizard with Directory-API picker; SidecarDO scale-out; outbound send-as (#32 territory).

- [ ] **Step 4: Finish the branch**

Use superpowers:finishing-a-development-branch. Open a PR against `main` (never push to main; no auto-merge until every fix is pushed). PR body: what shipped, the spec path, test counts, the deploy note ("adds a minutely cron trigger; no new bindings — safe for Workers Builds prod deploy"), and `Closes #31` **only if** the M365 follow-up issue has been filed to carry the remainder; otherwise say "Partial: Workspace slice of #31" so the issue stays open.

---

## Execution notes

- Tasks 1-4 are independent of each other and of the pipeline; Tasks 5-9 depend on their `Interfaces: Consumes` lists; Task 10 needs 9; Tasks 11-12 close out.
- Every task ends with the full `npm test` + `npm run typecheck` gates green and a commit — never leave a task with a red suite.
- If a referenced line number has drifted, trust the `grep` anchor given next to it, not the number.



