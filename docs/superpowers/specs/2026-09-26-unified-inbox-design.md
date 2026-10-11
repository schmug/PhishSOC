# Unified Inbox ("All inboxes") — Design

**Date:** 2026-09-26
**Branch:** `claude/unified-inbox-domains-59bd86`
**Status:** Approved in brainstorming; awaiting written-spec review.

## Summary

Add an "All inboxes" view: one conversation list merging the Inbox folder of
every mailbox the caller can see, newest first, with each row tagged by its
mailbox. Opening, starring, moving, deleting, replying and forwarding act on
the row's own mailbox through the existing per-mailbox endpoints. New mail can
be composed from any mailbox via a From picker. Replies and forwards go out
from the mailbox that received the mail.

Target user: one operator running many mailboxes across many domains (>10,
created ad hoc). No multi-user setting or toggle — the view is always
available alongside per-mailbox navigation.

## Decisions made during design (with rationale)

| Decision | Choice | Rationale |
| --- | --- | --- |
| Data strategy | Read-time fan-out to each `MailboxDO`, merge in the Worker | No global email table exists (one SQLite per mailbox). `/api/v1/org/search` already fans out this way (`workers/index.ts:473`). A write-time index would need every read/star/move/delete/quarantine path to dual-write plus a backfill; drift means missing mail in a phishing SOC. |
| Escape hatch | All merge logic behind one endpoint + one pure module | If fan-out latency degrades at the operator's real mailbox count, a write-time index can replace the internals without UI changes. |
| Rejected: client-side merge | — | N browser requests per page and the paging problem moves to the SPA. |
| Scope of view | Inbox folder only | Operator's stated need. Sent/Drafts/Quarantine stay per-mailbox. |
| Grouping | Conversations (threaded), matching the per-mailbox inbox | The per-mailbox inbox list is threaded (`app/queries/emails.ts:24`). Conversations never span mailboxes, so each DO groups its own threads before the merge. |
| Paging | Keyset cursor, Newer/Older buttons, no total count | Offset paging does not compose across N sources; org search caps at 200/mailbox and slices after merge, so deep pages silently truncate. A total count costs a second RPC per mailbox per refresh. |
| Live updates | React Query `refetchInterval: 30_000` + refetch on focus | One WebSocket per mailbox (`app/hooks/useMailboxEvents.ts`) does not scale to >10 mailboxes. Polling pauses while the tab is hidden (React Query default). |
| Per-mailbox opt-out | `hideFromAllInboxes?: boolean` on `MailboxSettings`, mailbox tier only | Operator creates throwaway/noisy mailboxes ad hoc. Absent key = shown, so new mailboxes appear automatically. No domain/org tier until asked for. |
| ACL | Apply the existing per-mailbox ACL filter even for a solo operator | Public repo, other deployments. Cross-mailbox isolation is a high-impact asset in `docs/security/THREAT_MODEL.md` (T3); the new route must not be the one path that skips it. |
| Reply/forward From | Fixed to the receiving mailbox in v1 | The reply/forward handlers load the original from the URL mailbox and send from it (`workers/routes/reply-forward.ts:33,51`). Reply-as-another-mailbox is a cross-mailbox action (read A, send as B) needing ACL checks on both and a change to step-up token binding — follow-up, own design. |
| Failure visibility | Partial results + `failed` list surfaced as a banner | Org search only `console.error`s a failed mailbox. Silently missing mail is worse than a visible "2 mailboxes didn't load". |

## Invariants the design relies on (verified 2026-09-26)

- Every received email id is `crypto.randomUUID()` (`workers/index.ts:1664`);
  drafts and sends also use `crypto.randomUUID()`. Ids are globally unique
  across mailboxes, so `(date DESC, id DESC)` is a strict total order over the
  merged set — no mailbox id needed in the tie-break.
- Received `date` is the receive time as ISO-8601 (`workers/index.ts:1734`,
  `new Date().toISOString()`), so SQL string comparison on `date` is
  order-preserving.
- The same message delivered to two of the operator's mailboxes is two rows
  with different ids. It appears twice in All inboxes, once per mailbox. No
  dedupe in v1.

## Architecture

### Backend

**`workers/lib/unified-inbox.ts`** (new, pure — no `env`, no I/O)
- `selectInboxMailboxes(mailboxes, acls, flags, callerEmail, callerGroups, isDev)`
  → mailboxes that pass `callerInAcl` (same filter as
  `mailboxesForOrgSearch`, `workers/lib/org-search.ts`) AND are not honeypot
  AND not sidecar AND not `hideFromAllInboxes`.
- `encodeCursor({ date, id })` / `decodeCursor(s)` — opaque base64url JSON.
  `decodeCursor` returns `null` on malformed input (endpoint answers 400).
- `mergeInboxPages(perMailbox, limit)` → sort all rows by `(date DESC, id DESC)`,
  take `limit`, return `{ emails, nextCursor }`. `nextCursor` is the last
  returned row's `{date, id}` when the merged set had more than `limit` rows
  in total, else `null`.
  Each row carries `mailbox_id` and `mailbox_email`.

**`MailboxDO.getThreadedEmails`** (`workers/durableObject/index.ts:312`)
- Add optional `before?: { date: string; id: string }` to its options.
- When `before` is set: add
  `AND (lif.date < ?d OR (lif.date = ?d AND lif.id < ?id))` to the final
  `WHERE lif.rn = 1`, and drop `OFFSET`.
- Change the final `ORDER BY lif.date DESC` (line 467) to
  `ORDER BY lif.date DESC, lif.id DESC` unconditionally (deterministic order;
  harmless for existing offset callers).
- Existing callers (no `before`) keep offset behavior unchanged. The draft
  branch (line 334) is untouched — unified view only queries `inbox`.
- Known gap, not fixed here: the threaded SELECT (lines 451–461) does not
  return `security_verdict`, so verdict pills appear not to render in the
  threaded per-mailbox inbox today. Unified rows inherit whatever this query
  returns. Tracked as a follow-up.

**`GET /api/v1/inbox`** — new Hono sub-app `workers/routes/unified-inbox.ts`,
mounted in `workers/index.ts` next to the other `app.route("/api/v1/...")`
lines (~158–173). Not under `/api/v1/mailboxes/:mailboxId`, so
`requireMailbox` (`workers/index.ts:162-163`) does not run — the handler does
its own filtering.
- Query: `before` (optional cursor), `limit` (default 25, clamp 1–50).
- Identity and groups from the verified JWT only:
  `callerEmailFromJwt(c.req.header("cf-access-jwt-assertion"))` and
  `callerGroupsFromJwt(...)`, as in `/api/v1/org/search`. Never the
  `cf-access-authenticated-user-email` header.
- Steps:
  1. `listMailboxes(env.BUCKET)` (`workers/lib/email-helpers.ts:38`).
  2. In parallel: `readMailboxAcl` per mailbox, and
     `resolveMailboxSettings(env, id).raw` per mailbox
     (`workers/lib/mailbox-settings.ts:153`) → `{ honeypot, sidecar, hidden }`
     using `raw?.honeypot?.enabled`, `sidecarConfigOf(raw)`
     (`workers/lib/sidecar-config.ts:29`), `raw?.hideFromAllInboxes`.
     Settings read failure → exclude the mailbox AND add its id to
     `failed`. (The mailbox-list endpoint instead shows it,
     `workers/index.ts:292-301`; here unknown honeypot/hidden state must not
     leak lure mail into the list, and `failed` keeps the gap visible.)
  3. `selectInboxMailboxes(...)`.
  4. `Promise.allSettled` over selected mailboxes:
     `stub.getThreadedEmails({ folder: "inbox", limit: limit + 1, before })`.
     `limit + 1` from each DO lets the merge know whether more rows exist.
  5. `mergeInboxPages(fulfilled, limit)`; rejected → push mailbox id to
     `failed` and `console.error` it.
- Response: `{ emails: UnifiedInboxRow[], nextCursor: string | null, failed: string[] }`.
- Local dev with no JWT: same behavior as org search (`isDev` passes all).
  Production with no JWT email: fail closed (`callerInAcl` handles this).

**`shared/mailbox-settings.ts`** — add `hideFromAllInboxes: z.boolean().optional()`
to `MailboxSettings` (line 394). Mailbox tier only; not added to domain/org
schemas. Written through the existing mailbox PUT
(`workers/index.ts:1233`), which already runs `stripDefaultEqual` — no new
write endpoint. `false` is the default and is stripped on save.

### Frontend

**Route** — `app/routes.ts`: add top-level `route("inbox", "routes/unified-inbox.tsx")`
(not nested under `mailbox/:mailboxId`).

**Entry points**
- `app/components/phishsoc/MailboxSwitcher.tsx`: an "All inboxes" item above
  the mailbox list, navigating to `/inbox`; active when on `/inbox`.
- `app/components/phishsoc/Shell.tsx`: an org-scoped nav entry next to the
  existing always-visible entries (~line 438).

**Data**
- `app/services/api.ts`: `listUnifiedInbox({ before?, limit? })`.
- `app/queries/keys.ts`: `unifiedInbox: { list: (before?: string) => ["unified-inbox", before ?? "head"] }`.
- `app/queries/inbox.ts` (new): `useUnifiedInbox(before)` with
  `refetchInterval: 30_000`.
- Existing email mutations (star, move, delete, mark read, reply, forward,
  send) additionally invalidate `["unified-inbox"]` on success.

**List** — `app/routes/unified-inbox.tsx`
- Move row rendering out of `app/routes/email-list.tsx` (532 lines) into a
  shared `app/components/EmailListRow.tsx` used by both pages. The unified
  row adds a mailbox chip (`mailbox_email`).
- Paging: component-local cursor stack. "Older" pushes `nextCursor`;
  "Newer" pops. Head page = no cursor.
- Banner when `failed.length > 0`: "N mailbox(es) didn't load", listing ids.
- Empty state when zero mailboxes are selected (all hidden) — links to
  `/mailboxes`.

**Selection and reading pane**
- Deep link `?mailbox=<id>&email=<id>`, consumed the same way
  `email-list.tsx:243-254` consumes `?email=`.
- The route keeps `selectedMailboxId` in local state alongside
  `useUIStore.selectedEmailId`.
- `EmailPanel` (`app/components/EmailPanel.tsx:54`) and `ComposePanel`
  (`app/components/ComposePanel.tsx:16`) read `mailboxId` from `useParams`.
  Add an optional `mailboxId` prop to each that overrides the param;
  `MailboxSplitView` threads it through. Per-mailbox pages pass nothing and
  behave as today.
- `useComposeForm(mailboxId, folder)` (`app/hooks/useComposeForm.ts`) already
  takes `mailboxId` as an argument — no change beyond what the panel passes.

**Compose From picker**
- Shown in `ComposePanel` only when opened from `/inbox` in `mode: "new"`.
- Options: the inbox-navigable mailboxes (same `!m.sidecar` filter as
  `Shell.tsx:606`), including ones hidden from All inboxes (hiding a mailbox
  from the list does not stop sending from it).
- Default: the open email's mailbox; else last-used From
  (`localStorage`, try/catch, per-viewer convenience); else none — Send is
  disabled until one is picked.
- Send calls the chosen mailbox's existing send endpoint. `validateSender`
  (`workers/routes/send-email.ts:52`) already binds From to the URL mailbox;
  the Sent copy lands in that mailbox.
- Reply/reply-all/forward: no picker; the panel uses the row's mailbox.

**Settings toggle** — mailbox settings page (`app/routes/settings.tsx`): a
"Hide from All inboxes" switch writing `hideFromAllInboxes`.

## Cost (metered: DO requests)

One `getThreadedEmails` RPC per selected mailbox per page load or refresh.
At 50 mailboxes and a 30s refresh: ~6,000 DO requests per hour while the
`/inbox` tab is visible; zero while hidden. Step 2's `resolveMailboxSettings`
reads the mailbox, domain and org tiers per mailbox per request — the same
cost the existing mailbox-list endpoint already pays.

## Testing

Follows existing layout: Worker tests in `test/`, frontend in `tests/frontend/`.
URL mock dispatchers parse with `new URL(url)` (root CLAUDE.md, CodeQL rule).

1. **`workers/lib/unified-inbox.ts` unit tests**
   - Merge orders by `(date DESC, id DESC)` across mailboxes, including two
     rows with the same `date` in different mailboxes.
   - Paging with `limit` never duplicates or skips a row across consecutive
     pages (walk a fixture of ~3 mailboxes × varying sizes to exhaustion,
     compare to a single global sort).
   - `nextCursor` is `null` exactly when no rows remain.
   - `selectInboxMailboxes` excludes ACL-denied, honeypot, sidecar and
     hidden mailboxes; includes unscoped mailboxes.
   - `decodeCursor` rejects malformed input.
2. **`MailboxDO.getThreadedEmails` with `before`** — seeded DO: rows strictly
   older than the cursor, equal-date tie broken by id, no OFFSET interaction;
   existing no-`before` call unchanged.
3. **`GET /api/v1/inbox` route test** — one mailbox stub rejects → response
   has the other mailboxes' rows and `failed: [thatId]`; a mailbox whose
   settings read throws is excluded and listed in `failed`; malformed
   `before` → 400.
4. **Settings** — `hideFromAllInboxes: false` is stripped on mailbox PUT;
   `true` persists.
5. **Frontend `/inbox`** — renders merged rows with mailbox chips, Older/Newer
   paging, failed banner, empty state; opening a row renders `EmailPanel`
   for that row's mailbox; From picker defaults as specified.
6. **Browser check** on the dev server before calling it done.

## Out of scope / follow-ups (file as issues)

- **Reply or forward from a different mailbox** than the one that received
  the mail (cross-mailbox action; own design).
- **Threaded inbox query omits `security_verdict`** — appears to hide verdict
  pills in the per-mailbox inbox today; fixing it benefits both views.
  Verify in the running app first.
- **Unread count badge** on the "All inboxes" entry.
- **Write-time inbox index** — only if measured fan-out latency at the
  operator's real mailbox count is unacceptable.
- **Domain-tier "hide all mailboxes on this domain"** — only if asked for.
