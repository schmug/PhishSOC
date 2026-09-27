# Sender blocklist — design

Date: 2026-09-27. Status: approved in chat, pending spec review.

## Problem

There is no way to block an unwanted sender. Triggering email:
`<1be0e58d-d7f1-5422-7204-4087493824a4@res.podview.com>` to
`clodcast@cortech.online` — PodView cold outreach, SPF/DKIM/DMARC pass,
Jev labeled it `spam` 0.93, final verdict `allow` (score 14), delivered to
Inbox.

Current state (verified 2026-09-27):

- No deny-list exists. Only `allowlist_senders` / `allowlist_domains`
  (`workers/security/triage.ts:200-204`), plus intel/reputation hard-blocks.
- `Folders.SPAM` exists (`shared/folders.ts:19`) and is listed in the
  sidebar, but it is not in `SYSTEM_FOLDER_IDS` and ingest never writes to it.
- Nothing calls `setReject`. Every inbound message is stored first
  (`stub.createEmail`, `workers/index.ts` in `receiveEmail`) and then scored.
- No List-Unsubscribe handling.

## Goal

From any email, the user blocks the sender address or domain. Future mail
matching the rule is handled by one of three actions:

| Action | Effect | Sender sees |
| --- | --- | --- |
| `drop` | Accept at SMTP, store nothing, write one audit row | Delivery success |
| `reject` | `message.setReject(reason)` — permanent SMTP error | Bounce with `reason` |
| `spam` | Store in Spam folder; security pipeline still runs and may escalate to Quarantine | Delivery success |

Default action in the UI: `spam`. Default tier for the button: the mailbox.

## Non-goals (file as follow-up issues)

- One-click unsubscribe (RFC 8058). Fetches a URL from an untrusted header;
  needs its own SSRF design.
- Routing classifier `spam` labels to the Spam folder. The triggering email
  shows the gap (spam 0.93 → allow); it is a verdict-aggregation change,
  separate from user-authored rules.
- Catch-all (`receiveCatchall`) and gateway-passthrough
  (`receiveGatewayPassthrough`) ingest paths.
- Gmail-side effects for sidecar mailboxes (labeling or deleting the Gmail
  copy of a dropped message).
- Envelope MAIL FROM rules, DKIM `d=` rules, locked (non-overridable) org
  rules, time-boxed rules.

## Data model

A new **top-level** settings field `blocklist`, on `MailboxSettings`
(`shared/mailbox-settings.ts:408`), `DomainSettings`
(`shared/domain-settings.ts:118`) and `OrgSettings`
(`shared/org-settings.ts:32`).

It must NOT live under `security`. `security` whole-replaces across tiers
(`workers/lib/mailbox-settings.ts:120-140`), so writing one mailbox block
into `security` would create a mailbox security override that shadows the
org's thresholds, detectors, etc. for that mailbox.

```ts
// shared/blocklist.ts
export const BlockAction = z.enum(["drop", "reject", "spam"]);
export const BlockRule = z.object({
  id: z.string().uuid(),
  match: z.string(),          // "user@example.com" or "example.com"
  action: BlockAction,
  reason: z.string().max(200).optional(), // reject only
  created_at: z.string(),
});
export const Blocklist = z.array(BlockRule).max(1000);
```

Validation on write (shared, used by UI and API):

- `match` lowercased and trimmed. Address form = contains exactly one `@`.
  Domain part converted to its IDNA A-label (`new URL("http://" + d).hostname`).
- Domain rules are refused when the domain is a public suffix (`com`,
  `co.uk`, …). Use a small bundled suffix check; no network.
- Domain rules for known shared domains (freemail + ESP bounce domains:
  `gmail.com`, `outlook.com`, `yahoo.com`, `icloud.com`, `sendgrid.net`,
  `amazonses.com`, `resend.dev`, `mailgun.org`) require
  `confirm_shared_domain: true` in the request; the UI shows a warning.
- `reason` sanitized: strip CR, LF and other control characters, ASCII
  printable only, max 200 chars. Empty → default
  `"Unsolicited commercial email refused by recipient"`.

Every write goes through `stripDefaultEqual(...)` before `BUCKET.put`
(CLAUDE.md convention). An empty `blocklist` array is the default and is
stripped.

## Resolution

`resolveBlocklist(orgRaw, domainRaw, mailboxRaw)` in
`workers/lib/mailbox-settings.ts`, exposed as `resolved.blocklist` from
`resolveMailboxSettings`. Result: every rule from all three tiers, each
tagged with its tier.

Unlike the allowlist carve-out (#149), the domain tier IS included.

## Matching and precedence

`matchBlocklist(rules, allowlist, fromAddress)` in the new
`workers/security/blocklist.ts`; pure, no I/O. It returns `{ rule, tier }`
or `null`.

1. `fromAddress` = `parsedEmail.from?.address`, lowercased, domain part
   converted to its A-label. Missing, empty, or group From → `null` (normal
   processing). No Gmail dot/plus normalization.
2. An address rule matches on exact equality. A domain rule `d` matches
   when the sender domain equals `d` or ends with `"." + d`, the same
   semantics as the allowlist at `workers/security/triage.ts:203-204`.
3. When several rules match: the most specific tier wins
   (mailbox > domain > org). Within a tier, an address rule beats a domain
   rule. Remaining ties go to the strictest action (`reject` > `drop` >
   `spam`).
4. Allowlist interaction: an allowlist entry (sender or domain) suppresses
   the block only when it comes from a strictly more specific tier than the
   winning block rule. Otherwise the block wins. Suppression only restores
   normal pipeline processing; the allowlist's hard-allow still requires
   trusted DMARC pass (unchanged).

   Tier provenance for allowlist entries needs the raw per-tier arrays.
   `extendAllowlistsWithOrg` already reads raw blobs.

## Enforcement point

In `receiveEmail` (`workers/index.ts`), immediately after the
mailbox-exists check and before any attachment `BUCKET.put`:

```ts
const settings = await resolveMailboxSettings(env, mailboxId); // hoisted; reuse below
const hit = safeMatchBlocklist(settings, parsedEmail);          // fail-open
if (hit) { ... }
```

- **Fail open.** A settings or match error logs and continues normal
  processing. A blocklist bug must never lose mail.
- `drop` → write the audit row (best-effort; a failure logs, the drop still
  happens) and return `{ blocked: { action: "drop", ruleId } }`.
- `reject` → CF Email Routing path: write the audit row and return
  `{ blocked: { action: "reject", reason, ruleId } }`. `workers/app.ts`
  `email()` calls `event.setReject(reason)` (add `setReject` to the event
  type). Sidecar path (`normalized.providerMessageId` set): downgrade to
  `drop`.
- `spam` → continue the normal flow, but create the email in `Folders.SPAM`
  instead of `Folders.INBOX`. The security pipeline still runs. The final
  folder is the stricter of Spam and the pipeline's result: quarantine or
  block moves it to Quarantine; allow or tag leaves it in Spam. Record the
  rule id on the email row (`blocked_by_rule` column) so the verdict panel
  can show it.

The `ReceiveEmailResult` type gains an optional `blocked` field. The
sidecar caller (`workers/providers/workspace.ts:345`) treats `blocked`
results as processed with no verdict.

The blocklist check adds one guarded `resolveMailboxSettings` call.
`receiveEmail` already makes ~6 such calls per message (`org-settings` and
`domain-settings` reads are ETag-cached); consolidating them is the
follow-up already noted in the new-email-webhook comment in
`receiveEmail`, not part of this change.

## Audit log (`blocked_log`)

New MailboxDO SQLite table, added as a migration in `workers/db/`:

```
blocked_log(id INTEGER PK, ts TEXT, rule_id TEXT, tier TEXT, action TEXT,
            sender TEXT, subject TEXT, message_id TEXT UNIQUE)
```

- `subject` truncated to 120 chars.
- `INSERT OR IGNORE` on `message_id`, so a sidecar at-least-once replay
  (dropped mail is never stored, so the stored-email dedupe probe misses
  it) does not duplicate rows. A null `message_id` always inserts.
- Retention: prune on insert to the newest 500 rows and rows under 30 days
  old. Flooding the log only evicts audit rows, never mail.
- Only `drop` and `reject` write rows. `spam` mail is stored and needs no
  row.

## API

All routes are mailbox-scoped and pass the existing mailbox ACL middleware.

- `POST /api/v1/mailboxes/:mailboxId/blocklist` with body
  `{ match, action, reason?, confirm_shared_domain?, move_existing? }`.
  - Validates the rule and appends it to the mailbox tier.
  - `stripDefaultEqual`, then `BUCKET.put`.
  - With `move_existing` (default true in the UI), moves the mailbox's
    existing emails from matching senders out of Inbox/Archive into Spam.
  - Returns the rule plus a moved count.
- `DELETE /api/v1/mailboxes/:mailboxId/blocklist/:ruleId` removes a
  mailbox-tier rule.
- `GET /api/v1/mailboxes/:mailboxId/blocked-log?limit=` returns audit rows.
- `POST /api/v1/org/blocklist`, `DELETE /api/v1/org/blocklist/:ruleId`,
  `POST /api/v1/domains/:domain/blocklist`,
  `DELETE /api/v1/domains/:domain/blocklist/:ruleId` — same body and
  validation, for the org and domain tiers. The domain routes apply the same
  owned-domain gate as the domain settings PUT.
- `blocklist` is owned by these endpoints alone. The existing mailbox PUT,
  domain PUT and org PUT (`mergeOrgSettingsPut`) all preserve the persisted
  `blocklist` and ignore any `blocklist` in the request body, the same way
  `honeypot` and org `domains` are preserved today. Without this, saving an
  unrelated settings form would wipe the blocklist.

## UI

- `EmailPanelToolbar.tsx`: a **Block sender** button that opens a dialog.
  - Radios: the full address (default), or a domain. The domain choice
    offers the registrable domain and the exact subdomain.
  - Action: Spam (default), Drop silently, or Bounce with message
    (textarea, 200-char limit, prefilled with the default reason).
    Sidecar mailboxes show "Bounce not available for Google Workspace
    mailboxes — will drop".
  - Checkbox: "Also move existing mail from this sender to Spam" (on).
  - Warning banner when the email's verdict auth is not trusted
    DMARC-pass: "This message's sender is not authenticated — the From
    address may be forged. Blocking it may block the real sender."
  - Shared-domain warning plus confirm for the list above.
- Spam is already listed in the sidebar (every DO folder row is), but it
  sorts among custom folders. Add `Folders.SPAM` to `SYSTEM_FOLDER_IDS`
  before `QUARANTINE` so it sorts with the system folders. This also adds a
  Spam row to the per-folder policy list in `SecuritySettingsPanel`.
- `SecuritySettingsPanel.tsx`: a **Blocked senders** section listing
  rules per tier (tier badge, match, action, created date, remove button
  at the editable tier) and the last 50 `blocked_log` rows.
- `SecurityVerdictPanel.tsx`: a "Blocked by rule: <match> (<tier>)" line
  when `blocked_by_rule` is set.

## Testing

Test files follow the existing `test/` and `tests/` layout.

- `matchBlocklist` unit tests:
  - exact address; domain; subdomain; parent domain does not match a
    subdomain rule; case-insensitivity; IDN A-label equivalence.
  - missing or group From returns `null`.
  - tier precedence; address beats domain within a tier; action tie-break.
  - an allowlist entry at a more specific tier suppresses the block; one at
    the same or a less specific tier does not.
- Rule validation: public-suffix refusal, shared-domain confirm required,
  reason sanitization (CR/LF stripped, length cap).
- `receiveEmail`:
  - `drop` → no email row, no R2 attachment writes, one audit row.
  - `reject` → returns the reason, one audit row.
  - sidecar `reject` downgrades to `drop`.
  - `spam` → row in Spam; a pipeline quarantine verdict moves it to
    Quarantine.
  - a settings read error fails open to Inbox.
  - duplicate `message_id` produces one audit row.
- `app.ts` `email()` calls `setReject` exactly once on a `reject` result.
- The POST blocklist route runs `stripDefaultEqual`, and `move_existing`
  moves matching mail.
- Browser check on the deployed app: block `podview.com` from the
  triggering email with action `spam`; the email moves to the now-visible
  Spam folder and the rule appears in settings.

## Second-opinion record (2026-09-27)

Trigger: security-boundary (new default-deny rule at ingress). Consulted
Grok (`cursor-grok-4.6-xhigh`) and Astra (`gpt-daybreak-blue-latest`,
effort high).

| Objection | Disposition |
| --- | --- |
| Spam skipping the pipeline leaves a compromised-newsletter phish unscored | Avoided: the pipeline runs; Spam is a floor |
| Blocking a spoofed email trains a rule against the victim brand | Avoided: unauthenticated-sender warning in the dialog |
| Global "block beats allow" stomps a deliberate allow | Avoided: most-specific-tier precedence; allow must be strictly more specific |
| Broad domain rules (freemail, ESP, public suffix) cause silent collateral loss | Avoided: public suffixes refused, shared domains need confirm |
| User reject text sent to arbitrary MTAs (CRLF, leakage) | Avoided: sanitized, ASCII, 200-char cap, no rule details |
| Union-only schema can't express removal or conflicts | Avoided: rule ids, tier-tagged resolution, deterministic tie-break |
| Settings/audit outage behavior undefined | Avoided: fail open on match; best-effort audit |
| Sidecar replay duplicates dropped-mail audit rows | Avoided: `message_id UNIQUE` + `INSERT OR IGNORE` |
| Per-message settings read cost | Disproved: `receiveEmail` already reads settings up to 3× per message; hoisting makes it 1 |
| Silent drop is irrecoverable | Avoided: user-requested behavior; audit row plus removable rule; `spam` is the UI default |
| Subdomain matching blast radius (Astra prefers exact + explicit wildcard) | Resolved by repo evidence: the allowlist already uses domain+subdomain matching (`triage.ts:203-204`); consistency wins, and the dialog defaults to the address, with the domain as an explicit choice |
| Malformed/multiple/IDN From ambiguity | Avoided: A-label normalization; missing/group From → no match |
