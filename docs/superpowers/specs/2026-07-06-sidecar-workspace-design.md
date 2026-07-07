# API-Sidecar Mode: Core + Google Workspace Provider — Design

**Date:** 2026-07-06
**Issue:** [#31](https://github.com/schmug/PhishSOC/issues/31) (first slice; M365 provider is a follow-up issue)
**Depends on:** #30 (MailProvider interface) — shipped; `workers/providers/{types,registry,cf-routing,resend}.ts` exist on `main`.

## Summary

Add a deployment mode where an operator connects an existing Google Workspace
mailbox via a domain-wide-delegation (DWD) service account, and PhishSOC scores
its inbound mail asynchronously — polling the Gmail API on a minutely cron,
running each new message through the existing security pipeline, and (once the
operator promotes the mailbox from observe-only to active) writing verdicts back
as Gmail labels. No MX change; the tenant's mail flow is untouched beyond
label writes the operator opted into.

## Decisions made during design (with rationale)

| Decision | Choice | Rationale |
| --- | --- | --- |
| Scope slice | Core + Workspace provider; M365 follows | Providers are independent; Workspace is testable against cortech.online; core (mode, storage, lifecycle) is shared |
| Body storage | Persist at ingest + retention reap (default 7 days) | Async stages (`runDeepScan`, yaramail) re-read from DO/R2 by ID; never-persist would require pipeline refactors. Reap honors the issue's "don't accumulate bodies" default |
| Inbound transport | Poll `history.list` on minutely cron; Pub/Sub push is a follow-up | Halves operator setup (no GCP Pub/Sub, no public webhook); the `historyId` cursor doubles as the backfill mechanism push needs anyway; meets the 5-minute acceptance bar |
| Poll ownership | Stateless cron fan-out; cursor state in `MailboxDO` | Matches the three existing cron jobs; no new DO class; poll function is re-homeable behind DO alarms or push later |
| Credentials | Worker secret + name-in-settings (`SIDECAR_SECRET_` prefix) | Proven `HUB_SECRET_` pattern in `workers/lib/hub-config.ts`; replaces the issue's "encrypted refresh tokens in DO" (DWD has no refresh tokens; secrets are encrypted at rest) |
| Onboarding | Settings-page section + docs; no wizard route | Reuses existing settings UI patterns; the credential step is `wrangler secret put`, which no wizard can do for the operator |

## Architecture

New code is confined to `workers/providers/workspace.ts`, the cron handler,
one `MailboxDO` migration, settings schema/UI, and one test endpoint. Per
#30's contract, **no edits to `workers/security/`, `workers/intel/`, or
`workers/agent/`**.

### Components

**`workers/providers/workspace.ts`**
- `WorkspaceProvider implements MailProvider`: `id: "workspace-api"`;
  `send()` throws `unsupported` (v1 is read-only sidecar; outbound stays on
  the Resend default from the registry); `applyVerdict(env, msg, verdict)`
  maps verdict action → Gmail label writes.
- Gmail client helpers: RS256 JWT assertion signed with `crypto.subtle` from
  the service-account key, DWD token exchange (`sub` = monitored user),
  `history.list`, `messages.get(format=raw)`, `labels.list/create`,
  `messages.modify`. Workers-runtime only (no `node:` imports).
- `pollWorkspaceMailbox(env, config, state)` — pure per-mailbox poll step,
  taking config + prior cursor state and returning new state. This signature
  is the seam for later re-homing behind Pub/Sub push or a DO alarm.

**`workers/app.ts` `scheduled()` + `wrangler.jsonc`**
- New cron trigger `* * * * *`; handler branches on `controller.cron` so the
  existing hourly jobs (feed refresh, WebAuthn reap, honeypot reap) are
  untouched.
- Minutely branch: `pollSidecarMailboxes(env, ctx)` enumerates mailboxes
  whose settings contain `sidecar` and runs the poll step for each.
- Hourly branch gains a fourth job: the sidecar retention reap (see Storage).

### Data flow (per poll tick, per sidecar mailbox)

1. Read `sidecar_state` (cursor, cached token, cached label IDs) from the
   mailbox's `MailboxDO`.
2. **First run** (no cursor): `users.getProfile` → store current `historyId`
   → stop. Monitoring starts "from now"; no pre-connection backfill.
3. **Steady state:** `history.list(startHistoryId=cursor,
   historyTypes=messageAdded, labelId=INBOX)` → new message IDs. Filter out
   drafts, sent mail, and chat messages. `messageAdded`-only filtering means
   our own label writes never re-enter the poll (no feedback loop).
4. Per message: `messages.get(format=raw)` → base64url-decode →
   `ArrayBuffer` → PostalMime → `MailboxInbound { kind: "mailbox", rawEmail,
   parsedEmail, mailboxId }` → existing `receiveEmail(normalized, env, ctx)`
   (`workers/index.ts:1490`). Security pipeline, per-tenant detectors, async
   deep-scan, yaramail, and hub intel all run unchanged.
5. `receiveEmail()` gains an additive return value `{ messageId, verdict }`
   (today it returns nothing; existing callers ignore it). The **poller**
   — not the pipeline — then:
   - `mode: "active"` → `provider.applyVerdict()` writes labels;
   - `mode: "observe"` → verdict recorded only.
   An audit row is written either way.
6. Advance the cursor only after the whole batch succeeds. Failures freeze
   the cursor (at-least-once). Idempotency: before ingesting, dedupe on the
   RFC `Message-ID` header against the DO so re-polls don't duplicate emails.

### Verdict → Gmail mapping

Three labels, created once via `labels.create` and cached in
`sidecar_state.label_ids`:

`FinalVerdict.action` is `allow | tag | quarantine | block`
(`workers/security/verdict.ts:234-237`):

| Verdict action | Label | Additional |
| --- | --- | --- |
| `block`, `quarantine` | `PhishPilot/Quarantine` | optionally remove `INBOX` when `quarantine_behavior: "label-and-archive"` (default `"label-only"`) |
| `tag` | `PhishPilot/Suspicious` | — |
| `allow` | `PhishPilot/Allow` | — |

Invariant: three labels, every scored message gets exactly one. A `null`
verdict (security disabled for the mailbox) writes no label and no audit row.

## Settings

`MailboxSettings` (`shared/mailbox-settings.ts`) gains one optional,
mailbox-tier-only field (identity-like, same class as `fromName` /
`forwarding` — deliberately absent from domain/org tiers):

```ts
sidecar?: {
  provider: "workspace";                    // "m365" added by the follow-up
  credentials_secret_name: string;          // must start with SIDECAR_SECRET_
  mode: "observe" | "active";               // default "observe"
  quarantine_behavior?: "label-only" | "label-and-archive"; // default "label-only"
  retention_days?: number;                  // default 7; 0 = keep forever (opt-in archive)
}
```

- Writes flow through the existing mailbox POST/PUT endpoints, so
  `stripDefaultEqual` applies per the repo contract — no new write path.
- A mailbox **is** a sidecar mailbox iff `settings.sidecar` is present. Mode
  is derived; there is no separate `MailboxDO.mode` flag to drift.
- Newly configured sidecar mailboxes can only start in `"observe"`; the UI
  enforces promotion as an explicit separate action.

## Credentials

- The service-account JSON lives in a Worker secret; the settings blob stores
  only the secret **name**, validated against the `SIDECAR_SECRET_` prefix
  (confused-deputy protection, mirroring `HUB_SECRET_` in
  `workers/lib/hub-config.ts:38-58`). Runtime resolution is `env[name]`.
- Rotation = `wrangler secret put SIDECAR_SECRET_<name>`; no blob rewrite.
- OAuth scope requested: `https://www.googleapis.com/auth/gmail.modify`
  (read + labels). Docs note observe-only-forever tenants may grant
  `gmail.readonly` and must re-consent on promotion to active.
- Access tokens (≤1 h lifetime) are cached in `sidecar_state` with expiry and
  refreshed when <5 minutes remain.
- `docs/sidecar-credentials.md` documents: GCP service-account creation, DWD
  authorization in the Workspace admin console (client ID + scopes), secret
  provisioning, rotation, and revocation.

## MailboxDO changes (one migration)

- **`sidecar_state`** (singleton row): `history_cursor TEXT`,
  `access_token TEXT`, `token_expires_at INTEGER`, `label_ids TEXT` (JSON),
  `last_poll_at INTEGER`, `last_error TEXT`,
  `consecutive_failures INTEGER`.
- **`sidecar_audit`**: one row per verdict decision — Gmail message ID, local
  email ID, verdict action + score, labels actually written (empty in
  observe mode), mode at time of decision, timestamp. This is the issue's
  "audit log of every verdict written".
- **`emails.body_reaped_at INTEGER`** marker column.

## Storage & retention

Bodies persist at ingest exactly like local mailboxes (so the unchanged
pipeline works), then an hourly reap job (pattern: `reapExpiredHoneypots`)
processes sidecar mailboxes past `retention_days`:

- Null body columns, set `body_reaped_at`, delete the message's R2
  attachments.
- **Survives forever:** verdict JSON, headers/subject/from metadata, URL
  rows, sender-reputation/graph rows, audit rows, case links. A Case on a
  reaped email still shows the full verdict story with a "body removed per
  retention policy" notice.
- Opt-in local archive = `retention_days: 0` (keep forever).

## Lifecycle, health & error handling

- Poll success resets `consecutive_failures`; failure increments it, records
  `last_error`, and never advances the cursor.
- Mailbox GET/list responses expose
  `sidecar_health: { healthy, last_poll_at, last_error }` — unhealthy when
  `consecutive_failures >= 3` **or** last success older than 15 minutes.
  Settings page + mailboxes list render a warning badge from it. This
  satisfies "renewal/poll failure raises a Settings warning within one
  cycle".
- Auth failures (revoked DWD grant, deleted secret, wrong scopes) are
  distinguished from transient Gmail 5xx in `last_error` so the operator
  knows whether to re-consent or wait.
- Backoff: after 5 consecutive failures, that mailbox polls every 15 minutes
  until a success.
- Auto-draft: `receiveEmail`'s auto-draft dispatch is skipped for sidecar
  mailboxes (replies happen in the tenant's Gmail, not PhishSOC).

## UI

- **Mailbox settings page** (`app/routes/settings.tsx` pattern): a Sidecar
  card — provider picker (Workspace only), secret-name field with prefix
  validation, observe/active toggle (observe-only at creation; promotion is
  explicit), quarantine behavior, retention days, health status.
- **Test connection** button → `POST /api/v1/mailboxes/:id/sidecar/test`:
  mints a token and calls `users.getProfile`, returning success or a precise
  failure (invalid JSON, DWD not granted, wrong scopes).
- **Mailbox list / inbox nav**: sidecar mailboxes are annotated by the API,
  hidden from inbox navigation (verdicts are consumed via Cases and the
  dashboard), and shown in settings with a sidecar badge + health warning.

## Testing (TDD)

Unit suites under `test/providers/` with mocked `fetch` routed by **parsed
hostname** (`new URL(url).hostname === "oauth2.googleapis.com"` /
`"gmail.googleapis.com"` — per the CLAUDE.md CodeQL rule, never substring):

- JWT assertion signing against a fixture service-account key; DWD token
  exchange including `sub` impersonation.
- Poll function: first-run cursor init; batch processing; `Message-ID` dedupe
  on re-poll; cursor freeze on failure; backoff engagement/reset.
- `applyVerdict`: action→label bucketing; label creation happens once;
  archive behavior gated on `quarantine_behavior`; observe mode writes no
  labels but writes audit rows.
- Settings: schema validation, `SIDECAR_SECRET_` prefix enforcement,
  `stripDefaultEqual` round-trip (defaults stripped on write).
- Retention reap: bodies/attachments removed, verdicts/audit/case links
  preserved, non-sidecar mailboxes untouched.
- End-to-end fixture: observe-mode mailbox processes a canned history batch
  into a stored email + verdict + Case; flip to active; assert the
  `messages.modify` call.

## Deployment

No new bindings, resources, or secrets at deploy time — only the added cron
trigger in `wrangler.jsonc`. The minutely branch no-ops when no sidecar
mailboxes exist, so the merge-deploys-prod pipeline (Workers Builds) is safe.

## Acceptance (from #31, adjusted to this slice)

- Workspace operator completes the DWD flow per docs, configures one mailbox
  in the settings UI, passes Test connection, and within 5 minutes sees
  inbound mail to that user appearing as Cases with verdicts.
- Operator can flip the mailbox between observe and active; only active mode
  writes labels; every decision lands in `sidecar_audit`.
- The tenant inbox is modified only by opted-into label/archive writes.
- Poll failure surfaces a settings warning within one cycle (≤15 min).
- Per-tenant detectors (#26) and hub intel (#23) run for sidecar mail
  identically to local mail (they hook `receiveEmail`, which is unchanged).

## Out of scope (follow-up issues to file when this lands)

- **M365 / Microsoft Graph provider** on the same core (subscriptions +
  category/folder writes).
- **Pub/Sub push transport** for Workspace (watch + webhook + OIDC
  validation), layered over the same poll/backfill path.
- **Onboarding wizard** with a Directory-API mailbox picker.
- **SidecarDO scale-out** (per-mailbox alarms) past ~dozens of busy
  mailboxes.
- Outbound send-as via provider APIs — #32 (inline gateway) territory.
- Banner injection / Gmail Add-on; calendar/Drive scanning; cross-tenant
  federation (#29 lineage).
