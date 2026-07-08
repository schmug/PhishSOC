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
| Label writes fail with 403, reads fine | Grant is `gmail.readonly`; widen to `gmail.modify`. The failure is recorded durably (`sidecar_health.label_error`, backed by `sidecar_state.label_error` / `label_failure_count`) and keeps health unhealthy until a label write succeeds — a quiet poll cannot flap it back to green. Ingest is unaffected: audit rows and Cases still land. Once the grant is widened, messages that missed their label are labeled retroactively when the poller re-encounters them (dedupe-path backfill; the existing audit row is updated in place, never duplicated) |
| Settings warning: "history gap" | Poll cursor expired (Gmail retains history ~1 week); monitoring reinitialized from now — mail during the gap was not scored. The warning text itself clears on the next clean poll, but the gap is recorded durably: an append-only `history-gap` row in the mailbox's `sidecar_events` table (with the old→new cursor jump bounding the unscored window), surfaced as `sidecar_health.last_gap` on the mailbox API until a newer gap supersedes it |
| Health: unhealthy (`consecutive_failures` ≥ 3, last poll > 15 min ago, or `label_error` set) | Fix the recorded `last_error` / `label_error`; the next successful poll resets the counters, and the next successful label write clears `label_error` |
| Failures reach ≥ 5 | Poller backs off to 15-minute retries until a success |
