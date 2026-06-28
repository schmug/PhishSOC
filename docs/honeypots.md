# Honeypot Mailboxes (#24)

Honeypots are **ephemeral burner addresses** that turn a PhishSOC deployment into
a passive sensor network. Everything that lands in a honeypot is unsolicited by
construction, so its URL / sender / attachment IOCs are extremely high-signal —
there is no legitimate sender, so no false-positive risk.

## Spinning up honeypots

```bash
# Create 10 honeypots on the first owned domain, each with a 14-day TTL.
curl -sS -X POST "$BASE_URL/api/v1/honeypots" \
  -H 'content-type: application/json' \
  -d '{ "count": 10, "ttl_days": 14 }'
# → { "created": ["hp-…@example.com", …], "domain": "example.com",
#     "expires_at": "…", "count": 10 }
```

Body fields (all optional):

| Field | Default | Notes |
| --- | --- | --- |
| `count` | `1` | Number of honeypots to create (max 50). |
| `ttl_days` | `7` | Days until the hourly cron reaps the honeypot (max 365). |
| `domain` | first owned domain | Must be an **owned** domain (`DOMAINS` env / org `domains`). |
| `max_inbound` | `1000` | Per-honeypot inbound cap before auto-disable. |

Each honeypot is a real `mailboxes/<id>.json` blob (so Email Routing delivers to
it) flagged `honeypot.enabled` with a random, opaque local-part. Honeypots get
**no ACL** and are **never surfaced in the user UI** — `GET /api/v1/mailboxes`
filters them out. They exist purely as IOC sources.

## What happens on inbound mail

For a honeypot, `receiveEmail` stores the message (for the rate-cap count and a
forensic record) and then **stops** — no security pipeline, no deep-scan, and
crucially **no agent / auto-draft**, so a honeypot can never auto-reply and
reveal itself. It then, best-effort:

- **Auto-publishes IOCs to the hub with elevated trust** — the inbound message's
  sender/URLs/domains are posted as a MISP event with `threat_level_id: "1"` and
  a `honeypot` tag (gated on the hub being configured with `auto_report: true`).
  A sender on an owned domain is never published (a misdirected internal message
  is not threat intel).
- **Enforces the inbound rate-cap** — once a honeypot has received more than
  `max_inbound` messages it is auto-disabled (`honeypot.disabled = true`) so an
  attacker who discovers the pattern cannot drive unbounded hub posts.

## Lifecycle / cleanup

The hourly cron (`scheduled()` in `workers/app.ts`) calls `reapExpiredHoneypots`,
which deletes the settings blob and reuses `reapMailbox` to wipe the Durable
Object, its R2 attachment blobs, and any ACL once `expires_at` has passed.

## Seeding (operator policy — not shipped)

Seed honeypot addresses where phishing is likely to find them, e.g. throwaway
signups, scraped contact pages, or leak/scrape corpora. PhishSOC does **not**
perform seeding itself — it is operator policy, and where/how you seed is what
determines what the sensors catch.
