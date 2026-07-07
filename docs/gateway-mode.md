# Inline Gateway Mode (v1 — inbound only)

Point a domain's MX at Cloudflare Email Routing; PhishSOC scores every
inbound message and relays it to your real mail backend (Google Workspace,
M365, or any SMTP-submission endpoint) with the verdict attached. Mail the
policy quarantines never reaches the backend.

**v1 scope:** inbound only, Cloudflare-only deployment (the issue #32
"Option A"). The external SMTP front-end (Option B), per-domain DKIM
signing, and outbound scanning are tracked in follow-up issues.

## How a message flows

1. Internet MX → Cloudflare Email Routing → the Worker's `email()` handler.
2. The security pipeline scores the message (same pipeline as standalone mode).
3. The verdict maps through the domain's relay policy:
   `allow → relay`, `tag → relay`, `quarantine → hold`, `block → drop` (defaults; all four configurable).
4. Relayed mail gains `X-PhishPilot-Verdict` / `X-PhishPilot-Score` headers
   and an ARC seal, then goes out over SMTP submission to your backend.
5. Held mail stays in the PhishSOC quarantine UI; registered mailboxes keep
   a full mirror copy of everything regardless.

Recipients with no registered PhishSOC mailbox are scored with domain-tier
settings. Both `quarantine` and `block` verdicts are capped at `tag` (there is
no mailbox to quarantine into and no mirror to drop safely), relayed, and NOT
stored.

## Limitations (read first)

- **Workers cannot use port 25.** The relay target must accept SMTP
  *submission*: port 587 (STARTTLS) or 465 (implicit TLS) with credentials.
  For Workspace use `smtp-relay.gmail.com:587`; for M365 use SMTP AUTH
  submission. A bare-MX backend needs the (follow-up) external front-end.
- **ARC sealing only when first in chain.** Messages already carrying ARC
  headers relay unsealed (their origin DKIM signature still validates —
  we only prepend headers, never modify existing ones).
- **Scan/seal failures fail open**: the gateway relays unscanned/unsealed
  and fires a security alert rather than eating mail.
- **Transient relay failures defer at the origin** (the Worker rethrows so
  the sending MTA retries). Permanent failures (bad credentials) keep the
  mirror copy, mark `relay_status=failed`, and alert.

## Setup

### 1. Generate the ARC sealing key (once per deployment)

    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out arc-private.pem
    openssl pkey -in arc-private.pem -pubout -outform DER | openssl base64 -A

Publish the public key as a DNS TXT record (pick a selector, e.g. `arc1`,
and a sealer domain you control, e.g. your PhishSOC host's domain):

    arc1._domainkey.gw.example.com  TXT  "v=DKIM1; k=rsa; p=<base64 from above>"

Store the private key and configure the sealer identity:

    wrangler secret put ARC_SEAL_PRIVATE_KEY < arc-private.pem

Then set **ARC sealer domain** and **ARC selector** on the org settings page.

### 2. Create backend relay credentials

**Google Workspace** (Admin console → Apps → Google Workspace → Gmail →
Routing → SMTP relay service): add a relay setting that accepts
authenticated submission, and create an app password (or use a dedicated
relay user). Also set **Inbound gateway** (Gmail → Spam, phishing, malware)
so Gmail trusts the gateway's Received chain and reads the ARC seal.

Store the credentials as a Worker Secret named per domain:

    wrangler secret put RELAY_CREDS_EXAMPLE_COM
    # paste: {"user":"relay@example.com","pass":"app-password"}

### 3. Configure the domain relay policy

Domain settings page → **Inline gateway relay**: enable, set target host
`smtp-relay.gmail.com`, port `587`, and the credentials secret name from
step 2. The quarantine mapping defaults to `hold` (mail stays in PhishSOC);
switch it to `relay` if you prefer backend-native quarantine routing — the
verdict header still travels with the message.

### 4. Cut over MX

Point the domain's MX records at Cloudflare Email Routing (per the standard
PhishSOC setup). Verify with a test message from an external mailbox:

- it arrives in the Workspace inbox,
- "Show original" in Gmail shows `arc=pass` and the `X-PhishPilot-*` headers,
- a message that scores quarantine appears in PhishSOC quarantine and never
  reaches Workspace,
- mail to an address with no PhishSOC mailbox still arrives (tagged when
  suspicious).

## Rollback

Disable the relay toggle (or delete the `relay` block from
`domains/<domain>.json`) — the domain instantly reverts to standalone
behavior. No code deploy involved.
