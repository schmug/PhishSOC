# Secrets Management

This document lists every secret consumed by the PhishSOC Worker and CI
pipeline: where each secret is stored, who can access it, and how often it
should be rotated.

**No secret values appear here.** If you discover a value committed to the
repository, treat it as compromised and rotate immediately.

---

## Worker secrets (set with `wrangler secret put`)

These are injected into the Worker runtime as environment variables. They are
never stored in `wrangler.jsonc` or any checked-in file.

### `POLICY_AUD` — required

| Field | Value |
| --- | --- |
| **What it is** | Cloudflare Access audience tag (JWT `aud` claim) for the Worker's primary Access application |
| **Where stored** | Cloudflare Workers secret — Dashboard → Worker → Settings → Variables & Secrets, or `wrangler secret put POLICY_AUD` |
| **Who has access** | Cloudflare account members with the **Workers Admin** or **Super Administrator** role |
| **Rotation cadence** | Whenever the Cloudflare Access application is regenerated or a team member with access is offboarded. The value is re-read from the Access modal (Dashboard → Worker → Settings → Domains & Routes → Enable Access) — no external rotation tool needed. |
| **If missing** | The Worker refuses all requests with `403 Cloudflare Access must be configured in production`. |

### `TEAM_DOMAIN` — required

| Field | Value |
| --- | --- |
| **What it is** | Cloudflare Access team base URL (e.g. `https://your-team.cloudflareaccess.com`) or the full `/cdn-cgi/access/certs` URL, used to fetch the JWT public-key set |
| **Where stored** | Cloudflare Workers secret — same location as `POLICY_AUD` |
| **Who has access** | Same as `POLICY_AUD` |
| **Rotation cadence** | Whenever the Access team domain changes (rare). Rotate in tandem with `POLICY_AUD`. |
| **If missing** | Same as `POLICY_AUD` — Worker fails closed. |

### `CROWDSEC_CTI_API_KEY` — optional

| Field | Value |
| --- | --- |
| **What it is** | API key for the [CrowdSec CTI REST API](https://docs.crowdsec.net/u/cti_api/intro), used during async deep-scan to enrich redirect-target IPs with threat signals |
| **Where stored** | Cloudflare Workers secret — `wrangler secret put CROWDSEC_CTI_API_KEY` |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role; CrowdSec Console account owner |
| **Rotation cadence** | Every 90 days, or immediately on suspected compromise. Rotate in the CrowdSec Console and push the new value with `wrangler secret put CROWDSEC_CTI_API_KEY`. |
| **If missing** | The CTI enrichment stage is silently skipped; the Worker deploys and operates normally without it. |

### `STEP_UP_AUD` — REMOVED (issue #376)

The legacy two-Access-app step-up has been replaced by an app-layer WebAuthn
step-up (see [`docs/step-up-auth.md`](step-up-auth.md)). `STEP_UP_AUD` is no
longer read by any code. Operators should **delete it** during decommissioning:
`wrangler secret delete STEP_UP_AUD`, then remove the second Access application
scoped to `/api/v1/confirm` from the Cloudflare dashboard.

### `CONFIRMATION_TOKEN_SECRET` — required for step-up sends

| Field | Value |
| --- | --- |
| **What it is** | HS256 HMAC signing secret for one-shot send-confirmation tokens. The token is now minted by the WebAuthn `authenticate/verify` endpoint (`/api/v1/webauthn/authenticate/verify`) after a verified passkey assertion. |
| **Where stored** | Cloudflare Workers secret — `wrangler secret put CONFIRMATION_TOKEN_SECRET` |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role |
| **Rotation cadence** | Every 90 days, or immediately after any suspected token-forgery incident. After rotation all outstanding confirmation tokens are immediately invalidated. Generate a cryptographically random value: `openssl rand -hex 32`. |
| **If missing** | The WebAuthn step-up endpoints return `503`, so risky (Tier ≥ 1) sends cannot be confirmed. The rest of the Worker is unaffected. |

### `NEW_EMAIL_WEBHOOK_URL` — optional

| Field | Value |
| --- | --- |
| **What it is** | Deployment-wide **fallback** chat webhook for ops-visibility "new mail" notifications (issue #563). Used only when no settings tier configures a webhook — see `NEW_EMAIL_WEBHOOK_*` below. When it applies, every inbound email that lands in a mailbox (except honeypot mail and ingested DMARC/TLS-RPT/RUF reports) POSTs a `{"text": "..."}` message here — the format Google Chat and Slack incoming webhooks both accept — with sender, subject, landing folder, verdict action, and a deep link into the message. This is a **separate, higher-volume** channel from `SECURITY_ALERT_WEBHOOK_URL` (that one is a low-volume security pager; see issue #511). |
| **Where stored** | Cloudflare Workers secret — `wrangler secret put NEW_EMAIL_WEBHOOK_URL`. Kept out of `wrangler.jsonc` `vars` because the URL embeds credentials (a Google Chat incoming-webhook URL carries a `key` and `token` query string). |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role; the operator who created the Google Chat (or Slack) incoming webhook |
| **Rotation cadence** | Whenever the destination chat space changes, or immediately if the URL is suspected leaked (it is a bearer credential — anyone with it can post to the space). Generate a new incoming webhook URL in Google Chat: space → Apps & integrations → Webhooks, then `wrangler secret put NEW_EMAIL_WEBHOOK_URL`. |
| **If missing** | The new-mail notification dispatch silently no-ops; email receipt is unaffected. |

### `NEW_EMAIL_WEBHOOK_*` — optional, per-tier

| Field | Value |
| --- | --- |
| **What it is** | Per-mailbox / per-domain / per-org new-mail webhooks. A settings tier sets a `newEmailWebhook` block naming one of these secrets, and that tier's webhook replaces the global fallback for mail in its scope — so one mailbox can route to its own bot without clobbering the org-wide channel. |
| **Where stored** | Cloudflare Workers secrets, one per destination — `wrangler secret put NEW_EMAIL_WEBHOOK_GROK`. The settings blob stores only the secret's **name**; the URL never lands in R2, because the settings GET endpoints return those blobs to any Access-authenticated client and a webhook URL is a bearer credential. |
| **Secret value** | Either a bare URL (the default — right for Slack / Google Chat / Discord incoming webhooks, which carry their credential in the query string) **or** a JSON envelope for destinations that authenticate with a header: `{"url": "https://api.example.com/hook", "headers": {"Authorization": "Bearer …"}}`. Envelope headers are merged over `content-type`. A value that parses as JSON but has no usable `url` sends nothing rather than falling back. Keeping the destination and its credential in one operator-set secret is deliberate: settings name the secret and nothing more, so a settings write can never pair a credential with a destination of its choosing, and no host allowlist is required. |
| **Naming** | The name MUST start with `NEW_EMAIL_WEBHOOK_`. Enforced by the Zod schema on write and re-checked in `dispatchNewEmailNotification` at use time, so a hand-edited R2 blob cannot point the dispatch at an unrelated secret (`CONFIRMATION_TOKEN_SECRET`, `HUB_API_KEY`) and have its value POSTed off-platform. Same contract as `RELAY_CREDS_` (#615) and `SIDECAR_SECRET_`. |
| **Resolution** | Override semantics, most specific tier wins: `mailbox > domain > org`, then the global `NEW_EMAIL_WEBHOOK_URL`. `enabled` must be explicitly `true`. Setting `{"enabled": false}` on a tier **mutes** that scope — it does not inherit, and does not fall back to the global. |
| **Payload format** | `format: "chat"` (the default) posts `{"text": "..."}` prose, which Slack and Google Chat incoming webhooks render. `format: "json"` posts the structured event instead — `mailboxId`, `messageId`, `folder`, `sender`, `subject`, `verdictAction`, `verdictScore`, `url` — for a bot or automation that wants fields rather than a sentence to parse. The `json` shape sends the subject verbatim (no `<>|` strip: that exists only to stop forged chat link syntax) capped at 1000 characters. Resolved from the winning tier only, never merged across tiers. |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role; the operator who created the destination webhook |
| **Rotation cadence** | Same as the global secret — whenever the destination changes, or immediately if the URL is suspected leaked. |
| **If missing** | A tier naming a secret that is unset (or outside the prefix) sends nothing for that scope and logs the reason. It deliberately does **not** fall back to the global URL, which would leak the mail to the channel that tier was configured to replace. |

### `NEW_EMAIL_WEBHOOK_SIGNING_SECRET` — optional

| Field | Value |
| --- | --- |
| **What it is** | HMAC-SHA256 signing secret for outbound new-email webhook requests (issue #700). Applies to every destination — the global `NEW_EMAIL_WEBHOOK_URL` fallback and every per-tier `NEW_EMAIL_WEBHOOK_*` secret alike — so it is a single deployment-wide signing identity, not a per-destination one. When set, every request carries an `x-phishsoc-signature: t=<unix-seconds>,v1=<hex-hmac>` header (Stripe's `t=,v1=` construction), letting a receiver verify both authenticity and integrity and reject stale or replayed deliveries. The signature is computed over `${timestamp}.${rawBody}` — the exact serialized request body, whatever payload format it holds. |
| **Where stored** | Cloudflare Workers secret — `wrangler secret put NEW_EMAIL_WEBHOOK_SIGNING_SECRET`. |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role; the operator(s) who need to verify signatures on the receiving end |
| **Rotation cadence** | Every 90 days, or immediately on suspected compromise. Coordinate with every receiver before rotating — an old signature stops verifying the moment the Worker secret changes, so update receiver-side verification secrets in the same maintenance window. Generate a new value: `openssl rand -hex 32`. |
| **If missing** | The outbound request is sent exactly as it was before this feature existed — no signature header, same headers and body. Signing is opt-in and fully backward compatible. |
| **Receiver-side verification** | Reject any request whose signature doesn't verify, and reject stale timestamps to bound replay. Node.js example: |

```js
const crypto = require("crypto");

// rawBody must be the exact bytes received — read it before any JSON.parse.
function verifyPhishSocSignature(rawBody, signatureHeader, secret, toleranceSeconds = 300) {
  const match = /^t=(\d+),v1=([0-9a-f]+)$/.exec(signatureHeader || "");
  if (!match) return false;

  const timestamp = Number(match[1]);
  const signature = match[2];
  if (Math.abs(Date.now() / 1000 - timestamp) > toleranceSeconds) return false; // stale/replayed

  const expected = crypto
    .createHmac("sha256", secret)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");

  const received = Buffer.from(signature, "hex");
  const wanted = Buffer.from(expected, "hex");
  return received.length === wanted.length && crypto.timingSafeEqual(received, wanted);
}

// const ok = verifyPhishSocSignature(
//   rawBody,
//   req.header("x-phishsoc-signature"),
//   process.env.NEW_EMAIL_WEBHOOK_SIGNING_SECRET,
// );
```

### `RP_ID` / `RP_ORIGIN` — WebAuthn Relying Party config (wrangler vars, not secrets)

Set in `wrangler.jsonc` `vars`. `RP_ID` is the effective domain
(`inbox.cortech.online`); `RP_ORIGIN` is the exact https origin
(`https://inbox.cortech.online`). Both are validated against the request origin
on every step-up verify, so they MUST match the deployed hostname.

### `YARAMAIL_CALLBACK_SECRET` — optional

| Field | Value |
| --- | --- |
| **What it is** | HMAC-SHA256 shared secret used to authenticate callbacks from the yaramail YARA attachment-scanner sidecar. The sidecar signs its request body with this value; the Worker verifies the signature before accepting results. |
| **Where stored** | Cloudflare Workers secret — `wrangler secret put YARAMAIL_CALLBACK_SECRET`. Must also be set in the sidecar's environment under the same name. |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role; the operator running the sidecar |
| **Rotation cadence** | Every 90 days, or immediately if the sidecar host is compromised. Both the Worker secret and the sidecar's copy must be updated atomically — update the sidecar first, then the Worker, to avoid a window where signatures fail. Generate a new value: `openssl rand -hex 32`. |
| **If missing** | The yaramail callback route returns `503`. Attachment heuristics from YARA are skipped. |

### `CLOUDFLARE_API_TOKEN` — optional

| Field | Value |
| --- | --- |
| **What it is** | Cloudflare API token with the **AI:Read** scope, used to fetch the live Workers AI text-generation model catalog and cache it in `BLOOM_KV`. Required only if you want the Settings dropdown to reflect the live model list rather than the curated `TEXT_MODELS` constant. |
| **Where stored** | Cloudflare Workers secret — `wrangler secret put CLOUDFLARE_API_TOKEN`. **Not** a GitHub Actions secret; not used in CI. |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role |
| **Rotation cadence** | Every 90 days, or on personnel change. Generate/rotate in the Cloudflare Dashboard → My Profile → API Tokens. Scope the replacement token to AI:Read only. |
| **If missing** | The Worker falls back to the curated `TEXT_MODELS` constant. Everything else works normally. |

### `CLOUDFLARE_ACCOUNT_ID` — optional

| Field | Value |
| --- | --- |
| **What it is** | Cloudflare account ID paired with `CLOUDFLARE_API_TOKEN` to construct the Workers AI catalog request URL |
| **Where stored** | Cloudflare Workers secret — `wrangler secret put CLOUDFLARE_ACCOUNT_ID`. Public in most Cloudflare docs (it appears in URLs) but treated as a secret here to avoid hardcoding it. |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role |
| **Rotation cadence** | Does not rotate (account IDs are immutable). Update only if the Worker moves to a different Cloudflare account. |
| **If missing** | Same as `CLOUDFLARE_API_TOKEN` absent — Worker falls back to the curated model list. |

### `CLOUDFLARE_INTEL_API_TOKEN` / `CLOUDFLARE_INTEL_ACCOUNT_ID` — optional

| Field | Value |
| --- | --- |
| **What it is** | Cloudflare API token (scope: **Account → Intel → Edit**) and the account ID it files under. Used only by the analyst-confirmed **Submit to Cloudflare** phishing-categorization action on cases (issue #755). Never called from the receive pipeline, the agent, or MCP. |
| **Where stored** | Cloudflare Workers secrets — `wrangler secret put CLOUDFLARE_INTEL_API_TOKEN` and `wrangler secret put CLOUDFLARE_INTEL_ACCOUNT_ID` |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role |
| **Rotation cadence** | Every 90 days, or on personnel change. Scope the replacement token to Intel Edit only. |
| **If missing** | The route returns `501` and the button is disabled. Nothing else is affected. |

Two optional tuning variables go with it: `CF_CATEGORIZE_MONTHLY_CAP` (integer, default `20`; the shared Threat Intel quota is 100/month) and `CF_CATEGORIZE_EXTRA_BLOCKED` (comma-separated registrable domains added to the built-in never-submit list). Neither is sensitive; set them as secrets or `vars`.

### `URLSCAN_API_TOKEN` / `URLSCAN_ACCOUNT_ID` — optional, reserved

| Field | Value |
| --- | --- |
| **What it is** | Cloudflare API token (scope: **Account → URL Scanner → Edit**) and account ID for the analyst "Scan this URL" action (issue #754). The client and quota tracking exist; the UI action is not wired up yet. Scans are always submitted as Unlisted. |
| **Where stored** | Cloudflare Workers secrets — `wrangler secret put URLSCAN_API_TOKEN` and `wrangler secret put URLSCAN_ACCOUNT_ID`. `URLSCAN_MONTHLY_CAP` (default `450`) overrides the monthly cap. |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role |
| **Rotation cadence** | Every 90 days, or on personnel change |
| **If missing** | The scan action is disabled. |

### `ARC_SEAL_PRIVATE_KEY` — optional (inline gateway)

| Field | Value |
| --- | --- |
| **What it is** | PKCS8 PEM RSA private key used to ARC-seal mail the inline gateway relays to a backend (issue #32). The public key is published as a DNS TXT record under the ARC selector configured in org settings. See [`docs/gateway-mode.md`](gateway-mode.md). |
| **Where stored** | Cloudflare Workers secret — `wrangler secret put ARC_SEAL_PRIVATE_KEY < arc-private.pem` |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role |
| **Rotation cadence** | Yearly, or immediately on suspected compromise. Publish the new public key under a **new selector**, switch the selector in org settings, then retire the old DNS record after in-flight mail has been delivered. |
| **If missing** | Relayed mail goes out unsealed (no alert). A key that is set but fails to seal also relays unsealed, and that does fire a security alert. |

### `WEBAUTHN_ADMIN_EMAILS` — optional

| Field | Value |
| --- | --- |
| **What it is** | Comma-separated allowlist of admin emails who may clear another user's lost step-up passkeys so they can re-enroll (issue #507). Only an interactive Access identity with an email claim qualifies; service tokens never do. |
| **Where stored** | Cloudflare Workers secret (`wrangler secret put WEBAUTHN_ADMIN_EMAILS`) or a `wrangler.jsonc` var. Kept out of teammate-editable settings on purpose. |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role |
| **Rotation cadence** | Review on personnel change |
| **If missing** | Admin recovery is impossible (fails closed). |

### `HUB_ALLOWED_HOSTS` / `FEED_ALLOWED_HOSTS` — optional (required to use hub or feed credentials)

| Field | Value |
| --- | --- |
| **What it is** | Comma-separated hostname allowlists that pin where credentials may be sent. A `HUB_SECRET_*` key is only sent when `intel.hub.url` is https and its hostname is on `HUB_ALLOWED_HOSTS`. A `FEED_SECRET_*` Authorization header is only attached when the feed URL is https and its hostname is on `FEED_ALLOWED_HOSTS` or belongs to a built-in default feed. Not secret themselves, but operator-only because settings are teammate-editable. |
| **Where stored** | Workers secret or `wrangler.jsonc` var |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role |
| **Rotation cadence** | Update when the hub or a credentialed feed moves hosts |
| **If missing** | Hub credentials are never released; credentialed feeds still fetch, but without their secret. |

### Prefixed secret families

Some settings reference a Worker secret **by name** so the value itself never lands in R2 (settings blobs are readable by any Access-authenticated client). Each family has a required prefix, enforced by the Zod schema on write and re-checked at use time so a hand-edited blob cannot point at an unrelated secret.

| Prefix | Used by | Value | Guide |
| --- | --- | --- | --- |
| `RELAY_CREDS_` | Inline gateway relay, per domain | JSON `{"user": "...", "pass": "..."}` for SMTP submission | [`gateway-mode.md`](gateway-mode.md) |
| `SIDECAR_SECRET_` | Workspace sidecar | Google service-account JSON key with domain-wide delegation | [`sidecar-credentials.md`](sidecar-credentials.md) |
| `HUB_SECRET_` | Community hub client (`intel.hub`) | Hub API key | [`hub/`](../hub/) |
| `FEED_SECRET_` | Credentialed intel feeds (`intel.feeds[].auth_secret`) | Feed API key, e.g. a CrowdSec Console blocklist key | — |
| `NEW_EMAIL_WEBHOOK_` | Per-tier new-mail webhooks | Webhook URL, or a `{url, headers}` JSON envelope | See above |

Rotate each with `wrangler secret put <NAME>`; the settings reference does not change.

---

## CI secrets (GitHub Actions)

The CI workflows (`ci.yml`, `codeql.yml`, `bumblebee.yml`) run typecheck,
tests, CodeQL, and a lockfile exposure scan only. They do not deploy the Worker and do not require any
Cloudflare credentials. There are currently **no GitHub Actions secrets**
configured for this repository.

If a deployment workflow is added in the future, the Cloudflare API token
used for `wrangler deploy` should be:

- Stored as a GitHub Actions repository secret (`Settings → Secrets and
  variables → Actions`) scoped to the repository only.
- Named `CLOUDFLARE_API_TOKEN` (conventional name for the Wrangler GitHub
  Action).
- Rotated every 90 days or on relevant personnel change.
- Scoped to the minimum required Cloudflare permissions (Workers:Edit,
  Workers Scripts:Edit).

---

## Local development

For local development, copy `.dev.vars.example` to `.dev.vars` (already in
`.gitignore`) and populate the values. `POLICY_AUD` and `TEAM_DOMAIN` are
not required locally — the Worker skips Cloudflare Access validation when
running under `wrangler dev`.

**Never commit `.dev.vars` or any file containing secret values.**

---

## Rotation checklist

1. Generate a new value (use `openssl rand -hex 32` for HMAC secrets; use
   the issuing service's UI for API keys and audience tags).
2. Set the new value: `wrangler secret put <SECRET_NAME>`.
3. If the secret is shared with a sidecar or external system, update that
   system's copy first to avoid a validation gap.
4. Verify the Worker responds normally after the new secret propagates
   (Cloudflare Workers secret propagation is typically < 30 s).
5. Record the rotation date in your team's access-management log.
