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

### `STEP_UP_AUD` — optional

| Field | Value |
| --- | --- |
| **What it is** | Cloudflare Access audience tag for the step-up Access application scoped to `/api/v1/confirm`. Separate from `POLICY_AUD` so the confirmation endpoint can require a stricter Access policy (e.g. hard-key MFA). |
| **Where stored** | Cloudflare Workers secret — `wrangler secret put STEP_UP_AUD` |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role |
| **Rotation cadence** | Whenever the step-up Access application is regenerated or relevant personnel change. |
| **If missing** | The `/api/v1/confirm` endpoint returns `503`. The rest of the Worker is unaffected. |

See [`docs/step-up-auth.md`](step-up-auth.md) for the full two-app topology, shared-hostname caveat, and testing guide.

### `CONFIRMATION_TOKEN_SECRET` — optional

| Field | Value |
| --- | --- |
| **What it is** | HS256 HMAC signing secret for one-shot email-confirmation tokens issued by the `/api/v1/confirm` flow |
| **Where stored** | Cloudflare Workers secret — `wrangler secret put CONFIRMATION_TOKEN_SECRET` |
| **Who has access** | Cloudflare account members with Workers Admin or Super Administrator role |
| **Rotation cadence** | Every 90 days, or immediately after any suspected token-forgery incident. After rotation all outstanding confirmation links are immediately invalidated. Generate a cryptographically random value: `openssl rand -hex 32`. |
| **If missing** | The `/api/v1/confirm` endpoint returns `503`. |

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

---

## CI secrets (GitHub Actions)

The CI workflows (`ci.yml`, `codeql.yml`) run `npm run typecheck` and
`npm test` only. They do not deploy the Worker and do not require any
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
