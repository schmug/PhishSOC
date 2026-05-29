# Step-Up Authentication: Two-Access-App Topology

PhishSOC enforces **per-send step-up authentication** for high-risk outbound email
(Tier ≥ 1 sends). When the composer detects a risky send, it opens a popup to the
step-up Cloudflare Access app, which runs an MFA challenge. On success the popup
mints a one-shot confirmation token that the main send request must include.

This document covers the two-app topology, required secrets, the session-reuse
window, and the **shared-hostname caveat** that operators must understand before
configuring the step-up app.

---

## 1. Two-App Topology

Two separate Cloudflare Access (self-hosted) applications share the same Worker
hostname (`inbox.cortech.online`):

| Application | Path | Access audience | Typical policy |
|---|---|---|---|
| **Main app** | `inbox.cortech.online/*` | `POLICY_AUD` | Email/SSO login, normal session duration (e.g. 24 h) |
| **Step-up app** | `inbox.cortech.online/api/v1/confirm` | `STEP_UP_AUD` | Require fresh MFA, short MFA-session duration (e.g. 15 m) |

The step-up app must cover **both GET and POST** on `/api/v1/confirm`:
- `GET /api/v1/confirm` — serves the relay HTML page; Access intercepts this request
  and runs the step-up login before letting it through.
- `POST /api/v1/confirm` — called by the relay page with `credentials: "same-origin"`;
  Access injects `cf-access-jwt-assertion` (audience = `STEP_UP_AUD`) on this fetch.

### Why /api/v1/confirm is mounted before the main Access middleware

In `workers/app.ts`, `/api/v1/confirm` is registered **before** the `app.use("*", …)`
middleware that validates `POLICY_AUD` tokens:

```
app.route("/api/v1/confirm", confirmRoute);   // step-up JWT — audience = STEP_UP_AUD
app.use("*", cfAccessMiddleware);             // main JWT   — audience = POLICY_AUD
```

If the confirm route were mounted after the main Access middleware, the step-up JWT
(`aud = STEP_UP_AUD`) would be rejected by the `POLICY_AUD` audience check before
the confirm handler ever ran. The route validates the step-up JWT itself (in
`workers/routes/confirm.ts`), so no main-Access bypass results.

### Tier classification

The composer classifies drafts into three tiers via `workers/security/send-risk.ts`:

| Tier | Trigger | Action |
|---|---|---|
| 0 | Internal-only recipients, trusted reply | No restriction |
| 1 | External recipient, > 10 recipients, or novel link domains | Step-up MFA required |
| 2 | BEC/credential keywords, macro attachment, or agent-authored Tier-1 | Step-up MFA required (bumped from Tier 1 for agent sends) |

---

## 2. Required Secrets

Set these with `wrangler secret put`. See `docs/secrets.md` for rotation cadences.

| Secret | Purpose | Generate |
|---|---|---|
| `STEP_UP_AUD` | Audience tag of the step-up Access application | Copy from Access app "AUD Tag" in the Cloudflare dashboard |
| `CONFIRMATION_TOKEN_SECRET` | HS256 signing key for the one-shot confirmation JWT | `openssl rand -hex 32` |
| `TEAM_DOMAIN` | Cloudflare Access team domain (also used by the main app) | e.g. `https://your-team.cloudflareaccess.com` |

`BLOOM_KV` must be bound in the production environment (used for one-shot `jti` replay
protection — each minted confirmation token is recorded in KV with a 120-second TTL
and consumed on first use; a replayed token returns 401).

---

## 3. Session Duration and the Silent-Reuse Window

The step-up Access application's **MFA session duration** determines how long a
successful MFA challenge is cached. A cached challenge lets subsequent sends within
that window complete without triggering a new MFA prompt:

- **15-minute MFA session:** the analyst is challenged on their first Tier ≥ 1 send;
  a second risky send within 15 minutes completes silently (no new MFA).
- **"Requires MFA on each login" per-app setting:** forces a fresh Access assertion
  on each popup navigation — effective per-send MFA. Note that `auth_time` is not
  exposed as a Cloudflare Access application-token claim; `iat` is the next-best
  signal and is stable within a warm session (see issue #364 for the empirical
  findings and planned `iat`-freshness enforcement).

Operator tradeoff: shorter MFA sessions increase friction but tighten the reuse window.

---

## 4. Shared-Hostname Caveat (Critical)

**Do not set the step-up app to "expires immediately" on a single-hostname topology.**

Because both Access applications share `inbox.cortech.online`, they share the same
Access session cookie. Setting the step-up app session to "expires immediately" forces
Access to expire the shared cookie after each step-up login — **which invalidates the
main app's session** for every API call the UI makes. The result is a continuous
re-authentication storm that breaks the UI completely.

This was confirmed during live testing on 2026-05-28 (see issue #287).

### Safe per-send alternatives on a single hostname

1. **Server-side `iat`-freshness enforcement** (#364): the `/api/v1/confirm` POST
   handler checks that the step-up JWT's `iat` is within a short freshness window
   (~60 s). A stale `iat` returns 401 and the relay retries with a fresh popup
   navigation — triggering a new MFA challenge without expiring the shared session
   cookie. Pending the re-test gates described in #364.

2. **Separate hostname for the step-up app**: host the step-up app at a different
   subdomain (e.g. `confirm.cortech.online/api/v1/confirm`). Each hostname gets its
   own cookie jar, so "expires immediately" on the step-up hostname is safe and
   does not touch the main app's session. Requires a routing change and an additional
   DNS record; tracked as an alternative in #287.

---

## 5. Testing the Step-Up Flow

### Trigger Tier 1 (external recipient)

1. Open the composer in a throwaway mailbox.
2. Address the email to an external domain (e.g. `test@example.com`).
3. Click **Send**. The step-up popup should open, run the MFA challenge, and close.
4. The email should send successfully.

### Trigger Tier 2 (BEC keyword)

1. Compose an email to any recipient containing a BEC keyword such as "wire transfer"
   or "urgent payment" in the subject or body.
2. The tier is bumped to 2; the popup opens the same way.

### Confirm cold-session behavior

Open the composer in an **incognito window** (no existing Access session) and trigger
a Tier 1 send. Access should prompt for full login + MFA before allowing the popup
to complete. A warm-session (logged-in) second send within the MFA-session window
completes without re-prompting.

### Confirm replay protection

Attempt a second send using the same `x-confirmation-token` (e.g. by capturing the
token and replaying the send-email request). The Worker returns **401** — the `jti`
was consumed on first use.

---

## Cross-References

- **#287** — topology decision: provision the step-up Access app, choose final MFA
  session duration, evaluate separate-hostname alternative.
- **#364** — `iat`-freshness enforcement in `/api/v1/confirm`: the primary
  same-hostname mechanism for per-send step-up once the re-test gates clear.
- `docs/secrets.md` — full rotation guidance for `STEP_UP_AUD` and
  `CONFIRMATION_TOKEN_SECRET`.
- `workers/routes/confirm.ts` — GET relay page + POST JWT verification + token minting.
- `workers/lib/confirm-token.ts` — one-shot token contract (60 s TTL, `payloadHash`
  binding, `jti` replay protection).
