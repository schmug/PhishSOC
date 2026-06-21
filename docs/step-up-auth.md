# Step-Up Authentication: App-Layer WebAuthn

PhishSOC enforces **per-send step-up authentication** for high-risk outbound email
(Tier ≥ 1 sends). When the composer detects a risky send, the user completes an
in-page **WebAuthn** assertion (Touch ID / Windows Hello / a security key) with
`userVerification: "required"`. The server verifies the assertion inside the
Worker, binds it to the Access-authenticated identity and the exact send payload,
and only then mints the one-shot confirmation token the send must carry.

This replaces the previous two-Access-app topology (issue #376). That design put a
second Access application on `/api/v1/confirm` of the same hostname as the main
app; both emitted a `CF_Authorization` cookie, the step-up path was nested inside
the main app's scope, and the browser sent **both** identically-named cookies to
`/api/v1/confirm`. Access read the wrong one and re-challenged forever — a verified
cookie collision (Access logs: 51 ALLOWED / 0 blocked), with no clean same-hostname
fix. WebAuthn removes the second Access app entirely: no popup, no cross-site
redirect, no cookie collision.

---

## 1. Topology

There is now **one** Cloudflare Access application — the main app
(`inbox.cortech.online/*`, audience `POLICY_AUD`). It remains the SSO/identity
layer. WebAuthn is an application-layer second factor mounted *behind* that
middleware:

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/v1/webauthn/authenticate/options` | main Access JWT | Issue a fresh, payload-bound assertion challenge |
| `POST /api/v1/webauthn/authenticate/verify` | main Access JWT | Verify the assertion, mint the confirm token |
| `POST /api/v1/webauthn/register/options` | main Access JWT (**interactive only**) | Begin enrollment (first key, or 2nd-key step-up gate) |
| `POST /api/v1/webauthn/register/verify` | main Access JWT (**interactive only**) | Store the new credential |

Because every route runs after the main Access middleware, the verified Access
identity (`sub` + optional `email`) is on the request context (`c.var.accessIdentity`,
see `workers/lib/access-identity.ts`). `sub` is the per-user trust anchor; `email`
is present only for interactive SSO sessions and gates enrollment away from service
tokens / the MCP server.

### Tier classification (unchanged)

The composer classifies drafts into three tiers via `workers/security/send-risk.ts`:

| Tier | Trigger | Action |
|---|---|---|
| 0 | Internal-only recipients, trusted reply | No restriction |
| 1 | External recipient, > 10 recipients, or novel link domains | WebAuthn step-up required |
| 2 | BEC/credential keywords, macro attachment, or agent-authored Tier-1 | WebAuthn step-up required + composer confirm phrase |

The send gate (`workers/lib/send-risk-gate.ts`) and the one-shot confirm-token
contract (`workers/lib/confirm-token.ts`: `payloadHash` binding, HS256, 60 s TTL,
`jti` replay protection in `BLOOM_KV`) are **unchanged** — WebAuthn changes only how
the token is minted.

### The four invariants enforced on `authenticate/verify`

1. **Fresh, payload-bound, one-shot challenge.** Issued server-side, stored in D1,
   bound to `(sub, payloadHash)`, consumed atomically with `DELETE … RETURNING` so a
   replayed or failed attempt cannot reuse it.
2. **Identity binding (load-bearing).** The asserted credential's `user_sub` MUST
   equal the request's Access `sub`. This is what stops an attacker with their own
   enrolled passkey + a stolen warm session from confirming someone else's send.
3. **User verification required.** Biometric / PIN, not bare presence.
4. **Full server verify.** RP ID, origin, challenge match, signature, and
   sign-counter regression, via `@simplewebauthn/server` (no hand-rolled crypto).

---

## 2. Configuration

### Vars (`wrangler.jsonc`)

| Var | Value | Notes |
|---|---|---|
| `RP_ID` | `inbox.cortech.online` | WebAuthn Relying Party ID — the effective domain (no scheme/port). MUST match the deployed hostname or every assertion is rejected. |
| `RP_ORIGIN` | `https://inbox.cortech.online` | The exact origin asserted in `clientDataJSON`. Validated on every verify. |

### Bindings

- **`WEBAUTHN_DB`** — D1 database (the first in the project). Stores
  `webauthn_credentials` and `webauthn_challenges` (schema in
  `migrations/webauthn/0001_init.sql`).
- **`BLOOM_KV`** — already bound; carries the one-shot confirm-token `jti`.

### Secrets (`wrangler secret put`)

| Secret | Purpose |
|---|---|
| `CONFIRMATION_TOKEN_SECRET` | HS256 signing key for the one-shot confirm JWT (`openssl rand -hex 32`) |
| `TEAM_DOMAIN` / `POLICY_AUD` | Main Cloudflare Access app (unchanged) |
| `SECURITY_ALERT_WEBHOOK_URL` | **Optional.** Out-of-band webhook for first-passkey (TOFU) enrollment alerts (see §6). When set, a first-key registration POSTs the `webauthn.first_key_registered` audit payload here. When unset, only the `console.log` audit line is emitted. |

> The legacy `STEP_UP_AUD` secret is **no longer used** and should be deleted (see
> the runbook below).

### One-time D1 setup

```bash
wrangler d1 create phishsoc-webauthn
# Copy the returned database_id into wrangler.jsonc d1_databases[0].database_id
wrangler d1 migrations apply phishsoc-webauthn --remote
```

---

## 3. Enrollment-first rollout

The rollout is **enrollment-first, then enforce**:

1. Deploy this build. The send gate still requires a confirm token for Tier ≥ 1,
   but the token is now minted only by a WebAuthn assertion.
2. Each operator enrolls a passkey in **Settings → Passkeys** (`app/components/PasskeyPanel.tsx`).
   The first key is a single ceremony behind an interactive Access session and
   emits a `webauthn.first_key_registered` audit log.
3. If an operator attempts a Tier ≥ 1 send before enrolling, the composer surfaces
   "No passkey enrolled. Add one in Settings → Passkeys, then send again."
4. Adding a 2nd+ key requires a fresh assertion from an existing key (a Tier-2
   step-up), so a stolen warm session cannot silently enroll a new authenticator.

**Recovery is admin-mediated only.** There is no emailed reset link, no TOTP
fallback, and no self-serve reset — each would reintroduce the email/injection
threat or a phishable weakest link. Admin recovery tooling is tracked in #507.

---

## 4. Operator runbook: decommissioning the old step-up

Do these **after** confirming the new build is live and operators have enrolled:

1. **Confirm enrollment.** Ensure each operator who sends risky mail has at least
   one credential (watch for `webauthn.first_key_registered` audit logs).
2. **Delete the second Access application** (the one scoped to `/api/v1/confirm`)
   in the Cloudflare Access dashboard. It is no longer referenced by any code.
3. **Delete the `STEP_UP_AUD` secret:** `wrangler secret delete STEP_UP_AUD`.
4. The `/api/v1/confirm` route (GET relay + Access-JWT POST) has already been
   removed from the Worker, so no traffic reaches the old path.

AAGUID hardware-pinning (restricting to approved authenticator models) is
deliberately deferred so bring-up isn't blocked; it is tracked in #506.

---

## 5. Testing the step-up flow

### Locally

`wrangler dev` seeds a synthetic interactive Access identity, so the WebAuthn
routes are exercisable. Use a virtual authenticator (Chrome DevTools → WebAuthn)
to enroll and assert.

### Automated

- `tests/workers/webauthn-authenticate.test.ts` — the six authenticate cases
  (happy + wrong-user / replay / payload-mismatch / UV-absent / counter-regression)
  in real `workerd` with self-signed ES256 assertions.
- `tests/workers/webauthn-register.test.ts` — interactive gating, first-key audit,
  2nd-key existing-key requirement.
- `tests/workers/webauthn-store.test.ts` — D1 store incl. atomic challenge consume.
- `tests/frontend/step-up-confirm.test.ts`, `webauthn-enroll.test.ts`,
  `passkey-panel.test.tsx`, `compose-send-risk.test.tsx`,
  `email-panel-send-risk.test.tsx` — client relay, enrollment, and composer wiring.

### Replay protection

Replay the same `x-confirmation-token` on a second send → **401** (`jti` consumed).
Replay the same WebAuthn assertion → **401** (challenge consumed by `DELETE … RETURNING`).

---

## 6. First-key (TOFU) enrollment alert

The **first** passkey a `sub` enrolls is the highest-risk moment in the whole
step-up: whoever lands that first credential can thereafter mint confirm tokens
for that identity's risky sends. There is no prior key to step up against, so the
first enrollment is trust-on-first-use. To make a surreptitious first-key
registration *actively* detectable — not just retrospectively greppable —
`register/verify` does two things on the first key only:

1. **Audit line (always).** Emits the structured
   `webauthn.first_key_registered` log (`sub`, `email`, `credentialId`,
   `aaguid`) for retrospective search. This is unconditional.
2. **Operator notification (when configured).** If the optional
   `SECURITY_ALERT_WEBHOOK_URL` secret is set, POSTs that same audit payload to
   the webhook as `application/json`, so the event reaches a pager / SOC channel
   in real time.

```bash
wrangler secret put SECURITY_ALERT_WEBHOOK_URL
# e.g. a Slack/PagerDuty/Sentry inbound webhook, or your own collector
```

Example payload:

```json
{
  "event": "webauthn.first_key_registered",
  "sub": "a1b2c3d4-…",
  "email": "operator@example.com",
  "credentialId": "…",
  "aaguid": "00000000-0000-0000-0000-000000000000"
}
```

**Fire-and-forget by contract.** The notification is dispatched via
`ctx.waitUntil(...)` (see `workers/lib/security-alert.ts`) and every failure — a
down endpoint, a timeout (10 s cap), a non-2xx response, or a malformed URL — is
caught and logged, never propagated. Enrollment still returns
`{ verified: true }` and the credential is still stored even if the webhook
throws. Only **first-key** registrations notify; adding a 2nd+ key (which already
requires a fresh existing-key assertion) does not. When the secret is unset the
dispatch no-ops and only the audit line is emitted.

> This alert is the operator notification channel referenced by the rollout
> (§3) and decommissioning runbook (§4) "watch for `webauthn.first_key_registered`"
> steps — wire the webhook before broad enrollment so the first keys are seen live.

---

## Cross-References

- **#376** — this work: app-layer WebAuthn step-up replacing the Access-JWT step-up.
- **#364 / #287** — superseded same-hostname / separate-hostname Access approaches.
- **#506** — AAGUID hardware-pinning (deferred).
- **#507** — admin recovery tooling (deferred).
- `workers/routes/webauthn.ts` — authenticate + register endpoints.
- `workers/lib/webauthn-store.ts` — D1 credential + challenge store.
- `workers/lib/confirm-token.ts` — one-shot token contract (unchanged).
