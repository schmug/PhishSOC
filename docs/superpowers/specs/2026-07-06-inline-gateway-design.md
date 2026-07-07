# Inline Gateway Mode — v1 design (Foundations + Option A)

**Date:** 2026-07-06
**Issue:** [#32](https://github.com/schmug/PhishSOC/issues/32) — feat: inline gateway mode — provider-agnostic MX-front MTA
**Slice:** first design→plan→implement cycle of #32. Covers relay-policy config,
ARC sealing, verdict-to-action relay core, and the Option A deployment shape
(Cloudflare Email Routing in, Worker relays out via SMTP submission). Option B
(external Postfix/Haraka front-end) and the outbound flow are follow-up issues.

## Decisions made during brainstorming

| Decision | Choice | Rationale |
| --- | --- | --- |
| V1 slice | Foundations + Option A | Dogfoodable on the existing Cloudflare deployment with no new infra; Option B reuses everything but the SMTP client. |
| Signing scope | ARC seal only, one gateway-level key | Origin DKIM survives raw relay with additive headers; only SPF breaks, and ARC is the remedy. Per-domain DKIM keys are only needed for the deferred outbound flow. |
| Test backend | Google Workspace tenant | Relay via `smtp-relay.gmail.com:587`; verify arrival + `arc=pass` in a real Workspace inbox. |
| Storage mode | Full mirror for registered mailboxes; unregistered recipients scanned, tag-capped, relayed, not stored | Relay is purely additive for registered mailboxes so quarantine UI/agent/audit keep working; unregistered recipients have no mailbox to store into. |
| Implementation approach | Sync in-pipeline relay; owned minimal SMTP client over `cloudflare:sockets`; ARC module behind a clean interface with a time-boxed `mailauth` spike | No new bindings; origin-MTA retry semantics for free; vetted canonicalization if `mailauth` runs on workerd. |

## Platform constraint that reshaped the issue

Cloudflare Workers **cannot open outbound TCP connections on port 25**
(platform-wide block). The issue's `smtp-relay.ts` sketch — "connect to
`aspmx.l.google.com`" — is port-25 MX delivery and is impossible from a Worker.
Consequences:

- Option A relays only via **submission ports** (587 STARTTLS / 465 implicit
  TLS) with operator credentials — e.g. `smtp-relay.gmail.com:587`,
  `smtp.office365.com:587`.
- Option B is unaffected (the external front-end does all SMTP) and remains the
  recommended production shape, per the issue.

## Architecture

Gateway mode is a **per-domain configuration, not a deployment mode**. A domain
enters gateway mode when its `DomainSettings` gains a `relay` policy block.
Domains without one are untouched; switching a domain in/out of gateway mode is
a settings write (satisfies the issue's "config change, not code change"
criterion).

Relay policy lives in the **domain settings tier** (`domains/<domain>.json` in
R2, Zod schema, `stripDefaultEqual` at the endpoint layer) — deliberately *not*
the `domain_relay_policy` D1 table the issue sketched. Repo convention wins;
credentials stay in Worker Secrets referenced by name.

### Registered-mailbox flow

Everything up to and including the verdict is today's pipeline, untouched:

```
email() [workers/app.ts:164]
  → normalizeInbound() [workers/providers/cf-routing.ts]
  → receiveEmail() [workers/index.ts:1492]
      → attachments to R2
      → runSecurityPipeline() → FinalVerdict [workers/security/verdict.ts:103]
      → folder move (QUARANTINE on quarantine/block) + MailboxDO storage
      → NEW: relay branch (this design)
```

The relay branch, reached only when the recipient domain has an enabled relay
policy:

1. Map `FinalVerdict.action` through the policy's action table.
   Defaults: `allow → relay`, `tag → relay` (headers carry the tag),
   `quarantine → hold`, `block → drop`. All four overridable per domain with
   behaviors `relay | hold | drop`.
2. For `relay`: prepend `X-PhishPilot-Verdict: <action>` and
   `X-PhishPilot-Score: <score>` headers to the **raw bytes**. Prepending new,
   distinct header names never invalidates the origin's DKIM signature.
3. ARC-seal the message *after* header prepending (the seal covers the added
   headers).
4. Hand raw bytes + envelope to `SmtpRelayProvider` → SMTP submission to the
   policy target.

Envelope on relay: `MAIL FROM` preserves the original envelope sender (the
runtime email event exposes `from`; only the typed signature in
`workers/app.ts:165` omits it — widen the type), `RCPT TO` is the original
envelope recipient. SPF breaks by design; ARC is the remedy.

`hold` and `drop` change nothing about existing behavior: quarantined mail
stays in the PhishSOC QUARANTINE folder (existing folder move), blocked mail is
handled as today. **Fail-closed default: under the default mapping,
`quarantine` and `block` verdicts never reach the relay call** — the relay
branch is only reachable through the action mapping, and relaying those
verdicts requires an explicit per-domain override (e.g. `quarantine: "relay"`
for operators who prefer backend-native quarantine routing; the verdict header
still travels with the message).

### Unregistered-recipient flow (gateway passthrough)

A gateway fronting a whole domain receives mail for Workspace users with no
registered PhishSOC mailbox. `normalizeInbound()` gains a third outcome: when
the recipient's domain has relay enabled and no registered mailbox matches, it
returns a new `GatewayInbound` kind. A new `receiveGatewayPassthrough()` in
`workers/index.ts`:

1. Runs the security pipeline with **domain-tier** resolved settings.
2. **Caps the action at `tag`** (reusing the learning-mode action-cap
   mechanism) — quarantine would have nowhere to store the message.
3. Prepends verdict headers, seals, relays. On this path a configured `hold`
   behavior degrades to `relay` — there is no mailbox to hold into, and
   delivering tagged beats losing mail.
4. Stores **nothing** (no mailbox, no copy). No mail is black-holed for users
   PhishSOC doesn't know about.

Precedence: for relay-enabled domains this branch wins over catch-all.
Catch-all-intel × gateway interplay is a filed follow-up.

### ARC sealing (RFC 8617)

- Sealer identity is **org-tier** — one per deployment: `gateway:
  { arcSealerDomain, arcSelector }` in org settings. The private key never
  touches R2; it lives in the `ARC_SEAL_PRIVATE_KEY` Worker Secret (PKCS8 PEM).
- The `ARC-Authentication-Results` (AAR) header is built from the `AuthVerdict`
  the pipeline already parsed (`workers/security/auth.ts`), with
  `arcSealerDomain` as the `authserv-id`.
- **v1 seals only when the inbound message has no existing ARC chain** (we are
  `i=1`). If a chain exists, relay unsealed (origin DKIM still carries) and
  log — chain *validation* is out of scope per the issue, and sealing atop an
  unvalidated chain would require asserting a `cv=` value we can't honestly
  compute.
- Key generation is documented (`openssl` one-liners); the operator publishes
  the `<selector>._domainkey.<sealerDomain>` DNS TXT record manually. No keygen
  UI in v1.

## Components & schemas

### New settings (flow through existing endpoints + `stripDefaultEqual` — no new write paths)

`shared/domain-settings.ts` — new optional `relay` block:

```ts
relay: z.object({
  enabled: z.boolean().default(false),
  target: z.object({
    host: z.string(),                        // "smtp-relay.gmail.com"
    port: z.number().int().default(587),
    implicitTls: z.boolean().default(false), // true = 465, false = STARTTLS on 587
  }),
  credentialsSecret: z.string().optional(),  // name of a Worker Secret holding {"user","pass"} JSON;
                                             // absent = unauthenticated relay (IP-allowlisted backends)
  actions: z.object({                        // verdict action → relay behavior
    allow: z.enum(["relay", "hold", "drop"]).default("relay"),
    tag: z.enum(["relay", "hold", "drop"]).default("relay"),
    quarantine: z.enum(["relay", "hold", "drop"]).default("hold"),
    block: z.enum(["relay", "hold", "drop"]).default("drop"),
  }).optional(),
}).optional()
```

`shared/org-settings.ts` — new optional `gateway` block:
`{ arcSealerDomain: string, arcSelector: string }`.

`workers/types.ts` `Env` — add `ARC_SEAL_PRIVATE_KEY?: string`.

### New modules (one responsibility each)

| Module | Contract |
| --- | --- |
| `workers/lib/arc-seal.ts` | `sealMessage(raw: Uint8Array, opts: { authResults, sealerDomain, selector, privateKeyPem }): Promise<string \| null>` — returns the three-header ARC block (AAR/AMS/AS) to prepend, or `null` when an existing chain forces the skip. Internals: `mailauth`'s sealer if the spike proves it runs on workerd, else owned relaxed canonicalization + `crypto.subtle` RSASSA-PKCS1-v1_5/SHA-256. Consumers can't tell which. |
| `workers/lib/smtp-client.ts` | `submitRaw({ host, port, implicitTls, auth?, mailFrom, rcptTo, raw }): Promise<void>` over `cloudflare:sockets`: EHLO → STARTTLS (or implicit TLS) → AUTH PLAIN → MAIL/RCPT → dot-stuffed DATA → QUIT. Throws typed errors distinguishing **transient** (4xx / connect / TLS) from **permanent** (5xx). |
| `workers/providers/smtp-relay.ts` | `SmtpRelayProvider` — glues policy → credentials lookup (`env[policy.credentialsSecret]`) → header prepend → seal → `submitRaw`. Registered in `workers/providers/registry.ts` keyed by relay-policy presence. |

### Modified files

- `workers/providers/types.ts` — new `GatewayInbound` kind
  (`{ kind: "gateway", rawEmail, parsedEmail, recipient, domain, envelopeFrom }`);
  `MailboxInbound` gains `envelopeFrom` so the relay branch has the true
  `MAIL FROM`.
- `workers/providers/cf-routing.ts` — resolve `GatewayInbound`; capture
  `event.from`.
- `workers/app.ts` — dispatch the third kind; widen the `email()` event type to
  include `from`.
- `workers/index.ts` — relay branch in `receiveEmail()`; new
  `receiveGatewayPassthrough()`.

### UI (minimal, existing pages)

- Domain settings page: Relay Policy card — enable, target host/port,
  credentials secret name, action-mapping selects showing defaults.
- Org settings page: two ARC fields (sealer domain, selector).

### Docs

`docs/gateway-mode.md` — Workspace setup (SMTP relay service config,
inbound-gateway setting, MX cutover), ARC key generation + DNS TXT, secret
naming convention, action-mapping semantics, explicit note that v1 is
inbound-only.

## Error handling

The load-bearing decision is what happens when relay fails; it splits on the
SMTP error class:

| Failure | Behavior |
| --- | --- |
| **Transient** (4xx, connect timeout, TLS failure) | Throw out of `receiveEmail()`. The existing handler re-throws (`workers/app.ts:180`), Cloudflare defers, the origin MTA retries — genuine MTA at-least-once semantics with no queue infrastructure. Cost: a retry re-runs the pipeline and may store a duplicate copy in PhishSOC. Accepted for v1 (retries are rare); Message-ID dedup is a filed follow-up. The alternative — swallowing the error — silently drops mail from the user's Workspace inbox. |
| **Permanent** (5xx: bad credentials, rejected recipient) | Do **not** throw — the mail is already safe in the PhishSOC mirror. Log, fire a `security-alert` (`workers/lib/security-alert.ts`), record `relay: "failed"` on the stored email's metadata so it's visible in the UI. |
| **Sealing failure** (bad key, malformed message) | Relay **unsealed** rather than not at all — deliverability degrades, mail still arrives. Log + alert. |
| **Unregistered-recipient path** | Same policy, except there is no local copy on permanent failure — permanent failures there **do** throw (bounce to origin is the only honest outcome). |

## Testing

All in the existing vitest setups (`test/`, `tests/`, vitest-pool-workers).

- **`arc-seal`**: unit tests against RFC 8617 vectors, plus a cross-check that
  seals we produce **validate with `mailauth`'s verifier** in Node-side tests —
  independent verification even if the sealer ends up owned code.
- **`smtp-client`**: scripted fake socket (in-memory `cloudflare:sockets`
  shape) — happy path, STARTTLS ordering, AUTH rejection, 4xx-vs-5xx error
  typing, dot-stuffing edge cases.
- **Pipeline**: `receiveEmail()` with a capturing mock provider — full
  verdict × action-mapping matrix, quarantine-never-relays, tag-cap on the
  passthrough path, header prepending preserves raw bytes.
- **Settings**: relay block round-trips through domain PUT with
  `stripDefaultEqual` (defaults don't persist).
- **Spike (plan step 1)**: seal a message with `mailauth` on workerd under
  `nodejs_compat`; the outcome picks the `arc-seal` internals before dependent
  work starts.

Test-mock URL checks parse hostnames, never substring-match (CodeQL gate, per
CLAUDE.md).

## Acceptance (adapted from #32 to the Option A slice)

1. A test domain's MX at Cloudflare; relay policy pointing at
   `smtp-relay.gmail.com:587` with credentials; ARC key published in DNS.
2. Inbound mail from the internet arrives in the Workspace inbox with
   `arc=pass` in Gmail's "show original" and `X-PhishPilot-*` headers present.
3. A quarantine-scoring message stays in PhishSOC quarantine and never reaches
   Workspace.
4. Mail to an unregistered address on the domain relays tagged, with nothing
   stored locally.
5. Disabling the relay policy returns the domain to standard (non-gateway)
   behavior with no code change.

## Out of scope — follow-up issues to file after implementation

- Option B: HTTP front-end endpoint (HMAC-authed, `yaramail-callback` pattern)
  + Postfix/Haraka recipe docs.
- Per-domain DKIM keys + outbound flow (backend → gateway → internet).
- Quarantine release / recipient digest UX.
- Catch-all-intel × gateway-passthrough interplay.
- ARC chain validation / sealing atop existing chains (`i>1`).
- Message-ID dedup on origin-retry re-delivery.
- M365 live validation (schema/config already provider-agnostic).
