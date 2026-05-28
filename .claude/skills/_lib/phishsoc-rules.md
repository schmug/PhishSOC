PhishSOC org-specific review calibration
=========================================

Pass this file to `/sec-vuln-scan` via `--extra` and to `/sec-triage` via
`--fp-rules`. It encodes invariants this codebase already enforces so they are
not re-reported as findings. Each rule names the control and WHERE it lives;
a verifier must still confirm the control is actually present at the cited
sink before dropping a finding — if the control is missing or bypassable on
the path under review, the finding is REAL.

Authoritative sources: `SECURITY_SPEC.md` (Rules 1-6), `.github/SECURITY.md`
(scope + disclosure), and the repo `CLAUDE.md` conventions.


SCOPE (from .github/SECURITY.md)
--------------------------------

In scope: `app/`, `workers/`, `hub/`, `shared/`; auth / authorization /
tenant-isolation boundaries; the detection pipeline (SPF/DKIM/DMARC parsing,
URL/homograph/RDAP analysis, LLM classifier); security-relevant
`wrangler.jsonc` config.

OUT OF SCOPE — treat as FALSE_POSITIVE (cite "out of scope per SECURITY.md"):
- Vulnerabilities in upstream/third-party dependencies (handled by Dependabot).
- Anything that requires physical access to the operator's Cloudflare account.
- Findings that only hold if Cloudflare Access is disabled, or that require
  running outside the documented deployment topology.
- Self-XSS, missing security headers with no demonstrated impact, and other
  low-severity classes major bug-bounty programs routinely reject.


PIPELINE INVARIANTS (from SECURITY_SPEC.md) — FALSE_POSITIVE if the finding
relies on violating one of these without showing the guard is missing
---------------------------------------------------------------------------

- Rule 1 — LLM output is NOT load-bearing. The Workers AI classifier
  (`workers/security/classification.ts`) and the hub triage agent
  (`hub/src/agent/triage.ts`) only influence advisory fields (tags,
  summaries, a capped score). Therefore **prompt injection via email
  subject/body/headers into the classifier or the EmailAgent/OrgAgent is NOT a
  code vulnerability in this target** — it cannot move a verdict on its own.
  Report it ONLY if you can show injected text reaches a load-bearing decision
  (a verdict write, an auth check, an outbound send) — that would itself be a
  Rule 1 violation and IS a real finding.
- Rule 2 — downstream stages only TIGHTEN verdicts. Deep-scan
  (`workers/intel/deep-scan.ts`) adds score and never downgrades. A finding
  that an async stage "lowers" a verdict is real only if the monotonicity
  guard is actually absent.
- Rule 3 — Authentication-Results are trusted only from an operator-configured
  authserv allowlist (`workers/security/auth.ts`). "We trust a spoofed
  Authentication-Results header" is FP unless the allowlist check is missing.
- Rule 4 — single-stage score contribution is capped (deep-scan ≤ 40, auth
  ≤ 30, classifier ~50 with confidence scaling). "One stage dominates the
  score" is FP unless the cap is missing.
- Rule 5 — LLM timeouts/parse-failures are treated as no-signal / fail-closed,
  not as a clean pass. FP unless that handling is absent.
- Rule 6 — the agent CANNOT send email. There is no `send_email` tool in the
  EmailAgent/OrgAgent toolset (`workers/agent/`); sending is a separate
  auth-protected, user-initiated endpoint. "The agent autonomously sends/
  exfiltrates" is FP unless a send-capable tool is actually wired in.


CONTROL LOCATIONS — FALSE_POSITIVE if the control is present at the cited sink
-----------------------------------------------------------------------------

- HTML / XSS: email HTML is rendered through DOMPurify in an opaque-origin
  iframe (`app/components/EmailIframe.tsx`); signatures are DOMPurify-sanitized
  in `app/lib/`. XSS in rendered email/signature content is FP UNLESS the
  sanitizer is missing or bypassable on that specific raw-HTML sink. (Stored
  email body/subject/headers and hub event data ARE untrusted — a NEW sink
  that bypasses DOMPurify is a real finding.)
- SSRF / redirects: MTA-STS policy fetches use `redirect: "manual"`
  (`workers/mta-sts/`), enforced by a hook in `.claude/settings.json`. "MTA-STS
  follows redirects" is FP unless `redirect: "manual"` is actually absent.
  Note: redirect-chain resolution of untrusted email URLs
  (`workers/intel/url-resolver.ts`) and RDAP/CrowdSec/DoH lookups ARE a real
  SSRF surface — report genuinely unguarded host/protocol control there.
- URL host checks: the convention is to compare a parsed `new URL(u).hostname`,
  never `startsWith`/`includes`/substring (CodeQL-gated). A substring host
  check IS a real finding; do not flag code that already parses the hostname.
- SQL: `MailboxDO` uses Drizzle with parameterized queries
  (`workers/durableObject/`); the hub uses `.bind(...)`. SQLi is FP unless you
  find string/template interpolation into a query or an unparameterized
  `.raw()`.
- Settings inheritance: every settings-tier write (mailbox POST/PUT, domain
  PUT, org PUT) routes through `stripDefaultEqual(...)`
  (`workers/lib/mailbox-settings.ts`), enforced by a hook. "Defaults shadow
  upstream tiers" is FP unless a write path skips `stripDefaultEqual` — a write
  path that DOES skip it is a real finding.
- ACL back-compat: when no `mailboxes-acl/<id>.json` blob exists, anyone whom
  Cloudflare Access already admitted is allowed (`workers/lib/mailbox-acl.ts`).
  This is intended documented design, not a bug. A real finding is a path that
  bypasses an ACL blob that IS present, or a route mounted before the ACL
  middleware that should be behind it.
- Auth front door: Cloudflare Access JWT validation in `workers/app.ts` is the
  perimeter; per Rule from SECURITY.md, any teammate past CF Access may reach
  all mailboxes by design. Tenant-isolation findings must show a break that
  does not assume CF Access is disabled.


STANDARD EXCLUSIONS (reinforce the built-in triage rules for this stack)
------------------------------------------------------------------------

- Volumetric DoS / rate-limiting / resource-exhaustion is infra-layer (FP).
  ReDoS / algorithmic blowup driven by untrusted email content IS reportable.
- No native memory-safety findings — this is TypeScript on Workers.
- Operator-controlled inputs (env vars, `wrangler.jsonc` values, CLI) are
  trusted unless an untrusted path reaches them.
- Open redirect, log spoofing, regex injection, missing audit logs, CSRF on
  idempotent endpoints: low-impact, FP unless chained into something real.
