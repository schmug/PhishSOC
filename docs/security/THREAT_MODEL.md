# Threat Model: PhishSOC

## 1. System context

PhishSOC is a phishing-triage SOC mailbox application built on Cloudflare
Workers (TypeScript) with a React 19 / React Router v7 single-page frontend.
Inbound email is delivered via the Cloudflare Email binding, parsed, and run
through a synchronous security pipeline (SPF/DKIM/DMARC, URL/homograph
heuristics, an LLM classifier, sender reputation, off-hours scoring) that
produces a verdict, followed by an asynchronous deep-scan stage
(redirect-chain resolution, RDAP domain age, CrowdSec CTI, Spamhaus DROP,
attachment heuristics). Per-mailbox state lives in a `MailboxDO` Durable
Object (SQLite + R2 attachments). AI chat agents (`EmailAgent`, `OrgAgent`
Durable Objects) and an MCP server expose mailbox tools to operators and
external AI clients. A MISP-compatible threat-intel `hub` exposes a
destroylist feed and admin UI. The app is deployed behind Cloudflare Access;
operators are authenticated teammates. It is the kind of system a small
security team self-hosts to triage a shared phishing inbox.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| Mailbox contents | Stored emails, headers, bodies, attachments, drafts per mailbox | high |
| Cross-mailbox / tenant isolation | The boundary that keeps one mailbox's data from another | high |
| Detection integrity | Correctness of the phishing verdict (a bypass lets phishing through; a flood causes alert fatigue) | high |
| Operator session | The authenticated Cloudflare Access session and its UI context | high |
| Service credentials | API keys/secrets in `Env` (CrowdSec, send-email, hub admin key, JWKS config) | critical |
| Internal/Cloudflare network reachability | What the Worker can reach via outbound fetch (internal hosts, metadata) | high |
| Service availability | The Worker staying responsive under crafted input | medium |
| Hub feed integrity | Correctness of the corroborated-phishing destroylist served to the community | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| Inbound email pipeline | `workers/index.ts` `receiveEmail` — raw MIME via the Email binding, parsed by `postal-mime`; subject/body/headers/attachments are fully attacker-controlled | untrusted email → process + stored mailbox data | Mailbox contents, Detection integrity, Service availability, Internal network reachability |
| Authenticated HTTP API | `workers/app.ts` + `workers/index.ts` + `workers/routes/*` — mailbox CRUD, settings, send, cases, dmarc/tlsrpt ingest, behind Cloudflare Access | unauth network → CF-Access-authenticated session | Mailbox contents, Cross-mailbox isolation, Operator session, Service credentials |
| Routes mounted before auth/ACL | `/api/v1/confirm` step-up (own JWT) and the yaramail HMAC callback are mounted before the mailbox-ACL middleware | unauthenticated network → privileged action gated by a separate secret | Mailbox contents, Cross-mailbox isolation |
| Outbound deep-scan fetches | `workers/intel/*` — redirect resolution of URLs extracted from email, RDAP, CrowdSec, DoH; `workers/mta-sts` policy fetch | server → arbitrary/attacker-named hosts | Internal network reachability, Service availability, Service credentials |
| Email rendering in UI | `app/components/EmailIframe.tsx` and signature rendering — stored untrusted email HTML projected into the operator's browser | stored untrusted content → operator browser | Operator session, Mailbox contents |
| AI agents & MCP server | `workers/agent/*`, `workers/mcp/*` — email content becomes LLM context; 9 mailbox tools exposed to operators and external AI clients | untrusted email content → LLM context → tool actions | Mailbox contents, Detection integrity |
| Hub feed & admin | `hub/*` — MISP event ingest/triage and the community destroylist feed; admin gated by `HUB_ADMIN_KEY`, per-org by bearer tokens | untrusted report submitters / unauth feed readers → hub state | Hub feed integrity, Service credentials |
| Settings-tier writes | mailbox POST/PUT, domain PUT, org PUT writing `*.json` to R2 (`workers/lib/mailbox-settings.ts`) | authenticated operator → multi-tier config inheritance | Detection integrity, Mailbox contents |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | SSRF / internal-resource access by crafting email URLs that the deep-scan stage resolves and fetches | remote_unauth | Outbound deep-scan fetches | Internal network reachability, Service availability | high | possible | partially_mitigated | MTA-STS uses `redirect:"manual"`; URL host checks parse `URL().hostname` (CodeQL-gated); no internal-range denylist on data-driven fetch | CLAUDE.md MTA-STS regression history (PRs #58/#92); CodeQL `js/incomplete-url-substring-sanitization` gate (PR #130) |
| T2 | Stored XSS via attacker-supplied email HTML/headers rendered in the operator's browser | remote_unauth | Email rendering in UI | Operator session, Mailbox contents | high | possible | partially_mitigated | DOMPurify sanitization + opaque-origin sandboxed iframe in `EmailIframe.tsx`; DOMPurify on signatures | |
| T3 | Cross-mailbox / tenant authorization bypass via a route reachable without the ACL gate or an ACL-blob bypass | remote_auth | Authenticated HTTP API; Routes mounted before auth/ACL | Cross-mailbox isolation, Mailbox contents | high | possible | partially_mitigated | Cloudflare Access perimeter; per-mailbox ACL blobs; HMAC on yaramail callback; step-up JWT on `/confirm` | |
| T4 | Detection-integrity manipulation: a crafted email evades verdict-tightening, makes LLM output load-bearing, or bypasses a score cap so phishing is scored clean | remote_unauth | Inbound email pipeline | Detection integrity | high | possible | partially_mitigated | SECURITY_SPEC Rules 1-6 (LLM advisory-only, monotonic tightening, score caps, fail-closed timeouts, no agent send) | SECURITY_SPEC.md Rules 1-6 exist precisely to bound this threat |
| T5 | SQL injection / unsafe query construction in the mailbox Durable Object or hub triage reaching stored data | remote_auth | Authenticated HTTP API; Hub feed & admin | Mailbox contents, Hub feed integrity | critical | rare | mitigated | Drizzle parameterized queries in `MailboxDO`; `.bind(...)` in hub triage; static migrations | |
| T6 | Disclosure of secrets / PII via error responses, logs, or over-broad API payloads | remote_auth | Authenticated HTTP API; Outbound deep-scan fetches | Service credentials, Mailbox contents | high | possible | partially_mitigated | Convention: secrets not logged; deep-scan logs error message only | |
| T7 | Settings-inheritance shadowing: a tier write persists rendered defaults as explicit overrides, silently masking upstream config | remote_auth | Settings-tier writes | Detection integrity, Mailbox contents | medium | possible | mitigated | `stripDefaultEqual(...)` on every write path, enforced by a `.claude/settings.json` hook | CLAUDE.md `stripDefaultEqual` convention (PRs #148/#154) |
| T8 | Sender / authentication-results spoofing: a forged `Authentication-Results` header is trusted, inflating sender legitimacy | remote_unauth | Inbound email pipeline | Detection integrity | medium | likely | partially_mitigated | Rule 3 trusted-authserv allowlist (default empty; operator must configure) | |
| T9 | Algorithmic-complexity / ReDoS denial of service via crafted email headers or body in a parser or heuristic | remote_unauth | Inbound email pipeline | Service availability | medium | possible | unmitigated | none specific (volumetric DoS is infra-layer; algorithmic blowup is not) | |
| T10 | Hub feed poisoning: a submitter corroborates a benign domain onto the community destroylist | remote_auth | Hub feed & admin | Hub feed integrity | medium | possible | partially_mitigated | corroboration threshold before promotion; admin/org token gating | |

## 5. Deprioritized

| threat | reason |
|---|---|
| Prompt injection from email content into the LLM classifier or EmailAgent/OrgAgent | Contained by SECURITY_SPEC Rules 1 & 6: LLM output is advisory-only and the agent has no send capability, so injection cannot move a verdict or take an action on its own. Re-promote only if injected text is shown to reach a load-bearing decision. |
| Volumetric DoS / request flooding | Handled at the Cloudflare infrastructure layer; out of application scope per `.github/SECURITY.md`. |
| Vulnerabilities in upstream dependencies (`postal-mime`, DOMPurify, etc.) | Out of scope per `.github/SECURITY.md`; tracked via Dependabot. |
| Attacks requiring Cloudflare Access to be disabled or physical CF-account access | Explicitly out of scope per `.github/SECURITY.md`. |
| Self-XSS, missing security headers without demonstrated impact | Low-severity classes excluded per `.github/SECURITY.md`. |

## 6. Open questions

- Does any data-driven outbound fetch (`workers/intel/url-resolver.ts`, RDAP, CrowdSec, DoH) restrict the destination host to public ranges, or can it reach `127.0.0.0/8`, `169.254.169.254`, or RFC-1918 hosts? (T1)
- Is DOMPurify applied on **every** path that renders email-derived HTML, including drafts, quoted replies, and any hub UI projection — or only the primary iframe? (T2)
- Are there any HTTP routes mounted before the mailbox-ACL middleware besides `/confirm` and the yaramail callback, and is each one independently authenticated? (T3)
- Is the HMAC verification on the yaramail callback constant-time, and is the secret compared with a timing-safe primitive? (T3)
- Can any email-controlled field reach a verdict write or a score that is not capped per Rule 4 — i.e., is the Rule 1/2/4 boundary enforced on every aggregation path? (T4)
- Are there parsers/heuristics that run unbounded regex or recursion over attacker-sized email fields without a size/time cap? (T9)
- What is the corroboration threshold and who can submit to the hub feed before a domain is promoted to the destroylist? (T10)

## 7. Provenance

- mode: bootstrap
- date: 2026-05-28
- target: /Users/cory/PhishSOC @ d2714eb
- inputs: code + CLAUDE.md + SECURITY_SPEC.md + .github/SECURITY.md (git-log/advisories not mined separately)
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Add an SSRF guard to every data-driven outbound fetch: resolve and reject private/link-local/metadata ranges before the request, on each redirect hop | T1 | yes | M |
| Enforce a Content-Security-Policy on the app and assert DOMPurify on every raw-HTML sink that renders email-derived content (test coverage per sink) | T2 | partial | M |
| Centralize the mailbox-ACL gate and add a test asserting no route is mounted before it without its own authentication | T3 | yes | M |
| Property/fuzz-test verdict aggregation against crafted emails to prove Rules 1/2/4 hold on every path (LLM advisory-only, monotonic, capped) | T4, T8 | partial | M |
| Apply size and time caps to all email-field parsers and regex heuristics; prefer linear-time matchers on attacker-controlled input | T9 | partial | S |
| Keep `stripDefaultEqual` on every settings-write path; the existing hook is the enforcement — extend it if a new write endpoint is added | T7 | yes | S |
