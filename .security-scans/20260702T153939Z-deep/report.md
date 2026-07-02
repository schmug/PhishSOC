# PhishSOC — Deep Security Audit Report

**Target:** `/home/user/PhishSOC` — Cloudflare-Workers phishing-triage backend + React SPA
**Scope:** `workers/` (security pipeline, intel deep-scan, agent Durable Objects, MCP server, routes, DMARC/SPF/DKIM ingest), `shared/` Zod schemas, `hub/` threat-intel hub, `sidecar/` YARA scanner, `app/` SPA
**Commit:** main @ `281456c`
**Tool:** deep-security-scan · **Threshold:** low · **Run type:** full (no prior bundle — every confirmed finding reported)

---

## Severity summary

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 9 |
| Medium | 1 |
| Low | 2 |
| **Total confirmed** | **12** |

Every finding below passed an independent factual-verification (grounding) gate after validation, then a dedicated severity / attack-path stage (impact × reachability × preconditions) with a mechanical over-rating policy pass. Pipeline: **12 verified, 0 corrected, 0 rejected**; severity policy **{kept: 11, downgraded: 1, dropped: 0}**.

---

## Coverage statement

- **Deterministic prefilter:** SKIPPED — `foxguard` not installed. Its pattern-matchable classes were **not pre-swept** (0 candidates ingested from the prefilter).
- **Saturation discovery:** ran **4 of up to 4 rounds**; terminal state = **capped** (hit the round cap — this is NOT "saturated": a further round was not proven to add nothing, the run stopped because it reached the maximum number of rounds).
- **Breadth:** **5 lensed workers per round**, **20 worker passes total** (lenses + their threat models), **~423 file-reviews total**.
- **Candidates vs reported:** **36 unique candidates** after cumulative merge (0 from the prefilter) → **12 confirmed and reported**, the remainder suppressed to the appendix (refuted / needs-info / policy actions), so suppression is visible, not deleted.
- **Factual-verification gate:** 12 verified, 0 corrected, 0 rejected (none were factually wrong / suppressed as rejected).
- **Completeness:** **partial.**

**Not observed** (these classes WERE reviewed across the discovery lenses; no finding confirmed — this is "looked, found nothing," NOT "did not look"): sql-injection, xss, ssrf, idor, hardcoded-secret, vulnerable-dependency, weak-crypto, path-traversal, deserialization.

**Not scanned / limits** (these were NOT deeply reviewed — absence of findings here means nothing): vendored / generated code and lockfiles (dependency manifests noted for supply-chain only, not deep-reviewed); anything outside the stated audit scope; the deterministic prefilter's pattern classes (prefilter did not run).

---

## Findings

| # | Severity | Title | Location | Class |
| --- | --- | --- | --- | --- |
| 1 | High | OrgAgent cross-mailbox search bypasses per-mailbox ACL (tenant-isolation break) | `workers/agent/org-tools.ts:80` | missing-authz |
| 2 | High | Org/domain settings writes have no authorization beyond CF Access admittance | `workers/index.ts:820` | missing-authz |
| 3 | High | Crafted HTML entity in email body crashes the security pipeline → email delivered unscanned | `workers/security/classification.ts:152` | dos |
| 4 | High | TLS-RPT gzip decompression bomb OOMs the Worker (5MB cap checked after full materialization) | `workers/tlsrpt/parser.ts:49` | dos |
| 5 | High | Root cause: `decodeEntities` does not range-check code point before `String.fromCodePoint` | `shared/html-text.ts:48` | dos |
| 6 | High | Intel feed refresh reads network response body with no size cap (OOM via feed URL) | `workers/intel/feeds.ts:332` | dos |
| 7 | High | DMARC RUA XML tag-extractor is O(n²) on malformed input → CPU-exhaustion DoS | `workers/dmarc/parser.ts:126` | dos |
| 8 | High | Sybil self-invite defeats hub "contributors≥2" resistance → destroylist feed poisoning | `hub/src/routes/orgs.ts:100` | business-logic |
| 9 | High | OrgAgent `search_cases_across_mailboxes` returns per-email data across ALL mailboxes, no ACL | `workers/agent/org-tools.ts:93` | missing-authz |
| 10 | Medium | Deep-scan URL resolver buffers full attacker-controlled body (decompression bomb) | `workers/intel/url-resolver.ts:231` | dos |
| 11 | Low | DMARC RUF per-minute rate limit is a non-atomic count-then-insert (TOCTOU) | `workers/dmarc/ingest.ts:154` | race-condition |
| 12 | Low | Outbound send rate limit check-then-act gap allows exceeding 20/hr–100/day quota | `workers/durableObject/index.ts:855` | race-condition |

---

### 1. [High] OrgAgent cross-mailbox search bypasses per-mailbox ACL (tenant-isolation break / info disclosure)
- **Location:** `workers/agent/org-tools.ts:80` · **Class:** missing-authz · **Fingerprint:** `scf1:0a144e80204a1f78`
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
- **Source → Sink:** CF Access JWT (any admitted caller) via `/agents/org-agent/default` WS/HTTP → `search_cases_across_mailboxes` → `listMailboxes` + `stub.searchEmails` fan-out across ALL mailboxes.
- **Why:** `app.ts:139` runs the per-mailbox ACL gate only for `email-agent` paths; `emailAgentMailboxIdFromPath` returns null for `org-agent`, so the org agent reaches `OrgAgent` with no ACL check. `search_cases_across_mailboxes` fans out to every mailbox (incl. honeypots) and returns per-email id/sender/subject/verdict/score. The HTTP twin `/api/v1/org/search` enforces the boundary via `mailboxesForOrgSearch`/`callerInAcl`; the tool does not. A CF-Access-admitted analyst scoped OUT of a mailbox reads that mailbox's email metadata.
- **One-line fix:** Thread the verified CF-Access identity into `createOrgTools` and filter the fan-out through `mailboxesForOrgSearch`/`callerInAcl` (reuse the HTTP twin's logic) before searching; correct the misleading "aggregate data only" comments.

### 2. [High] Org/domain settings writes have no authorization beyond CF Access admittance
- **Location:** `workers/index.ts:820` · **Class:** missing-authz · **Fingerprint:** `scf1:dc27e4e433d52b2c`
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`
- **Source → Sink:** CF Access JWT (any admitted caller, incl. one scoped out of all mailboxes) + request body → `putDomainSettings`/`putOrgSettings` → `BUCKET.put(domains/<d>.json | org/settings.json)`.
- **Why:** PUT `/api/v1/domains/:domain/settings` (820), PUT `/api/v1/org/settings` (792), POST/DELETE `/api/v1/org/domains` (187/205) do no ACL/owner/role check. These tiers resolve (mailbox > domain > org) into the effective settings of mailboxes the caller has no ACL access to — including `agentSystemPrompt` (straight to the AI on chat + auto-draft) and `security.attachment_policy`. A scoped-out insider injects the AI system prompt or relaxes attachment handling for a denied mailbox.
- **One-line fix:** Gate these org/domain write endpoints with an org-admin group check (fail closed on missing email/group) or require the caller to hold ACL access to every mailbox inheriting the tier; consider WebAuthn step-up for these high-blast-radius writes.

### 3. [High] Crafted HTML entity in email body crashes the security pipeline, delivering the email completely unscanned
- **Location:** `workers/security/classification.ts:152` · **Class:** dos (impact: fail-open bypass) · **Fingerprint:** `scf1:aebfe6c1e99c90a9`
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`
- **Source → Sink:** inbound email HTML body → `bodyHtml` → `classifyEmail` → `htmlToPlainText` → `decodeEntities` → `String.fromCodePoint`.
- **Why:** `classifyEmail` calls `htmlToPlainText(input.bodyHtml)` at line 152, BEFORE its own try block (line 172). `decodeEntities` does `String.fromCodePoint(parseInt(...))` guarded only by `Number.isFinite`, so an out-of-range numeric reference (`&#x110000;`, `&#99999999;`) throws `RangeError`. The throw propagates through `measureAsync` (rethrows) out of `runSecurityPipeline`; `receiveEmail`'s outer catch logs and leaves `securityVerdict=null` — no verdict persisted, no quarantine, deep-scan skipped, message lands in INBOX unscanned. One appended token bypasses the entire phishing defense.
- **One-line fix:** Range-check the code point in `decodeEntities` (clamp invalid refs to U+FFFD); also move the `htmlToPlainText` call inside `classifyEmail`'s try and synthesize a fail-closed verdict when the pipeline throws.

### 4. [High] TLS-RPT gzip decompression bomb OOMs the Worker (5MB cap checked only after full materialization)
- **Location:** `workers/tlsrpt/parser.ts:49` · **Class:** dos · **Fingerprint:** `scf1:72ab5d6e50605c56`
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **Source → Sink:** inbound attachment `application/tlsrpt+gzip` / `*.tlsrpt.gz` → `gunzip: new Response(stream.pipeThrough(DecompressionStream)).arrayBuffer()`.
- **Why:** `gunzip()` fully materializes the decompressed body; the 5MB `TLSRPT_MAX_DECOMPRESSED_BYTES` cap is enforced only afterward (`ingest.ts:65`). A ~130KB gzip-of-zeros expands past the 128MB isolate limit before the check runs. `ingestTlsRptReport` runs unconditionally (no opt-in gate, unlike RUF), and `email()` re-throws so Cloudflare retries the same bomb. Deviates from the DMARC sibling, which reads incrementally and aborts mid-stream.
- **One-line fix:** Make `gunzip` accept a `maxBytes`, read the `DecompressionStream` chunk-by-chunk, and return null the instant the running total exceeds the cap (mirror `workers/dmarc/parser.ts`).

### 5. [High] Root cause: decodeEntities does not range-check the code point before String.fromCodePoint
- **Location:** `shared/html-text.ts:48` · **Class:** dos (impact: fail-open bypass) · **Fingerprint:** `scf1:5ac39340400c85f8`
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`
- **Source → Sink:** any HTML passed to `htmlToPlainText` → `String.fromCodePoint(code)` with only a `Number.isFinite(code)` guard.
- **Why:** For `&#xNN;`/`&#NN;` the parsed integer can exceed the valid Unicode range (0..0x10FFFF); `Number.isFinite` passes but `String.fromCodePoint` throws `RangeError`. This is the shared root cause behind finding #3 — every `htmlToPlainText` caller (classifier input, `stripHtmlToText`, compose utils) inherits a crash on attacker-controlled HTML; on the inbound classifier path it manifests as a security-pipeline fail-open.
- **One-line fix:** Replace `Number.isFinite(code)` with `Number.isInteger(code) && code >= 0 && code <= 0x10FFFF` on both hex and decimal branches, returning the literal match (or U+FFFD) otherwise.

### 6. [High] Intel feed refresh reads network response body with no size cap (OOM via teammate-editable feed URL)
- **Location:** `workers/intel/feeds.ts:332` · **Class:** dos · **Fingerprint:** `scf1:0c64854b1e888c73`
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H`
- **Source → Sink:** teammate/operator-configurable feed URL in mailbox/domain intel settings → `await res.text()` (unbounded) during cron `refreshFeed`.
- **Why:** `refreshFeed` fetches `feed.url` with only a 15s timeout, then `await res.text()` with no Content-Length or byte cap. The host allowlist gates only the auth secret, not the request; `refresh_hours:0` (or first run) forces a fetch every cron tick. A feed pointed at an attacker server returning a multi-GB (or gzip-bomb) body OOMs the shared cron isolate — an uncatchable termination that also kills the co-scheduled WebAuthn-challenge reap and honeypot reap, recurring every tick. Same pattern in `misp-client.ts:54` and `hub/src/lib/sync.ts:228`.
- **One-line fix:** Read `res.body` through a reader loop, abort past a hard byte cap, and reject early on oversized `content-length`; apply to the sibling sinks too.

### 7. [High] DMARC RUA XML tag-extractor is O(n²) on malformed input → CPU-exhaustion DoS (empirically confirmed)
- **Location:** `workers/dmarc/parser.ts:126` · **Class:** dos · **Fingerprint:** `scf1:cc31378661dde09e`
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **Source → Sink:** inbound DMARC-report XML (gzipped ≤5MB, or uncapped plain `.xml`) → `allTags(xml,'record')` regex `/<record\b[^>]*>([\s\S]*?)<\/record>/gi`.
- **Why:** The lazy-quantified regex driven by `matchAll` is quadratic on input with many unclosed `<record>` tags — each opening tag forces a full forward scan for a `</record>` that never appears. Measured: 900KB → 18.7s, 1.8MB → 76.5s single-threaded CPU. The gzip path allows ~4.9MB under the 5MB cap; the plain `.xml` branch has no cap at all (~25MB). Retry re-throw amplifies the burn.
- **One-line fix:** Add a small pre-parse XML size cap on both branches and replace the lazy-regex extractor with a linear split/scan bounded by `DMARC_MAX_RECORDS`.

### 8. [High] Sybil self-invite defeats hub "contributors≥2" resistance → arbitrary destroylist feed poisoning (DoS blocklisting)
- **Location:** `hub/src/routes/orgs.ts:100` · **Class:** business-logic · **Fingerprint:** `scf1:7d36a4a82cec50b0`
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:L`
- **Source → Sink:** authenticated org `POST /orgs/invite` → public `POST /orgs/accept` (self-minted sybil orgs) → `getPromotedForSharingGroup` → `GET /feeds/destroylist.txt` consumed by the main app.
- **Why:** `POST /orgs/invite` needs only any valid org key (no admin gate, no rate limit; membership check fires only when a sharing group is supplied), and `POST /orgs/accept` mints a fresh org at `trust=1.0`. One participant mints two independent orgs, posts the same attribute (e.g. `{type:'domain',value:'victim-bank.com'}`) to the NULL sharing group from each, reaching `contributor_count=2`/`score=2.0` — exactly the promotion threshold. The value is served on every consumer's destroylist and hard-blocks any chosen legitimate domain/URL fleet-wide.
- **One-line fix:** Gate `/orgs/invite` behind admin/existing-group membership (no null-group invites) + per-org quota, give new orgs probationary sub-1.0 trust, and exclude self-invited siblings (same invite lineage) from `contributor_count`.

### 9. [High] OrgAgent search_cases_across_mailboxes returns per-email data across ALL mailboxes with no ACL filtering
- **Location:** `workers/agent/org-tools.ts:93` · **Class:** missing-authz · **Fingerprint:** `scf1:107d341e18e9e4a6`
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
- **Source → Sink:** any CF-Access-admitted user via `/agents/org-agent/<name>` chat WS → `search_cases_across_mailboxes` → `listMailboxes` + per-mailbox `stub.searchEmails` returning sender/subject/verdict/score.
- **Why:** The OrgAgent WS route is deliberately excluded from the `app.ts` ACL gate on the false premise that OrgAgent "exposes only aggregate data." The tool returns each matching email's sender/subject/verdict/score across every mailbox with zero ACL filtering, while the parallel `/api/v1/org/search` filters the same fan-out through `mailboxesForOrgSearch`/`callerInAcl`. A teammate ACL-scoped OUT of a mailbox still reads its email metadata. (Same root gap as #1, viewed at the tool's `execute()` entry.)
- **One-line fix:** Capture `callerEmail`/`callerGroups` from the `cf-access-jwt-assertion` on the WS upgrade, pass into `createOrgTools`, and scope the fan-out via `readMailboxAcl` + `mailboxesForOrgSearch`; keep aggregate tools aggregate.

### 10. [Medium] Deep-scan URL resolver buffers full attacker-controlled response body (HTTP Content-Encoding decompression bomb) before truncating
- **Location:** `workers/intel/url-resolver.ts:231` · **Class:** dos · **Fingerprint:** `scf1:efb540276f96694f`
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
- **Source → Sink:** URL extracted from inbound email body → deep-scan `scanUrls` → `resolveUrl` final GET → `(await res.text()).slice(0, 200_000)`.
- **Why:** `res.text()` materializes the WHOLE body before the 200KB slice, and Workers fetch transparently decodes `Content-Encoding`, so a small gzip/br body that expands to hundreds of MB spikes isolate memory and can OOM (uncatchable) the fire-and-forget deep-scan and co-located work. The SSRF guard blocks only private IPs; the 8s timeout bounds time not bytes. Sibling ingest paths (DMARC/TLS-RPT/MTA-STS) all cap this; the most attacker-influenced fetch does not. Calibrated Medium (background `waitUntil` stage; Cloudflare auto-recovers isolates; availability-only).
- **One-line fix:** Stream `res.body` through a reader with a hard byte cap and cancel once exceeded (mirror `dmarc/parser.ts gunzip`); reject early on oversized `content-length`.

### 11. [Low] DMARC RUF per-minute rate limit is a non-atomic count-then-insert (TOCTOU)
- **Location:** `workers/dmarc/ingest.ts:154` · **Class:** race-condition · **Fingerprint:** `scf1:5ea3ac6e04528f36`
- **CVSS:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L`
- **Source → Sink:** concurrent inbound RUF emails to one mailbox → `countDmarcRufRecordsSince(...)` then `insertDmarcRufRecord(...)` across two DO RPCs with parse work between.
- **Why:** `RUF_RATE_LIMIT_PER_MINUTE` (100) is enforced by a count read then a separate insert, in independent Worker invocations with no transaction. A concurrent burst all observes `recentCount < 100` before any insert lands, admitting ~100+N rows/minute. Bounded: opt-in feature (default off), self-limiting per window, modest per-row storage — hence Low.
- **One-line fix:** Fold the count+insert into a single no-await DO method (conditional `INSERT ... SELECT ... WHERE (SELECT COUNT(*) ...) < :limit`) so the DO's single-threaded execution serializes the check-then-act.

### 12. [Low] Outbound send rate limit check-then-act gap allows exceeding 20/hr–100/day quota
- **Location:** `workers/durableObject/index.ts:855` · **Class:** race-condition · **Fingerprint:** `scf1:b61e394f5fff5b07`
- **CVSS:** n/a · **Policy:** calibrated Medium → **downgraded to Low** (anti-pattern: `internal-no-boundary`)
- **Source → Sink:** concurrent POST `/emails`, `/reply`, `/forward` for one mailbox → `checkSendRateLimit()` COUNT(*) then later `stub.createEmail(Folders.SENT,...)` with awaits (R2 stores) in between.
- **Why:** The check reserves nothing and is a separate DO RPC from the insert, so N concurrent authenticated sends all pass the same stale count and produce (start+N) real outbound emails, defeating the 20/hr–100/day anti-abuse throttle. Downgraded to Low: the attacker only amplifies an action they are already authorized to perform (send from any mailbox by documented design) — no privilege/trust boundary between principals is crossed, CF Access + provider-level throttle still hold; it is a missing atomic-reserve on a defense-in-depth quota, not a boundary breach.
- **One-line fix:** Add a single no-await DO method (`reserveSendSlotAndCreate`) that re-counts and inserts atomically, or an atomically-incremented rolling counter guarded inside the insert.

---

## Appendix — reviewed but NOT reported (suppression is visible, not deleted)

These were validated and then suppressed. "Refuted" = the exploit does not hold against the actual code; "needs-info" = a real gap remains but a decisive guard/deployment fact is unresolved; policy actions note the anti-pattern that fired. None of these are reportable findings.

| Title | Location | Disposition | Reason (short) |
| --- | --- | --- | --- |
| (placeholder test candidate) | `f:1` | refuted | No such file/finding; all fields were single-char placeholders — no source→sink path. |
| EmailAgent handleNewEmail trusts body mailboxId (confused-deputy) | `workers/agent/index.ts:319` | refuted | Internal caller pins mailboxId to the DO name; external `/agents/*` requests preserve the path prefix so the `/onNewEmail` guard never matches — sink unreachable. |
| Yaramail callback HMAC signs only body, not mailboxId path — cross-mailbox replay | `workers/routes/yaramail-callback.ts:64` | refuted | Replayed `emailId` (random UUID, mailbox-scoped) does not exist in another mailbox → no-op; forging a signature needs the shared secret. |
| Admin-token compare early-returns on length mismatch (timing leak) | `hub/src/lib/admin-auth.ts:31` | refuted | Only reveals secret length; sub-µs signal dominated by network jitter; does not reduce a high-entropy secret. |
| Confirm-token verification does not pin JWT algorithm | `workers/lib/confirm-token.ts:90` | refuted | jose rejects asymmetric/`none` against the symmetric key; all accepted algs need the secret; plus jti/bloom/replay binding. |
| Credential-bearing feed/hub outbound fetches omit `redirect: manual` | `workers/intel/feeds.ts:306` | refuted | Credential attached only to https host-allowlisted destinations; cross-origin Authorization stripping + platform private-IP block neutralize the redirect vector. |
| HTML-entity RangeError breaks reply/compose UI (client-side DoS) | `app/hooks/useComposeForm.ts:242` | refuted | Raw entity is consumed by `stripHtml`/escape before reaching the vulnerable decode; only a user typing it into their own editor (self-DoS) reaches it. |
| MTA-STS policy fetch reads unbounded body before 64KB cap | `workers/mta-sts/posture.ts:334` | refuted | `AbortSignal.timeout(1500)` aborts the read; per-request isolate isolation; non-amplified path — buffer-then-check is the accepted baseline. |
| Reference sidecar fetches attacker `presignedUrl`, no size limit / inbound auth | `sidecar/example/main.py:154` | refuted | Example/stub code with zero deployment artifacts; inbound validation explicitly deferred to network controls; not reachable in the deployed system. |
| Hub inbound MISP sync parses unbounded peer JSON per page | `hub/src/lib/sync.ts:228` | needs-info | 15s abort + graceful `.catch` + 4-min soft-lock bound it; only an uncatchable OOM evades; peers are admin-only. DoS from peer responses is out of the documented threat model — needs a deployment call. |
| Honeypot inbound rate-cap TOCTOU (overshoot under concurrency) | `workers/index.ts:1249` | refuted | Single DO serializes store-before-count; only the first `maxInbound` publish, count is monotonic — overshoot does not occur. |
| GET /acl returns owner+member list when JWT has no email | `workers/routes/acl-members.ts:37` | refuted | `requireMailbox`→`callerInAcl(null-email)` returns 403 in prod before the handler; unscoped mailbox returns 404 with no data. Fail-closed holds. |
| yaramail HMAC callback signs only body — path/replay unauthenticated | `workers/routes/yaramail-callback.ts:54` | refuted | Body immutable without secret; `applyYaraSignal` no-ops on absent `emailId`; score capped/monotonic/idempotent; only score column touched. |
| MCP draft tools omit `createdBy`, evading #266 agent tier bump | `workers/mcp/index.ts:244` | refuted | MCP requires verified JWT + ACL pass; every external send forces the HMAC confirm step-up regardless of provenance; only Tier1-vs-Tier2 step-up delta on a human-reviewed draft. |
| Org-wide config writable by any CF-Access-admitted caller | `workers/index.ts:187` | refuted | (Duplicate surface of #2 but framed as org-domains allowlist) — CF Access + schema validation; `org.domains` gates only own-domain catch-all intel, not sender trust; documented intentional single-org model. No system-defined boundary crossed. |
| yaramail sidecar dispatch POSTs to unvalidated teammate `endpoint_url` | `workers/security/yaramail-signal.ts:123` | refuted | Writing `endpoint_url` requires authenticated ACL member; request is blind (response discarded); operator-authored config, not attacker input; no metadata/internal target in the isolate. |
| url-resolver SSRF guard fails open / DNS-bypassable | `workers/intel/url-resolver.ts:143` | refuted | DoH fail-open + TOCTOU is real, but the Workers platform network-layer block on private subrequests is the backstop; no internal target; blind data flow (never echoed to sender). |
| Authenticated SSRF + response reflection in hub peer probe/sync | `hub/src/routes/admin.ts:140` | refuted | Only the `HUB_ADMIN_KEY` holder can set `base_url`; that principal already fully controls the hub admin surface; CF Workers fetch has no IMDS/private-network target. |
| SSRF (limited) in MTA-STS posture fetch on user-supplied domain | `workers/mta-sts/posture.ts:316` | needs-info | Domain regex fixes scheme/port/path; requires a provisioned mailbox + valid STSv1 TXT; response not reflected (blind). No private-IP resolve guard here (unlike url-resolver) — residual blind-SSRF needs a platform-block confirmation. |
| Redirect-chain SSRF guard is DoH-based (TOCTOU / rebinding) | `workers/intel/url-resolver.ts:185` | refuted | Even a successful rebind terminates at the platform private-destination block; guard fails open by design; result is blind (title only, capped) — no exfil channel. |
| Domain-scoped fan-out endpoints leak per-mailbox forensic/report data | `workers/index.ts:839` | refuted | Data is PII-redacted, double-opt-in, domain-scoped spoofing intel (not private correspondence); domain/org aggregation is the intended admitted-caller-wide operator surface. |
| yaramail callback HMAC binds only body, no replay protection | `workers/routes/yaramail-callback.ts:64` | refuted | HMAC-with-secret gate; email-existence + monotonic/capped/idempotent `applyYaraSignal`; no way to obtain a valid (body,signature) pair without the secret; TLS transport. |
| Any admitted user can lock down and seize every unscoped mailbox | `workers/index.ts:316` | refuted | `callerInAcl(null)`=all-access, so pre-lockdown the attacker already had full access; lockdown grants only ACL ownership vs equally-trusted teammates; audit + transfer paths exist. No higher tier crossed. |
| Hub inbound-sync soft lock is non-atomic (double-pull) | `hub/src/lib/sync.ts:327` | refuted | Soft lock written before I/O; platform-scheduled (no attacker trigger); `INSERT OR REPLACE`/`INSERT OR IGNORE` idempotency makes a fired race merely redundant fetches. |

---

*Interop artifacts embedded in `report.html` (base64, downloadable): `bundle.json` (sealed content-addressed bundle, issue #21), `results.sarif` (SARIF 2.1.0, fingerprints in `partialFingerprints`), and this `report.md`. Re-run later with `args.priorBundle` set to this run's `bundle.json` to get a per-release delta.*
