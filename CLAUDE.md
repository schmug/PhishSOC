# CLAUDE.md

This file is loaded into Claude Code sessions working on this repo. It captures
conventions surfaced by real incidents so future agents inherit the lesson
without re-discovering it. Keep entries grounded in observed events; this is a
seed, not a comprehensive style guide.

## Codebase map

| Folder | Purpose |
| --- | --- |
| `app/` | React 19 / React Router v7 SPA — routes, components, hooks, and client-side queries for the mailbox UI |
| `shared/` | Zod schemas and pure helpers shared by both the React app and Workers (mailbox/domain/org settings, folder constants) |
| `workers/` | All Cloudflare Workers backend code; see subsystems below |
| `hub/` | MISP-compatible community threat-intel hub — exposes a destroylist feed and admin UI for corroborated phishing reports |
| `sidecar/` | Stand-alone YARA attachment scanner sidecar Worker with its own `wrangler.jsonc`, package, and tests |
| `test/` | Vitest unit-test fixtures and per-subsystem test suites mirroring the `workers/` tree |
| `tests/` | Integration and frontend Vitest test suites (routes, intel, security, lib) |
| `docs/` | Developer and operator documentation (architecture notes, setup guides) |
| `public/` | Static assets served by the Worker (favicon, theme bootstrap script) |

### `workers/` subsystems

| Subsystem | Purpose |
| --- | --- |
| `workers/agent/` | `EmailAgent` and `OrgAgent` Durable Objects — AI chat agents with 9 email tools, auto-draft, and streaming responses |
| `workers/security/` | Synchronous security pipeline: SPF/DKIM/DMARC, URL heuristics, LLM classifier, sender reputation, off-hours scoring, and verdict aggregation |
| `workers/intel/` | Async deep-scan stage: redirect-chain resolution, RDAP domain age, CrowdSec CTI, Spamhaus DROP/EDROP CIDR, attachment heuristics, and threat-intel feed management |
| `workers/lib/` | Shared backend helpers: mailbox/domain/org settings resolution, attachment storage, email helpers, token handling, and schema definitions |
| `workers/routes/` | Hono sub-apps for scoped API routes: reply/forward, DMARC, TLS-RPT, cases, send-email, hub UI, ACL |
| `workers/durableObject/` | `MailboxDO` — per-mailbox Durable Object with SQLite schema/migrations and R2 attachment storage |
| `workers/mcp/` | `EmailMCP` — MCP server exposing email tools over HTTP so external AI clients (Claude Code, Cursor) can act on mailboxes |
| `workers/dmarc/` | DMARC aggregate-report ingest and RUF forensic-report ingest |
| `workers/spf/` | SPF TXT record fetch and posture scoring for the per-domain posture surface |
| `workers/dkim/` | DKIM public-key lookup and posture check for the per-domain posture surface |
| `workers/bimi/` | BIMI TXT record presence check for the per-domain posture surface |
| `workers/mta-sts/` | MTA-STS policy fetch and caching for the per-domain posture surface |
| `workers/tlsrpt/` | TLS-RPT posture check and aggregate-report ingest for the per-domain posture surface |
| `workers/db/` | SQLite schema definition and migration runner used by `MailboxDO` |
| `workers/app.ts` | Top-level Worker entry point: Cloudflare Access auth, Hono routing, cron handler, Durable Object exports |
| `workers/index.ts` | Core Hono API app: mailbox CRUD, email receive pipeline, settings endpoints, send-email handler |
| `workers/types.ts` | `Env` interface binding all Worker environment variables and Durable Object stubs |
| `workers/email-sender.ts` | Outbound email send helper wrapping the `send_email` binding |

## Conventions

### Security-scan findings go to a private GHSA, never a public PR or issue

**This repo is PUBLIC.** A security-audit report — the `file:line` + source→sink +
CVSS + one-line-fix output of `security-scan` / `deep-security-scan` /
`security-diff-scan`, or any hand-written finding — is an exploitation-ready
targeting package for whatever it documents. It must **never** land as:

- a committed `.security-scans/**` report on a branch that gets pushed (the
  branch diff is publicly viewable the moment it is pushed, PR or not),
- a public GitHub issue (this repo's `issues.opened` routine auto-implements
  **and merges** fixes from public issues within minutes — an uncoordinated
  partial fix that also advertises the bug), or
- a public PR body/title/test that spells out the attack.

Route every finding through the **`/ghsa` skill** into a private GitHub Security
Advisory draft (dedupe against existing advisories first — this repo already has
a substantial GHSA history). Develop the fix on a GHSA temporary private fork, or
via a fix PR whose title/body does **not** describe exploitation; link the fixing
PR + patched version on the advisory; publish (and request a CVE) only after the
fix is deployed — and only with explicit human confirmation.

This applies to **your own cloud/scheduled scan routines too**, not just bots:
if a routine produces findings, its sink must be a private GHSA, not a committed
report or a public PR. The `security-scan` family already writes its HTML+md
report locally — do not commit that report to this repo.

Origin: 2026-07-03. PR #565 (a cloud `deep-security-scan` run) published a
12-finding report — 9 High, unpatched, against `main @281456c` — as a public PR,
partly re-leaking findings already tracked in private GHSA drafts
(`GHSA-g3v6-6xph-3vx6`, `GHSA-vpmq-j44v-vjr6`). Bot PRs #562/#568 did the same
with a forged-`To:`-header harvest-alert bypass. Closed + branches deleted;
findings re-triaged into private advisories.

### URL host checks in test mocks must parse, not substring

When a test routes mock `fetch` responses by URL, do **not** match with
`url.startsWith("https://example.com")` or `url.includes("example.com")`.
CodeQL's `js/incomplete-url-substring-sanitization` rule (high severity) flags
those patterns as an SSRF / redirect-bypass risk even in test-only code, and
PRs are gated on CodeQL — the alert blocks merge.

Parse the URL and compare the parsed `hostname` instead:

```ts
// BAD
if (url.startsWith("https://cti.api.crowdsec.net")) { ... }

// GOOD
if (new URL(url).hostname === "cti.api.crowdsec.net") { ... }

// GOOD (host + path)
const u = new URL(url);
if (u.hostname === "cti.api.crowdsec.net" && u.pathname.startsWith("/v2/smoke/")) {
  ...
}
```

This applies to both mock dispatchers (deciding which canned response to
return) and assertions (`expect(call[0]).startsWith(...)` → use the parsed
equivalent).

Origin: PR #130 (CrowdSec CTI deep-scan) — five test-only URL substring checks
tripped CodeQL and required a fixup commit.

### Don't race a SECURITY_SPEC.md update against a parallel doc PR

`SECURITY_SPEC.md` codifies invariants the security pipeline enforces. When a
code change narrows or extends one of those invariants, the spec needs to
follow — but if both the code change and a separate spec-document PR are open
at the same time, editing the spec from inside the code PR guarantees a merge
conflict on whichever lands second.

Instead:

1. Land the code change first with the new behavior.
2. In that PR's body, note: `follows up: narrow SECURITY_SPEC.md Rule N once
   #<spec-PR-num> lands.`
3. After both predecessors are on `main`, file a small `docs:` PR doing the
   narrowing.

Origin: PR #132 (Closes #28) changed Rule 5's timeout-vs-parse-fail behavior,
deferred the spec edit to avoid racing PR #119 (which introduced the spec),
and PR #134 narrowed the rule once both had landed.

### `stripDefaultEqual` runs on every settings-tier write

Every endpoint that writes a settings tier — mailbox POST, mailbox PUT,
domain PUT, org PUT — must route the parsed payload through
`stripDefaultEqual(...)` from `workers/lib/mailbox-settings.ts` before
`BUCKET.put`. If you add a new tier or a new write endpoint targeting
`mailboxes/<id>.json`, `domains/<domain>.json`, or `org/settings.json`,
the strip pass is part of the contract — not optional.

```ts
// GOOD — every settings-tier write
const parsed = SomeSettings.safeParse(body?.settings ?? {});
if (!parsed.success) return c.json({ error: "..." }, 400);
const stripped = stripDefaultEqual(parsed.data);
await env.BUCKET.put(key, JSON.stringify(stripped));
```

Without it, a fresh form save with rendered defaults
(`agentModel: DEFAULT_AGENT_MODEL`, `autoDraft: { enabled: true }`)
persists those values as explicit overrides at the written tier,
silently shadowing every upstream tier forever — which defeats
absent-key-inherits semantics for the most common write path.

Hook scope: the PostToolUse stripDefaultEqual guard monitors endpoint files (`workers/index.ts`, `workers/routes/*`) and `workers/lib/mailbox-settings.ts` — NOT `workers/lib/org-settings.ts` or `workers/lib/domain-settings.ts`, because the strip happens at the endpoint layer, not inside those lib helpers (narrowed in PR #534 to eliminate false-positive blocks on the lib readers).

Origin: #106 acceptance criterion 6 originally read "PUT" only. PR #148
shipped with the strip on mailbox PUT but not on mailbox POST — caught
by advisor before merge and fixed in the same PR. PR #154 shipped with
the strip on mailbox POST/PUT but not on the new domain PUT — same
advisor catch, fixed before merge. The pattern is symmetric across
tiers; the rule is "every write," not "every PUT."

### Stacked PRs: `--delete-branch` on the predecessor auto-closes the dependent

This repo merges with `gh pr merge --squash --delete-branch` (the
convention every recent commit on `main` follows). When PR B is stacked
on PR A (B's `baseRefName` points at A's branch, not `main`), merging A
with `--delete-branch` deletes A's branch on the remote — and GitHub
auto-closes any open PR whose base branch was just deleted. PR B goes
to `state: CLOSED` even though its content is fine, and `gh pr reopen`
fails (`Could not open the pull request`).

Two ways to avoid it:

1. **Pre-flip the dependent's base back to `main` BEFORE merging the
   predecessor.** This keeps B open through the predecessor's merge.
   B will go `DIRTY` (because its history still contains A's pre-squash
   commit, and `main` now has the squashed version), so a fresh rebase
   is still needed before B can merge — but B stays open and you can
   force-push to the same branch.
2. **Drop the predecessor's pre-squash commit with `--onto`** when
   rebasing B against the new `main`:
   ```
   git rebase --onto origin/main <predecessor-pre-squash-sha>
   ```
   This is the cleanest way to re-base B; a plain `git rebase main`
   leaves the duplicate commit floating and produces conflicts against
   the squashed version on `main`.

If you forget step 1 and the dependent gets auto-closed, recovery is to
force-push the rebased branch and `gh pr create` a fresh PR (the closed
one cannot be reopened once its base ref is gone).

Origin: 2026-05-03 merge train. PR #162 (stacked on #159) was
auto-closed when #159's `--delete-branch` removed
`claude/issue-122-cron-runs`; recovered as PR #172. PR #163 (stacked on
#161) was pre-flipped to `main` ahead of #161's merge, then rebased
with `--onto origin/main 2c0e680` to drop the duplicated #149 commit
cleanly. Both landed without losing CI history.

### Single-issue routine: dedup gate — check for an open PR before creating one

Before any automated routine opens a PR for issue `<N>`, it must verify that no
open PR already references that issue. Without this guard a batch/cron run and a
per-issue `issues.opened` run can both find the same open issue and independently
ship competing PRs.

Add the following two checks to the **Early-exit gate**, after the `state` check,
and exit silently (no comment, no commit) if either returns a non-empty result:

```
# 1. Branch-pattern match — open PRs whose head already targets this issue
mcp__github__list_pull_requests: owner=schmug repo=PhishSOC state=open
  → filter results for head.ref matching "claude/issue-<N>-" prefix
  → exit silently if any match

# 2. Body / title reference match — open PRs that close/fix the issue
mcp__github__search_pull_requests: "repo:schmug/PhishSOC is:pr is:open closes #<N>"
  → exit silently if any match
```

Both checks are required. The branch-pattern check misses PRs opened by sessions
that used random `claude/friendly-sagan-*` branches (e.g. issue #384 was handled by
a first-wave session on `claude/friendly-sagan-uOn28`); the body-reference check
catches those. The branch-pattern check catches PRs opened by sessions that did not
embed `Closes #<N>` verbatim.

**Root cause of 2026-06-01 double-fire (issue #403):**

Two routine types ran concurrently on the same open DMARC-epic issues with no
idempotency check between them:

| Wave | Type | Session | Issues | PRs |
|------|------|---------|--------|-----|
| First (11:04–11:12 UTC) | Per-issue `issues.opened` sessions | multiple | #379–#387 | #388–#396 |
| Second (11:22–12:03 UTC) | Single batch/cron session | `01Uqvt1cBFXbAdxSb2MNz2Kh` | #379–#384, #387 | #397–#401 |

The batch session started ~13 minutes after the first wave, when first-wave PRs were
open but not yet merged. It iterated through the same open issues and opened five
duplicate PRs; one of them (#399 for issue #387) was opened 26 minutes after the
first-wave PR (#393) had already merged.

**Where the routines live:** The per-issue routine is a Claude Code web session
triggered by `issues.opened` events on `schmug/PhishSOC`, configured in the
claude.ai session UI (external to this repo). The batch routine is a separate
scheduled/cron claude.ai session. Both must apply the dedup gate above; this
CLAUDE.md entry is the spec for that update.

Origin: Issue #403 (2026-06-01). Six duplicate PRs had to be closed; five surviving
PRs were rebased and merged one-by-one through a manual merge train.
