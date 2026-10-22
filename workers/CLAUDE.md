# workers/ — Hono on Cloudflare Workers

Additive to root CLAUDE.md. Workers-specific conventions only.

## Scoped commands

Run from the **repo root** (Workers tests live in root `test/` and `tests/`):

```bash
npm test           # vitest run — workers + frontend
npm run typecheck  # cf-typegen + react-router typegen + tsc -b
```

## Runtime invariants

- **Workers runtime only.** No `node:` imports, no `Buffer`, no `process.env`. Use `crypto.subtle`, `Response`, `ReadableStream` from the Workers global scope.
- **MTA-STS fetches must include `redirect: "manual"`.** Any `fetch()` of a policy URL in `workers/mta-sts/` must pass `redirect: "manual"` or the security pipeline is bypassed. Covered by root CLAUDE.md Rule 3.
- **Every settings-tier write runs `stripDefaultEqual`.** See root CLAUDE.md for the full rule. Applies to `mailboxes/<id>.json`, `domains/<domain>.json`, and `org/settings.json` writes.

## Code layout

- **`workers/app.ts`** — main Worker export. Wires the Hono API (`workers/index.ts`), React Router SSR, `EmailAgent`/`EmailMCP` DO exports, `email()` inbound handler, and `scheduled()` cron handler.
- **`workers/index.ts`** — Hono router for all `/api/v1/` endpoints. New API routes go here.
- **`workers/durableObject/`** — `MailboxDO`: per-mailbox Durable Object with SQLite (drizzle), R2 attachment refs, ACL, sender-graph, and verdict store. Schema changes require a new migration in `workers/durableObject/migrations.ts`.
- **`workers/agent/`** — `EmailAgent` (per-mailbox AI agent via Cloudflare Agents SDK) and `OrgAgent` (org-wide agent).
- **`workers/mcp/`** — `EmailMCP`: Model Context Protocol server exposing 13 mailbox tools over Streamable HTTP at `/mcp`, behind Cloudflare Access.
- **`workers/security/`** — Synchronous security pipeline (SPF/DKIM/DMARC parse → sender reputation → URL heuristics → LLM classification → verdict). Runs inline during `receiveEmail()`.
- **`workers/intel/`** — Threat-intel layer: bloom-filter feed lookups, async deep-scan (URL fetch + RDAP), CrowdSec CTI, MISP corroboration, hub reporting.
- **`workers/lib/`** — Shared helpers: mailbox/domain/org settings resolvers, attachment storage, email helpers, ACL, AI wrappers, confirm tokens.
- **`workers/db/`** — Drizzle schema for the DO's SQLite.
- **`workers/routes/`** — Thin Hono route handlers extracted from `index.ts`: ACL members, cases, reply/forward, send-email, DMARC/TLSRPT ingest, hub-ui proxy, yaramail callback, confirm.
- **`workers/dmarc/`** — DMARC record parsing, RUA/RUF ingestion, and posture checks.
- **`workers/dkim/`** — DKIM record lookup and posture scoring.
- **`workers/spf/`** — SPF record lookup and posture scoring.
- **`workers/bimi/`** — BIMI record lookup and posture checks.
- **`workers/tlsrpt/`** — TLSRPT report ingestion and parsing.
- **`workers/mta-sts/`** — MTA-STS policy fetch and posture check (always `redirect: "manual"`).
- **`workers/email-sender.ts`** — Outbound email via the Cloudflare Email Service `send_email` binding (`EMAIL`).
- **`workers/types.ts`** — `Env` interface shared across all workers files.
