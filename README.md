[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/schmug/PhishSOC)
<div align="center">
  <h1>PhishSOC</h1>
  <p><em>A phishing-aware email SOC on Cloudflare Workers — full mailbox UI, AI triage agent, and a real-time SPF/DKIM/DMARC + URL/RDAP scoring pipeline.</em></p>
</div>

PhishSOC is a self-hosted phishing-detection layer wrapped around a complete Cloudflare-native email client. Mail arrives via [Cloudflare Email Routing](https://developers.cloudflare.com/email-routing/), each mailbox is isolated in its own [Durable Object](https://developers.cloudflare.com/durable-objects/) with a SQLite database, and attachments are stored in [R2](https://developers.cloudflare.com/r2/). When the security pipeline is enabled per mailbox, every inbound message is scored — SPF/DKIM/DMARC parse, URL/homograph heuristics, an LLM classifier, threat-intel feed matching, and an async deep-scan stage (redirect-chain resolution, RDAP domain age, attachment checks) — before it ever reaches the inbox.

An **AI agent** runs alongside the inbox: it reads incoming mail, auto-drafts replies (always requiring explicit send-confirmation), and exposes 9 agent tools in-app and 13 tools over [MCP](https://modelcontextprotocol.io/) so external clients like Claude Code or Cursor can act on any mailbox. Built with the [Cloudflare Agents SDK](https://developers.cloudflare.com/agents/) and [Workers AI](https://developers.cloudflare.com/workers-ai/).

![PhishSOC screenshot](./docs/img/demo_app.webp)


Read the blog post to learn more about Cloudflare Email Service and how to use it with the Agents SDK, MCP, and from the Wrangler CLI: [Email for Agents](https://blog.cloudflare.com/email-for-agents/).

For a folder-by-folder orientation of the repo, see the [Codebase map](./CLAUDE.md#codebase-map) in CLAUDE.md.

## How to setup

**Important**: Clicking the 'Deploy to Cloudflare' button is only one part of the setup. You must follow the **After deploying** steps as well. For a full step-by-step guide with screenshots, refer to the upstream setup walkthrough — its deploy/Email-Routing/Access steps still apply to PhishSOC: 
https://github.com/cloudflare/agentic-inbox/issues/4#issuecomment-4269118513

### To set up

1. Deploy to Cloudflare. The deploy flow will automatically provision R2, Durable Objects, and Workers AI. You'll be prompted for **DOMAINS** -- your domain(s) with Email Routing enabled. Comma-separated for multi-domain (e.g. `example.com` or `a.example,b.example`).

     [![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/schmug/PhishSOC)

2. **Configure Cloudflare Access** -- Enable [one-click Cloudflare Access](https://developers.cloudflare.com/changelog/post/2025-10-03-one-click-access-for-workers/) on your Worker under Settings > Domains & Routes. The modal will show your `POLICY_AUD` and `TEAM_DOMAIN` values. `TEAM_DOMAIN` can be either your Access team URL or the full `.../cdn-cgi/access/certs` URL. **You must set these as secrets for your Worker.**
3. **Set up Email Routing** -- In the Cloudflare dashboard, go to your domain > Email Routing and create a catch-all rule that forwards to this Worker
4. **Enable Email Service** -- The worker needs the `send_email` binding to send outbound emails. See [Email Service docs](https://developers.cloudflare.com/email-routing/email-workers/send-email-workers/)
5. **Create a mailbox** -- Visit your deployed app and create a mailbox for any address on your domain (e.g. `hello@example.com`)

### Troubleshooting Access

1. If you see `Invalid or expired Access token`, that usually means `POLICY_AUD` or `TEAM_DOMAIN` secrets are incorrect.
   * Resolution: [turn Access off and back on for the Worker to get the Access modal again](https://developers.cloudflare.com/changelog/post/2025-10-03-one-click-access-for-workers/), then reset your Worker secrets to the latest `POLICY_AUD` and `TEAM_DOMAIN` values shown there.
2. If you see `Cloudflare Access must be configured in production`, this application is intentionally enforcing Cloudflare Access so your inbox is not exposed to anyone on the internet.
   * Resolution: enable Access using [one-click Cloudflare Access for Workers](https://developers.cloudflare.com/changelog/post/2025-10-03-one-click-access-for-workers/), then set the `POLICY_AUD` and `TEAM_DOMAIN` Worker secrets from the modal values.

## Features

- **Full email client** — Send and receive emails via Cloudflare Email Routing with a rich text composer, reply/forward threading, folder organization, search, and attachments
- **Per-mailbox isolation** — Each mailbox runs in its own Durable Object with SQLite storage and R2 for attachments
- **Built-in AI agent** — Side panel with 9 agent tools for reading, searching, drafting, and sending
- **MCP server** — 13 tools at `/mcp` so external AI clients (Claude Code, Cursor) can act on any mailbox
- **Auto-draft on new email** — Agent automatically reads inbound emails and generates draft replies, always requiring explicit confirmation before sending
- **Configurable and persistent** — Custom system prompts per mailbox, persistent chat history, streaming markdown responses, and tool call visibility
- **Security pipeline** — Opt-in SPF/DKIM/DMARC parsing, URL homograph detection, LLM classifier, sender reputation, threat-intel feed matching, and async deep-scan (redirect-chain resolution, RDAP domain age, attachment heuristics). See [Security](#security) below

## Stack

- **Frontend:** React 19, React Router v7, Tailwind CSS, Zustand, TipTap, `@cloudflare/kumo`
- **Backend:** Hono, Cloudflare Workers, Durable Objects (SQLite), R2, Email Routing
- **AI Agent:** Cloudflare Agents SDK (`AIChatAgent`), AI SDK v6, Workers AI (`@cf/moonshotai/kimi-k2.5`), `react-markdown` + `remark-gfm`
- **Auth:** Cloudflare Access JWT validation (required outside local development)

## Getting Started

```bash
npm install
npm run dev
```

By default the dev server runs with all bindings local-only — no Cloudflare Access service token is required. The Worker's `send_email` binding becomes a local no-op, which is fine for UI work and most backend iteration.

### Optional: enable remote bindings locally

If you have Cloudflare Access service-token credentials for the deployed Worker and want `send_email` (or future remote bindings) to route to it, install [direnv](https://direnv.net/) and create a gitignored `.envrc` at the repo root:

```bash
# .envrc — DO NOT COMMIT (already in .gitignore)
export CLOUDFLARE_ACCESS_CLIENT_ID=<your token>.access
export CLOUDFLARE_ACCESS_CLIENT_SECRET=<your secret>
```

Then `direnv allow .`. Vite will detect the creds at startup and enable the remote-binding proxy. Without these vars set, `vite.config.ts` passes `remoteBindings: false` so the dev server boots cleanly.

### Configuration

1. Set your domain(s) in `wrangler.jsonc` — `DOMAINS` is comma-separated, e.g. `"a.example,b.example"`
2. Create an R2 bucket named `agentic-inbox`: `wrangler r2 bucket create agentic-inbox`
3. Create the threat-intel KV namespace and paste the returned ID into `wrangler.jsonc` (replace `REPLACE_WITH_KV_NAMESPACE_ID`):

   ```bash
   wrangler kv namespace create BLOOM_KV
   wrangler kv namespace create BLOOM_KV --preview
   ```

### Deploy

```bash
npm run deploy
```

### Two-domain end-to-end test

To exercise both inbound and outbound on independent domains (useful for validating the full security pipeline):

1. Add both domains to `DOMAINS`, e.g. `"cortech.online,dmarc.mx"`.
2. In the Cloudflare dashboard, enable **Email Routing** on each domain and add a catch-all rule that forwards to this Worker.
3. Verify each domain (or specific MAIL FROM addresses) under **Email → Email Service** so the `send_email` binding can send "from" either domain. See the [Email Service docs](https://developers.cloudflare.com/email-service/).
4. Create one mailbox per domain in the app (e.g. `inbox@cortech.online`, `inbox@dmarc.mx`).
5. Send a message from mailbox A → mailbox B. The roundtrip exercises: outbound `send_email`, inbound Email Routing, security pipeline scoring, agent auto-draft, and reply send.
6. Recommended: turn the **security pipeline** on for at least one mailbox and populate **Trusted authentication servers** with `mx.cloudflare.net` (Settings → Security) before testing.

## Prerequisites

- Cloudflare account with a domain
- [Email Routing](https://developers.cloudflare.com/email-routing/) enabled for receiving
- [Email Service](https://developers.cloudflare.com/email-service/) enabled for sending
- [Workers AI](https://developers.cloudflare.com/workers-ai/) enabled (for the agent)
- [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/) configured for deployed/shared environments (required in production)

Any user who passes the shared Cloudflare Access policy can access all mailboxes in this app by design. This includes the MCP server at `/mcp` -- external AI tools (Claude Code, Cursor, etc.) connected via MCP can operate on any mailbox by passing a `mailboxId` parameter. There is no per-mailbox authorization; the Cloudflare Access policy is the single trust boundary.

## Security

See also: [SECURITY_SPEC.md](./SECURITY_SPEC.md) — "Rules for Agent-Safe Email Pipelines", a vendor-neutral codification of the prompt-injection and async-pipeline invariants this codebase ships.

The security pipeline is **opt-in per mailbox** — existing mailboxes are unaffected until you flip the toggle in **Settings → Security**. When enabled, every inbound email runs through a synchronous scoring pipeline (SPF/DKIM/DMARC parse → URL heuristics → LLM classifier → sender reputation → threat-intel feed match → aggregate verdict), then an async deep-scan stage layered on top.

### Recommended configuration after enabling

These two settings are the high-leverage ones. Both live in **Settings → Security**; both are empty by default for back-compat.

#### 1. Trusted authentication servers

Sets which `Authentication-Results` headers are trusted when computing the SPF/DKIM/DMARC verdict. Without this list populated, an attacker-controlled upstream mail server can inject a forged `Authentication-Results: attacker.example; spf=pass; dkim=pass; dmarc=pass` header and the parser will accept it.

Populate with the authserv-id(s) that actually sit on your mail path. For a typical Cloudflare-routed setup:

```
mx.cloudflare.net
```

If your mail traverses a Google/Microsoft forwarder before Cloudflare, add those too (suffix match is supported — `google.com` covers `mx1.google.com`, `mx5.google.com`, etc.):

```
mx.cloudflare.net, google.com, outlook.com
```

#### 2. Business hours

Optional. When enabled, mail delivered outside your working hours gets a small score nudge (+10) — BEC / wire-fraud requests disproportionately land at 3 AM and on weekends. The nudge can push a borderline verdict over the tag/quarantine threshold; it can never single-handedly quarantine an email on time alone (the triage layer deliberately ignores the signal for explicit allowlists and trusted history).

Takes an IANA timezone plus an hour window:

```
Timezone: America/New_York
Start:    09
End:      18  (exclusive — 18:00 itself is off-hours)
Weekends: flagged when weekdays_only is on
```

### Pipeline stages

| Stage | Latency | Notes |
| --- | --- | --- |
| Auth header parse | µs | SPF/DKIM/DMARC from `Authentication-Results`; gated by trusted authserv-ids |
| URL extract + homograph/shortener check | ms | Levenshtein vs a high-value-domain list |
| Sender reputation | ms | Rolling avg score per mailbox; flagged-sender fast path |
| Threat-intel bloom lookup | ms | Against [workers/intel/feeds.ts](workers/intel/feeds.ts) (URLhaus, PhishDestroy, configurable; Spamhaus DROP/EDROP CIDR feeds consumed in deep-scan) |
| Triage short-circuits | µs | Hard-block on confirmed intel / flagged sender; hard-allow on DMARC pass + allowlist or trusted history |
| LLM classifier | seconds (5s cap) | Workers AI; timeout → contributes 0 to score (skipped); parse/other error → fail-closed to `suspicious` (see [SECURITY_SPEC.md Rule 5](SECURITY_SPEC.md)) |
| Verdict aggregation | µs | Pure scoring function; thresholds configurable per mailbox |
| Off-hours boost | µs | Optional, scoring-only |
| **Async deep-scan** | seconds–tens-of-seconds | `ctx.waitUntil`; see below |

### Async deep-scan

Fires after the sync verdict is stored and only ever *tightens* the decision (sync `allow` → deep-scan `quarantine` is fine; reverse is not). Contribution capped at `+40` so it can't dominate the sync signal.

- **Redirect-chain resolution** — follows `bit.ly`-style wrappers up to 5 hops so downstream checks see the real destination.
- **RDAP domain age** — queries `rdap.org` for registration date. Domains <7d get +20, <30d get +10. Fails silently on flaky RDAP servers.
- **CrowdSec CTI enrichment** — *optional, async-only*. When `CROWDSEC_CTI_API_KEY` is set, redirect-target hostnames are resolved via DoH (`cloudflare-dns.com`) and each unique IP is looked up against [CrowdSec CTI](https://docs.crowdsec.net/u/cti_api/intro). Signals: `behaviors` matching `phishing`/`exploit` (+25), `reputation=malicious` (+15), `reputation=suspicious` or `classifications` containing `tor`/`vpn:public`/`data_center` (+10). Capped at +25 per inbound. Responses cached in `BLOOM_KV` for 12h (1h for 404s); 429 rate-limits return `null` without poisoning the cache. Free-tier CTI is rate-limited, so this stage **never runs on the synchronous receive path**. Set the secret with `wrangler secret put CROWDSEC_CTI_API_KEY`; deploys without it just no-op the stage.
- **Spamhaus DROP / EDROP** — *no-auth IP feed*. The cron refresher pulls [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt) and [EDROP](https://www.spamhaus.org/drop/edrop.txt) every 12h and stores the parsed CIDR list in `BLOOM_KV`. In deep-scan, every redirect-target hostname is resolved via DoH and each unique IP is checked for membership against the DROP/EDROP CIDR set; a match adds +20 (capped at +25 per inbound) and a `redirect target IP <ip> (<cidr>) on Spamhaus DROP` reason. CIDR membership is implemented as a linear scan with IPv4-as-uint32 masking (the lists are small — a few thousand entries — so no index is needed). DoH resolution is shared with the CrowdSec CTI stage so we don't double-spend DNS queries; deploys without DROP feeds and without a CTI key skip DoH entirely.
- **CrowdSec community blocklist** — *operator-configured IP feed*. Same `ip-cidr` ingest path as DROP/EDROP, scoped to redirect targets only (the signal is strong on attacker infra, weak on sending MTA IPs). Registered as a default feed with id `crowdsec-community` but ships with an empty URL because there is no public no-auth download endpoint; operators wire it up via mailbox settings (`intel.feeds`) by setting their CrowdSec Console blocklist URL plus an `auth_secret` referencing a Worker secret containing the API key. Once configured, a match contributes the same +20 IP-feed weight and a `redirect target IP <ip> (<cidr>) on CrowdSec Community Blocklist` reason.
- **Attachment heuristics** — dangerous extensions, macro-enabled Office, `.pdf.exe`-style double extensions, MIME/extension mismatches, archives that advertise a payload in the filename.

### Threat-intel hub

The [`hub/`](hub/) subdirectory is a MISP-compatible community threat-intel hub — mailboxes can push phishing reports (`workers/intel/report.ts`) and pull corroborated lists back via the destroylist feed. Trust-weighted so one org can't single-handedly promote its own intel.

### Domain posture surfaces

The per-domain page (`/domains/:domain`) surfaces published email-auth posture alongside threat verdicts. Today it shows:

- DMARC apex policy + alignment rate.
- **MTA-STS** mode/mx/max_age (`_mta-sts.<domain>` TXT + `https://mta-sts.<domain>/.well-known/mta-sts.txt`, cached in KV by policy `id` so a roll auto-invalidates).
- **BIMI** record presence (`default._bimi.<domain>` TXT — surfaces "configured / configured-with-VMC / not configured / unavailable"; does NOT fetch the SVG logo or VMC certificate).
- **SPF** posture (`<domain>` TXT for `v=spf1 …` — surfaces mechanism count, `all` qualifier, include count, and a bounded include-chain resolver that flags records exceeding RFC 7208 §4.6.4's 10-DNS-lookup ceiling).
- **TLS-RPT** posture (`_smtp._tls.<domain>` TXT for `v=TLSRPTv1` — surfaces "TLS reporting configured: yes / no" plus the parsed `rua=` endpoint URLs; posture-only, does NOT ingest inbound TLS-RPT reports here).

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Browser    │────>│  Hono Worker     │────>│  MailboxDO      │
│  React SPA   │     │  (API + SSR)     │     │  (SQLite + R2)  │
│  Agent Panel │     │                  │     └─────────────────┘
└──────┬───────┘     │  /agents/* ──────┼────>┌─────────────────┐
       │             │                  │     │  EmailAgent DO  │
       │ WebSocket   │                  │     │  (AIChatAgent)  │
       └─────────────┤                  │     │  9 email tools  │
                     │                  │────>│  Workers AI     │
                     └──────────────────┘     └─────────────────┘
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the fork→branch→PR flow, how to run tests, commit-format rules, and DCO sign-off requirement.

## License

Apache 2.0 -- see [LICENSE](LICENSE).
