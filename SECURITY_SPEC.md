# Rules for Agent-Safe Email Pipelines

A small, opinionated spec for teams building LLM-driven email pipelines on top
of attacker-controlled content. Distilled from the invariants we run in
production in PhishSOC; vendor-neutral so any team can adopt them.

This document codifies six rules. Each rule states the invariant in
abstract terms, the attack class it prevents, and the concrete enforcement
point in this repository (with stable function-level anchors so the
citations survive line drift).

The list is closed: it describes the floor, not the ceiling. Adding new
invariants is out of scope for this document.

---

## Rule 1 — LLM output is non-load-bearing

> Any LLM stage in the pipeline must be allowed to mutate **only** fields
> that downstream consumers treat as advisory. An LLM may suggest a tag, a
> summary, a category, a draft. It must not directly mutate scores,
> verdicts, sharing scope, promotion state, queue priority, or any field
> that can change a security or routing decision.

### What it prevents

Prompt injection. An attacker who can write the email body (or any
LLM-visible field — subject, sender display name, attachment text, an HTML
`alt` attribute) can, with high reliability, talk an LLM into emitting any
output the attacker wants. If that output is *consumed as policy*, the
attacker has just escalated from "person who can send mail" to "person who
can rewrite your security verdict." If LLM output is consumed as *hints*,
the attacker only gets to influence labelling, which is corrected by other
signals.

The right framing: assume every LLM in your pipeline is partially
attacker-controlled. Design downstream consumers accordingly.

### How PhishSOC enforces this

The MISP-compatible community hub runs a triage LLM against each new
event. Its outputs are restricted by code path, not by prompt:

- `hub/src/agent/triage.ts` — `triageEvent` (lines 36-76). The LLM call
  generates a `tags` array. The function's only side effects are
  `INSERT OR IGNORE INTO tags` and `INSERT OR IGNORE INTO event_tags`. It
  cannot write to `events`, `corroboration`, `orgs.trust`, or anything
  promotion-related.
- The contract is documented at the file head (lines 5-13) and again in
  `hub/README.md` under "Agent triage".
- Score aggregation and destroylist promotion live in
  `hub/src/lib/aggregate.ts`, on a code path the triage agent never calls.

A reviewer auditing this rule should be able to grep for every `env.AI.run`
in the hub and verify, for each, that the surrounding function only writes
to advisory tables.

---

## Rule 2 — Downstream stages only tighten verdicts

> Once a synchronous decision has been made and the user (or downstream
> consumer) may have observed it, asynchronous stages may *upgrade* the
> verdict in the safer direction (allow → tag → quarantine → block) but
> **never** in the riskier direction. No async stage may de-escalate.

### What it prevents

Async-window confusion attacks and inconsistent UI state. If sync says
`quarantine` and an async stage flips it back to `allow` ten seconds later,
the user has either already seen a warning that vanished (confusing), or
worse, the async stage is now an attacker-reachable surface for unblocking
mail. Monotonicity in the safer direction is the only consistent model:
once we've decided to be cautious, no later signal can talk us out of it.

### How PhishSOC enforces this

- `workers/intel/deep-scan.ts` — `runDeepScan` (lines 66-128). Score is
  read from the stored sync verdict, the deep-scan delta is added (never
  subtracted), and the action is only persisted if `tierIndex(newAction) >
  tierIndex(baseVerdict.action)` (line 102, helper at lines 279-286).
- The intent is captured at the file head, lines 16-20: "If the combined
  deep-scan signals push the verdict across a higher threshold ... we
  upgrade ... We never DOWNgrade."
- The folder move at line 120 only fires for `quarantine`/`block` upgrades,
  never the reverse.

---

## Rule 3 — Authentication-Results requires a trusted-authserv allowlist

> Any parser that consumes `Authentication-Results` (RFC 8601) headers
> must, by default, reject results from authserv-ids the operator has not
> explicitly trusted. The header is unauthenticated by design — its
> trustworthiness is a function of *who wrote it*, and that's the
> operator's call, not the email's.

### What it prevents

Forged `Authentication-Results`. An attacker who runs their own mail
server can prepend (or substitute) a header like:

```
Authentication-Results: attacker.example;
  spf=pass smtp.mailfrom=victim.com;
  dkim=pass header.d=victim.com;
  dmarc=pass header.from=victim.com
```

A naive parser that takes the first SPF/DKIM/DMARC verdict it sees
without checking the authserv-id will treat this as a fully-authenticated
message from `victim.com`. The fix is RFC 8601 §5: validate the
authserv-id against a list of MTAs you actually trust.

The default must be deny. Trusting any header is back-compat for the
unconfigured case; in production it is a vulnerability waiting to be
discovered.

### How PhishSOC enforces this

- `workers/security/auth.ts` — `parseAuthResults`. The authserv-id allowlist
  is read at `auth.ts:141-142` (`gating = trusted.length > 0`); when gating is
  on, the per-header loop skips every header whose authserv-id is missing or
  not on the list (suffix-aware via `matchesTrusted`, `auth.ts:117-123`).
- `AuthVerdict.trusted` (`auth.ts:47`) is set **only when an
  operator-configured authserv-id actually matched** — `auth.ts:161`:
  `if (gating && !verdict.trusted) verdict.trusted = true`. With an empty list
  (the back-compat default) the SPF/DKIM/DMARC results are still parsed so
  scoring keeps working, but `trusted` stays false: an unconfigured deployment
  never treats a header as authserv-trusted.
- **Load-bearing enforcement.** The `hard_allow` short-circuit
  (`evaluateHardAllow`, `triage.ts:189-198`) requires `auth.trusted` in
  addition to `dmarc === "pass"`. A forged `Authentication-Results` header on
  a deployment with no `trusted_authserv_ids` configured therefore cannot
  reach the allow short-circuit and skip the classifier + downstream intel.
  (Hardened in PR #369 / advisory GHSA-j644-r34r-2m9j.)
- The threat model is documented at the head of `auth.ts`. PhishSOC ships with
  the list empty for back-compat; the README under "Trusted authentication
  servers" tells operators to populate it so the *score contribution* is also
  treated as load-bearing.

> Followup worth tracking: PR #369 made the **load-bearing** paths
> default-deny — the `trusted` flag and the `hard_allow` gate no longer trust
> an unconfigured deployment. What remains back-compat is the **scoring**
> contribution: with an empty list, parsed results still feed the score (just
> not the trust flag). Flipping that scoring default to deny is the remaining
> optional step.

---

## Rule 4 — Cap the contribution of any single LLM or async stage

> No single LLM call, no single async signal, no single intel feed should
> be able to push a verdict from `allow` past `quarantine` on its own.
> Score contributions from any one stage must be capped below the
> threshold gap, so that a quarantine decision always reflects at least
> two independent signals.

### What it prevents

Single-source compromise. If your LLM hallucinates, your RDAP server
gets MITM'd, your bloom filter gets a false positive, or your threat-intel
feed gets poisoned upstream, the blast radius is bounded. The verdict
moves a bit; it doesn't flip end-to-end on one bad signal.

This is also a defense against an attacker who *targets* one stage. If
the attacker can make your LLM output `phishing` for a benign message
(harassment via mass false-positive), they can degrade UX. If that single
output could quarantine on its own, they can also DoS legitimate mail.

### How PhishSOC enforces this

- `workers/intel/deep-scan.ts:64` — `DEEP_SCAN_MAX_ADD = 40`, applied at
  line 96: `added = Math.min(DEEP_SCAN_MAX_ADD, added)`. Deep-scan signals
  combined cannot add more than 40 to the sync score, so they cannot
  single-handedly cross the default `tag → quarantine` gap when sync said
  `allow`.
- `workers/security/auth.ts` — `scoreAuth` (lines 134-141). Auth signals
  cap at 30 even if every method failed. (`if (score > 30) score = 30`,
  line 140 — the cap intentionally lives below the quarantine threshold.)
- The classifier's own contribution is bounded by enum (Rule 1) and by
  confidence-scaling — `scoreClassification` in
  `workers/security/classification.ts` (lines 136-148) tops out at ~50 for
  a max-confidence `phishing` label; combined with auth cap and other
  signals, no single stage hits quarantine alone under default thresholds.

The principle: *thresholds are budgets*. Every stage spends from a budget
smaller than the next-tier gap.

---

## Rule 5 — Treat LLM timeouts as no-signal, not fail-closed

> Any LLM call in a security path must have a hard timeout. A *timeout*
> (Workers AI throttling, model cold start, AbortError) means the LLM
> produced no signal — so it should contribute 0 and tag the email
> `llm_unavailable`, not synthesize a `suspicious` verdict. Parse-fail
> and model-garbage paths still fail closed to `suspicious`: those
> represent the LLM returning untrustworthy output, which is genuinely a
> suspicion signal — distinct from "the LLM didn't answer."

### What it prevents

Availability-as-bypass — but without the UX cliff. The original
"5s cap → `suspicious`" behavior produced a global false-positive spike
whenever Workers AI throttled. Treating timeout as no-signal lets other
pipeline stages decide; the verdict still composes correctly because the
aggregator already handles per-stage absence. The fail-closed half is
preserved where it actually fires: when the LLM *did* answer but its
output is unparsable or out of enum, the model is saying something we
can't trust, and "I can't trust this" is not `safe`.

The asymmetry matters. Degrading the classifier (rate-limit, outage,
context-window busting) no longer flips messages to `suspicious` on its
own — but auth, URL, reputation, and intel signals still run, and a
genuine `phishing`/`bec` parse from a slow model still scores normally
once it lands.

### How PhishSOC enforces this

- `workers/security/classification.ts` — `classifyEmail` (lines 97-163).
  - Hard 5-second timeout via `Promise.race` against
    `setTimeout(..., 5000)` at lines 125-140.
  - The `isClassifierTimeout` discriminator (lines 86-95) distinguishes
    timeout / `AbortError` / `ERR_ABORTED` from other thrown errors.
  - On timeout (lines 145-156) the function returns
    `{ label: "unavailable", confidence: 0, reasoning: "classifier timeout" }`.
  - On any other thrown error (lines 160-161) it still fails closed to
    `{ label: "suspicious", confidence: 0.3, reasoning: "classifier unavailable" }`.
- Parse failures fail-closed too — these are not timeouts:
  - "no JSON object found" → `suspicious` (line 170)
  - "JSON parse failed" → `suspicious` (line 181)
  - "label not in enum" → `suspicious` (`normalizeLabel`, lines 185-192)
- `scoreClassification` (lines 194-215) maps `unavailable` to score 0
  with reason `llm_unavailable` (lines 201-203); other labels score
  through the confidence-scaled table as before.
- Per-mailbox `security.classification.skip_on_timeout` (default `true`,
  line 115) controls the new behavior; setting it `false` reverts that
  mailbox to legacy fail-closed-on-timeout for back-compat.

---

## Rule 6 — The agent never sends without explicit user confirmation

> An auto-acting agent on a mailbox is allowed to *draft*. It is not
> allowed to *send*. Every outbound message must clear an explicit
> human-in-the-loop confirmation that is not solicitable by the agent
> itself.

### What it prevents

Indirect prompt injection that escalates to outbound action. An attacker
who can place text into the agent's context window (the simplest channel:
send the mailbox an email) can attempt to make the agent reply, forward,
exfiltrate, or impersonate. If the agent has direct send capability, the
attacker has hijacked the user's identity. If the agent can only
draft-and-stage, the worst case is a draft the user reviews and
discards.

The confirmation surface must be outside the agent's reach: a UI button
the agent cannot click, not a "say YES to send" prompt the agent could
fulfill on its own.

### How PhishSOC enforces this

- `workers/agent/index.ts` — `createEmailTools` (lines 103-263). The
  agent is given exactly these tools: `list_emails`, `get_email`,
  `get_thread`, `search_emails`, `draft_email`, `draft_reply`,
  `mark_email_read`, `move_email`, `discard_draft`. There is no
  `send_email` tool wired into the agent.
- The system prompt at lines 78-83 codifies the same rule for the model:
  "You can ONLY draft emails. You do NOT have the ability to send emails
  directly. ... The operator will review and send drafts from the UI -
  you cannot send them."
- The send code path lives in `workers/email-sender.ts` and is reachable
  only from authenticated UI / API routes, not from the agent's tool set.
- The user-facing copy at `app/routes/settings.tsx:218` ("Drafts are
  never sent without explicit confirmation.") matches the implementation.

A useful audit: grep the agent tool definitions for any tool whose
`execute` reaches a code path that calls `send_email`. There should be
zero results. (At the time of writing, there are.)

---

## How to adopt this in your own codebase

If you're building an LLM-on-email pipeline, the cheapest path to
agent-safety is:

1. **Wrap every `ai.run` call in a function whose return type is an
   advisory enum, not a free-form string** — and whose only side effects
   write to advisory tables. That makes Rule 1 enforceable by code review
   rather than by prompt-engineering.
2. **Pick threshold gaps before you pick stage caps.** Set a budget for
   each stage that's strictly smaller than the gap to the next tier.
   Rule 4 follows automatically.
3. **Make the timeout, parse-fail, and unknown-label paths all funnel to
   the same `suspicious` constant.** Don't let any sad path return
   `safe`. Rule 5 follows automatically.
4. **Don't give the agent a send tool.** Pre-commit hook, lint rule,
   whatever it takes — the agent's tool surface should not contain a
   verb that crosses the trust boundary on its own.

The remaining rules (2, 3, 6) are architectural. They're cheap to
add early, expensive to retrofit; do them up front.

---

## Out of scope

- New invariants beyond these six. (See issue #25.)
- A vendor-neutral reference repo. (Tracked separately.)
