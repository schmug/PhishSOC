# triage

A Claude Code skill that triages a batch of raw security-scanner findings:
verifies each is real, collapses duplicates, re-ranks by derived
exploitability, and tags each survivor with a component owner. Turns a raw
dump into a short, ranked, owned list.

## Status

Pairs with `/sec-vuln-scan` (which writes `VULN-FINDINGS.json`), and will also
ingest loosely-structured JSON or markdown from other scanners.

## Requirements

- Claude Code CLI installed and authenticated
- A read-only checkout of the target codebase (verification reads source;
  it does not build or run anything)
- A file or directory of findings to triage

## Installation

Project-scoped (ships with this repo — nothing to do if you cloned it):

```bash
ls .claude/skills/sec-triage/SKILL.md
```

Or user-scoped:

```bash
mkdir -p ~/.claude/skills
cp -r .claude/skills/sec-triage ~/.claude/skills/
```

## Usage

From a Claude Code session in the target repo:

```
/sec-triage path/to/findings.json
```

Interactive mode (the default) opens with a short interview about your
environment, threat model, and preferred scoring standard — these shape how
reachability is judged and how severity is labeled. To skip the interview
and use defaults:

```
/sec-triage path/to/findings.json --auto
```

Common invocations:

```
/sec-triage VULN-FINDINGS.json --repo .                 # sec-vuln-scan output, repo = cwd
/sec-triage VULN-FINDINGS.json --repo . --fp-rules .claude/skills/_lib/phishsoc-rules.md
/sec-triage scanner_export/ --votes 5 --repo .          # high-stakes batch, 5-vote verify
/sec-triage backlog.md --auto --votes 1 --repo .        # quick first pass on a markdown report
```

## Output

- `./TRIAGE.json` — every input finding, annotated with `verdict`,
  `verify_verdict`, recomputed `severity`, `severity_alignment` vs. the
  scanner's claim, `preconditions`, `vote_breakdown`, `rationale` citing
  file:line evidence, `owner_hint`, and `duplicate_of` where applicable.
  Sorted by what to act on first.
- `./TRIAGE.md` — reviewer-facing report: an "Act on these" section with
  one entry per confirmed finding, then a "Dropped" table explaining every
  rejection.

A `needs_manual_test` verdict means static reasoning hit its limit on that
finding — treat it as a recommendation for a human to build a controlled
proof-of-concept, not as a failure.

## Checkpointing and resume

Per-phase state is written to `./.triage-state/`. If a run is interrupted
(rate limit, context exhaustion, Ctrl-C), re-invoking `/sec-triage` with the same
arguments resumes from the last completed phase — the interview is not
re-asked and verifiers already tallied are not re-spawned. Pass `--fresh` to
start over. `./.triage-state/` is scratch; add it to `.gitignore`.

## What it does and doesn't do

- **Does:** read source, grep for callers, reason about reachability and
  protections, vote, rank, and route.
- **Does not:** build, run, or test the target; install dependencies;
  reach the network; write proof-of-concept exploits. All conclusions are
  static. This is deliberate — the skill is meant to run in a review box
  alongside a read-only checkout.

## Questions

Reach out to your Anthropic contact.
