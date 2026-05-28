---
name: sec-patch
description: Generate candidate fixes for verified security findings. Consumes
  TRIAGE.json (preferred) or VULN-FINDINGS.json. Static-analysis input gets a
  per-finding patch subagent + independent reviewer and is written as inert
  diffs for human review. Writes PATCHES/bug_NN/{patch.diff,patch_result.json},
  PATCHES.md, and PATCHES.json. Use when asked to "fix the findings",
  "patch these vulns", "generate fixes", or "close the loop on triage".
argument-hint: "<findings-path> [--repo PATH] [--top N] [--id fNNN] [--fresh]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - Bash(python3 .claude/skills/_lib/checkpoint.py:*)
  - Bash(rg:*)
  - Bash(grep:*)
  - Bash(ls:*)
  - Bash(wc:*)
  - Bash(head:*)
  - Bash(file:*)
  - Bash(jq:*)
---

# patch

Third leg of the static pipeline (`/sec-vuln-scan` → `/sec-triage` → `/sec-patch`).
Turns a ranked list of verified findings into candidate diffs.

**Static mode only.** This port targets a TypeScript / Cloudflare Workers app;
there is no execution oracle (no ASAN binary to build, run, and re-attack), so
the execution-verified ladder from the reference harness does not apply. Every
diff here is authored and independently reviewed by agents reading source, then
written as inert text. Confirm each at runtime with a human-built `vitest` case
before upstreaming.

The skill **never applies a diff** to the target repo. Output is inert text
in `./PATCHES/` for a human to review and apply out-of-band. There is no
`--apply` or `--approve` flag by design: the capability isn't present, so it
can't be prompt-injected into use.

Invoke with `/sec-patch <findings-path> [--repo PATH] [--top N] [--id fNNN]
[--fresh]`.

**Arguments** (parse from `$ARGUMENTS`):
- findings path (first positional, required): `TRIAGE.json`,
  `VULN-FINDINGS.json`, or any JSON the `/sec-triage` ingest table recognizes.
- `--repo PATH`: target codebase, read-only (default cwd). Required; the skill
  stops if cited files don't resolve under it.
- `--top N`: patch only the N highest-severity true positives.
- `--id fNNN`: patch only the finding with this id.
- `--fresh`: ignore `./.patch-state/` checkpoint and start over.

**Tools.** Prefer Read, Glob, Grep, Write, Task. Some sessions do not
provision Glob or Grep; `allowed-tools` is a permission filter, not a loader.
When they are unavailable, fall back to the read-only Bash commands
whitelisted above: `rg`/`grep` for search, `ls` for enumeration,
`head`/`file`/`wc` for sniffing, `jq` for JSON ingest. Bash is otherwise
permitted only for `python3 .claude/skills/_lib/checkpoint.py` (state I/O).
`find` is NOT permitted.

**Write scope.** The Write tool may target ONLY paths under `./PATCHES/` and
`./.patch-state/`. Never write into `--repo`, never `git apply`, never
`patch`, never edit target source. If a step seems to require it, the step is
wrong.

---

## Checkpointing (runs before Phase 0 and after every phase)

State persists to `./.patch-state/` so a fresh `/patch` session resumes
without re-spawning patch or reviewer subagents. All checkpoint I/O goes
through `python3 .claude/skills/_lib/checkpoint.py` (atomic, JSON-validated).
The Write→`--from` pattern keeps repo-derived bytes out of Bash argv; never
pass payload via heredoc or stdin.

State files: `progress.json` (single source of truth: `{"status":
"running"|"complete", "phase_done": N, "shards_done": [...]}`),
`phaseN.json`, `_chunk.tmp`.

**Start of run.** Bash:
`python3 .claude/skills/_lib/checkpoint.py load ./.patch-state`

- `status == "absent"` OR `"complete"`, OR `--fresh` in `$ARGUMENTS` →
  fresh start. Bash:
  `python3 .claude/skills/_lib/checkpoint.py reset ./.patch-state`,
  proceed to Phase 0.
- `status == "running"` with `phase_done == N` → resume. Read
  `phase0.json`..`phaseN.json` in order (and any `shard_*.json` listed in
  `shards_done`), merge into working state, print
  `Resuming from checkpoint: Phase N complete`, skip to Phase N+1. Do not
  re-spawn any subagent whose output is already checkpointed.

**End of every phase N.** Write tool → `./.patch-state/_chunk.tmp` with the
phase's JSON, then Bash:
`python3 .claude/skills/_lib/checkpoint.py save ./.patch-state <N> <name> --from ./.patch-state/_chunk.tmp`

**End of run.** After writing `PATCHES.md` and `PATCHES.json`, Bash:
`python3 .claude/skills/_lib/checkpoint.py done ./.patch-state 4`

---

## Phase 0: Parse arguments

### 0a. Parse `$ARGUMENTS`

Extract findings path (first positional), `--repo` (default `.`), `--top`,
`--id`, `--fresh`. If no findings path, stop and ask.

### 0b. Mode is always `static`

This port has no execution oracle, so there is no execution-verified mode.
`TRIAGE.json`, `VULN-FINDINGS.json`, generic finding JSON, and markdown are all
handled in static mode: the oracle is a fresh-context reviewer that reads
source (Phase 3). Record `mode: "static"` in working state and proceed.

**Checkpoint:** Write tool → `./.patch-state/_chunk.tmp`:
`{"phase": 0, "mode": "static", "args": {repo, top, id, findings_path}}`
Then Bash:
`python3 .claude/skills/_lib/checkpoint.py save ./.patch-state 0 mode --from ./.patch-state/_chunk.tmp`

---

## Phase 1: Ingest and normalize

Same input contract as `/sec-triage` Phase 1. Normalize every input format to a
flat `findings[]` of dicts. Pull what's present; never guess what's absent.

### 1a. Recognized containers (priority order)

1. **`TRIAGE.json`** — read `.findings[]`. **Filter to `verdict ==
   "true_positive"`.** This is the canonical input: already verified,
   deduped, ranked, owner-tagged.
2. **`VULN-FINDINGS.json`** — read `.findings[]`. Unverified; print
   `Warning: VULN-FINDINGS.json is unverified scanner output. Consider
   /sec-triage first.` and continue.
3. Generic `*.json` with a top-level list or a `findings`/`results`/
   `issues`/`vulnerabilities` array.

### 1b. Field aliases (canonical ← also-accept)

| Canonical        | Also accept                                              |
|------------------|----------------------------------------------------------|
| `file`           | `path`, `location.file`, `filename`                      |
| `line`           | `line_number`, `location.line`, `lineno`                 |
| `category`       | `type`, `cwe`, `rule_id`, `crash_type`                   |
| `severity`       | `severity_rating`, `level`, `priority`                   |
| `title`          | `name`, `summary`, `message`                             |
| `description`    | `details`, `report`, `body`, `evidence`, `rationale`     |
| `recommendation` | `fix`, `remediation`, `mitigation`                       |
| `owner_hint`     | `owner`, `component`                                     |

Attach `id` (`f001`, `f002`, ... in ingest order; preserve existing ids from
TRIAGE.json) and `source` (relative path of the file it came from).

### 1c. Filter and order

- If `--id fNNN`: keep only that finding.
- If `--top N` (static mode): sort by `severity` HIGH > MEDIUM > LOW then
  `confidence` desc, keep the first N.
- Drop findings with no `file` (cannot patch what cannot be located). Record
  them as `skipped` with reason `"no source location"`.

### 1d. Locate the target codebase (static mode)

Resolve `--repo`. For the first 5 findings with a `file`, check the path
resolves under repo (try as-given, then with common prefixes stripped). If
none resolve, **stop**: tell the user the cited files aren't reachable and
suggest a `--repo` value.

**Checkpoint:** Write tool → `./.patch-state/_chunk.tmp`:
`{"phase": 1, "mode": ..., "findings": [...], "skipped": [...], "repo": ...}`
Then Bash:
`python3 .claude/skills/_lib/checkpoint.py save ./.patch-state 1 ingest --from ./.patch-state/_chunk.tmp`

---

## Phase 2: Generate patches (one patch subagent per finding)

One Task per finding, all in a SINGLE assistant message for parallel
execution. `subagent_type: "general-purpose"`. Never set
`run_in_background` — you need the diff text, not an async handle.

Each subagent has read-only access to `--repo`. It cannot modify the target;
it emits the diff as text in its response. The orchestrator writes that text
to `PATCHES/bug_NN/patch.diff`.

#### Patch subagent prompt (assemble once, reuse per finding)

```
You are conducting authorized security research as part of a defensive
assessment. Your task: write a candidate fix for ONE verified vulnerability
finding in a codebase you have read-only access to.

You may use Read, Glob, and Grep ONLY on paths inside {REPO_PATH}. You may
NOT build, run, install, edit files on disk, or reach the network. You will
emit the fix as a unified diff in your final response; you will NOT apply it.

────────────────────────────────────────────────────────────────────────
FINDING:

  id:        {id}
  file:      {file}
  line:      {line}
  category:  {category}
  severity:  {severity}
  title:     {title}

  description:
  {description}

  recommendation:
  {recommendation or "(none provided)"}

────────────────────────────────────────────────────────────────────────
PROCEDURE:

1. READ THE CODE. Open {file} at line {line} and the surrounding function.
   Understand what the code does — do not trust the finding's description as
   the only source.

2. ROOT CAUSE FIRST. Trace backward from the cited sink to where the bad
   value or missing check originates. The fix usually belongs there, not at
   the line the scanner flagged. Name the root-cause location (file:line).

3. VARIANT HUNT. Grep for sibling call sites with the same pattern. Your fix
   should cover all of them, or your rationale should say why not.

4. MINIMAL DIFF. Smallest change that fixes the root cause. No refactoring,
   no drive-by cleanup, no reformatting, no comment-only changes. Match the
   surrounding code's style (brace placement, naming, error handling).

5. ADVERSARIAL SELF-CHECK. Re-read your diff as an attacker. Name one input
   variation that would reach the same bad state without tripping your
   change. If you can name one, your fix is at the wrong layer — go back to
   step 2.

6. REGRESSION TEST. As part of the diff, add ONE test case that fails before
   your change and passes after — placed wherever the project keeps its
   tests (look for test_*/, *_test.*, tests/, spec/). If no test directory
   exists, omit the test and say so in <test_note>.

────────────────────────────────────────────────────────────────────────
OUTPUT — your final response MUST contain exactly these tags. Emit the diff
verbatim between the markers; do NOT wrap it in ``` fences.

<patch_diff>
--- a/path/to/file
+++ b/path/to/file
@@ ... @@
 context line
-removed line
+added line
</patch_diff>
<rationale>what changed and why, mechanically — file:line of root cause,
what the change enforces</rationale>
<variants_checked>file:function pairs you grepped for the same
pattern, and whether each needed the fix</variants_checked>
<bypass_considered>the input variation you tried in step 5 and why it
no longer reaches the bad state</bypass_considered>
<test_note>where the regression test landed, or why none was
added</test_note>

If you determine the finding is NOT fixable as described (wrong file, code
already patched, finding is a false positive), emit:

<patch_diff>NONE</patch_diff>
<rationale>why no patch is appropriate</rationale>
```

#### Spawn

For each finding in `findings[]`, build a Task call with the prompt above
(substituting `{REPO_PATH}`, `{id}`, `{file}`, `{line}`, `{category}`,
`{severity}`, `{title}`, `{description}`, `{recommendation}`).
`description: "patch {id}"`.

If `len(findings) > ~40`, shard into sequential batches of ~40 (each batch
one message). Per-finding shard checkpoint after each result is parsed.

If any Task call returns `status: "async_launched"` instead of the
subagent's text, the runtime backgrounded it. Pick one recovery and use it
for the whole batch:
  - If completion notifications arrive in your conversation: parse each
    subagent's tagged blocks from its notification `result` as it lands. Do
    not end your turn until every finding is accounted for.
  - If notifications do not arrive: do NOT poll transcript files. Re-spawn
    the missing patch subagents in a fresh Task batch (smaller shard, e.g.
    10) and use the synchronous results.
The same recovery applies to reviewer subagents in Phase 3.

#### Parse

From each Task result, extract the five tagged blocks. Tolerate leading/
trailing whitespace, stray ``` fences, and HTML-escaped entities (`&lt;`
`&gt;` `&amp;` — some runtimes escape angle brackets in notification
payloads; unescape before writing the diff). If `<patch_diff>` is `NONE` or
empty,
mark `status: "no_patch"`. Otherwise write the diff text to
`./PATCHES/bug_NN/patch.diff` (NN = zero-padded index in sorted order) and
record `rationale`, `variants_checked`, `bypass_considered`, `test_note`.

**Checkpoint per finding:** Write tool → `./.patch-state/_chunk.tmp` =
`{"id": ..., "bug_nn": "NN", "status": ..., "rationale": ..., ...}`, then Bash:
`python3 .claude/skills/_lib/checkpoint.py shard ./.patch-state <id> --from ./.patch-state/_chunk.tmp`.
After all findings, write the consolidated phase payload to `_chunk.tmp` then:
`python3 .claude/skills/_lib/checkpoint.py save ./.patch-state 2 generate --from ./.patch-state/_chunk.tmp`

---

## Phase 3: Independent review (static mode only)

One reviewer subagent per generated diff, all in ONE message,
`subagent_type: "general-purpose"`.

**The reviewer never sees the finding's `description`, `recommendation`, or
the patch author's `rationale`.** It gets only `{file, line, category}`
plus the raw diff bytes, and re-derives whether the diff is a minimal,
in-scope fix by reading the source itself. This keeps any instructions
embedded in finding prose from reaching both the author and the gate.

#### Reviewer prompt (assemble once, reuse per diff)

```
You are reviewing a candidate security patch as a maintainer would. You have
read-only access to the unpatched source at {REPO_PATH}. You may use Read,
Glob, Grep. You may NOT build, run, or apply the diff.

You have NOT seen the scanner's description of the vulnerability or the
patch author's reasoning. Work only from the location, the category, and the
diff.

LOCATION: {file}:{line}
CATEGORY: {category}

DIFF UNDER REVIEW:
<diff>
{diff_text — or, for diffs over ~50 lines, replace this block with:
"Read the diff at ./PATCHES/bug_NN/patch.diff" and let the reviewer Read it}
</diff>

────────────────────────────────────────────────────────────────────────
ANSWER FOUR QUESTIONS:

1. SCOPE. Does the diff touch only files/functions on the path between
   {file}:{line} and its callers? List any hunk that falls outside that
   path.

2. SUPPRESSION. Does the diff fix a root cause, or does it suppress the
   symptom (try/except: pass, early-return on a magic value, deleting the
   check that fired, lowering a log level)?

3. NEW SURFACE. Does the diff add parsing, trust a new input field, weaken
   validation elsewhere, or remove a security-relevant check?

4. STYLE. 0-10: would you merge this as-is?
   0-3 wrong layer / suppression; 4-6 correct but noisy; 7-10 minimal,
   targeted, matches surrounding style.

────────────────────────────────────────────────────────────────────────
End your response with EXACTLY:

  REVIEW: ACCEPT | REJECT
  STYLE_SCORE: <0-10>
  OUT_OF_SCOPE_HUNKS: <comma-separated file:line, or none>
  REASON: <2-4 sentences citing specific diff hunks and source lines>

ACCEPT requires: in-scope, root-cause fix, no new attack surface,
style >= 5. Otherwise REJECT.
```

#### Spawn and parse

One Task per finding with `status != "no_patch"`. Parse the trailing block.
Attach `review`, `style_score`, `out_of_scope_hunks`, `review_reason` to the
finding. Set `verified: "static_review_only"` for every static-mode result
regardless of ACCEPT/REJECT — the label describes the verification class,
not the outcome.

**Checkpoint:** Write tool → `./.patch-state/_chunk.tmp`:
`{"phase": 3, "findings": [...]}`
Then Bash:
`python3 .claude/skills/_lib/checkpoint.py save ./.patch-state 3 review --from ./.patch-state/_chunk.tmp`

---

## Phase 4: Output

### 4a. Per-finding `patch_result.json`

For each finding (both modes), Write
`./PATCHES/bug_NN/patch_result.json`:

```json
{
  "id": "f003",
  "source": "TRIAGE.json#2",
  "title": "...",
  "file": "...",
  "line": 0,
  "category": "...",
  "severity": "HIGH",
  "owner_hint": "...",
  "mode": "static",
  "verified": "static_review_only",
  "review": "ACCEPT" | "REJECT" | null,
  "style_score": 0,
  "out_of_scope_hunks": [],
  "rationale": "...",
  "variants_checked": "...",
  "bypass_considered": "...",
  "test_note": "...",
  "review_reason": "..."
}
```

### 4b. `./PATCHES.json`

```json
{
  "patch_completed": true,
  "mode": "static",
  "repo": "...",
  "summary": {
    "input_count": 0,
    "patched": 0,
    "no_patch": 0,
    "accepted": 0,
    "rejected": 0
  },
  "findings": [ { ...patch_result.json shape... } ]
}
```

### 4c. `./PATCHES.md` (incremental)

**Step 1 — header.** Write tool → `./PATCHES.md` (clobbers prior):

````markdown
# Candidate Patches

> **Static review only.** These diffs were authored and reviewed by
> independent agents reading source. They were NOT compiled, run, or
> re-attacked. Read each diff yourself and add a `vitest` case before
> applying or upstreaming.

**Input:** {findings_path} · **Repo:** {repo} · {N} findings → {M} diffs

---
````

**Step 2 — per finding** (sorted: ACCEPT first, then by
severity). Write `./.patch-state/_chunk.tmp`:

````markdown
## bug_{NN}: [{severity}] {title}  ({id})

`{file}:{line}` · {category} · owner: {owner_hint or "?"}
**Status:** {verified} · review {review or "n/a"} · style {style_score or "n/a"}/10
**Diff:** `PATCHES/bug_{NN}/patch.diff` ({hunk count} hunks, {line count} lines)

**Rationale:** {rationale}
**Variants checked:** {variants_checked}
**Bypass considered:** {bypass_considered}
{if review == "REJECT":}
> **Rejected by reviewer:** {review_reason}
{if out_of_scope_hunks:}
> **Out-of-scope hunks:** {out_of_scope_hunks}

---
````

Then `checkpoint.py append ./PATCHES.md --from ./.patch-state/_chunk.tmp`.

**Step 3 — footer.** Append a `## Skipped` table for findings with no `file`
or `status == "no_patch"`, one line each with the reason.

**Checkpoint (final):** Bash:
`python3 .claude/skills/_lib/checkpoint.py done ./.patch-state 4`

### 4d. Terminal summary

Under ~10 lines:

```
Patches generated (static mode): {N} findings → {M} diffs.

  Accepted:  {n}   {title of top accepted}
  Rejected:  {n}
  No patch:  {n}

Wrote ./PATCHES/bug_NN/, ./PATCHES.md, ./PATCHES.json
These are drafts. Review each diff and add a vitest case before applying.
```

---

## Guard rails

- **The skill never applies diffs.** No `git apply`, no `patch`, no Edit
  against `--repo`. If you find yourself needing to, the design is wrong.
- **Write only under `./PATCHES/` and `./.patch-state/`.**
- **Reviewer isolation.** The reviewer prompt receives `{file, line,
  category, diff}` and nothing else from the finding. Do not pass it
  `description`, `recommendation`, `exploit_scenario`, or the patch author's
  `rationale`.
- **Always set `subagent_type`.** Forking would leak every finding's prose
  into every patch subagent.
- **All Task calls for a phase in ONE message.** Serial spawning is correct
  but N× slower.
- **Checkpoint before starting the next phase**, every time.

---

## Testing this skill

Run the static chain against this repo's own findings:

```
/sec-vuln-scan workers/intel
/sec-triage VULN-FINDINGS.json --repo . --auto
/sec-patch TRIAGE.json --repo . --top 3
```

Expected: up to three diffs under `PATCHES/bug_00..02/`, each
`verified: "static_review_only"` with an ACCEPT/REJECT review and a style
score. Confirmed true-positives go to a private GitHub Security Advisory
(`.github/SECURITY.md`), not a public issue.

---

## Design notes

- **TRIAGE.json is canonical input** because patching unverified findings
  wastes tokens on false positives. VULN-FINDINGS.json is accepted with a
  warning for convenience.
- **Static mode emits a regression test inside the diff** rather than
  running it. The skill cannot execute target code; the test is for the
  human who applies the diff (a `vitest` case here).
- **Reviewer never sees finding prose.** Target source can contain
  injected instructions that survive into a scanner's `description` field.
  The patch author sees that prose (it has to, to know what to fix); the
  reviewer doesn't, so injected text cannot pass its own gate.
- **`verified` is the verification class, not pass/fail.**
  `static_review_only` means "an agent read it" regardless of
  ACCEPT/REJECT. Downstream tooling should branch on this field, not on
  `review`.
