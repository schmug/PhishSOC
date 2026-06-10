# Perplexity Bumblebee — Evaluation and Adoption Decision

**Decision:** Adopt (scoped) — weekly repo-checkout scan of the two committed npm lockfiles, plus an assemble-on-advisory incident runbook  
**Date:** 2026-06-10 · **Issue:** #413  
**License:** Bumblebee is [Apache-2.0](https://github.com/perplexityai/bumblebee/blob/main/LICENSE) — the same license as this repo. Usage in CI and local incident response is clean; no vendored source, only a checksum-pinned release binary fetched at workflow run time.

---

## What Bumblebee answers that existing tooling does not

| Tool | Question it answers | Surface | What it does *not* do |
|---|---|---|---|
| **Dependabot** (SCA) | "Is a newer/patched version available?" — version drift, registry advisories | npm packages + GitHub Actions | Does not tell you a *specific known-bad version* is on disk right now |
| **CodeQL** (SAST) | "Does *our* source contain a security flaw?" | `javascript-typescript` in this repo | No dependency provenance; never looks at lockfiles |
| **`npm audit`** | "Do installed deps match registry advisories?" | npm only | Registry advisories lag campaign disclosure; no curated incident catalog; no agent-skill/MCP/extension inventory |
| **Bumblebee** | "An advisory names trojaned `X@1.2.3` — is it present on disk *right now*?" | npm lockfiles + (endpoint-side) skill-lock manifests, MCP host configs, editor/browser extensions | Ships **no advisory feed** — exposure catalogs are operator-supplied; v0.1 matches **exact versions only** (no ranges) |

**Bumblebee does not replace Dependabot, CodeQL, or `npm audit`.** It is the
incident-response complement: when a supply-chain campaign advisory lands, it
answers the exposure question in seconds instead of a manual lockfile grep.

### Scope corrections relative to issue #413's assumptions

Two surfaces the issue hoped to cover are **not** covered by this adoption,
verified against the v0.1.1 inventory sources:

- **`.claude/skills/` is NOT covered.** Bumblebee v0.1.1 enumerates only the
  skills.sh / vercel-labs lock manifests (`skills-lock.json` and
  `~/.agents/.skill-lock.json`). Loose `SKILL.md` directories — which is what
  this repo's `.claude/skills/` contains — are not an inventory source.
  Revisit if upstream adds loose-skill-directory enumeration.
- **MCP coverage is endpoint-side, not repo-side.** Bumblebee parses MCP
  *host* configs (`.mcp.json`, `claude_desktop_config.json`,
  `~/.claude.json`). This repo commits none of those files, and
  `workers/mcp/` is an MCP *server implementation*, not a host config — so
  the repo-checkout scan gains no MCP coverage. MCP-config scanning only
  pays off on developer endpoints (fleet rollout is explicitly out of scope
  for #413; file separately if wanted).

What the repo-checkout scan *does* cover: `package-lock.json` (709 packages)
and `hub/package-lock.json` (202 packages) — the full committed npm
dependency surface of the deployed Worker and the hub.

---

## Integration shape chosen: scheduled CI scan + incident runbook

1. **Weekly scheduled scan** — [`.github/workflows/bumblebee.yml`](../.github/workflows/bumblebee.yml),
   Mondays 07:27 UTC (offset from CodeQL's 06:27), mirroring `codeql.yml`
   conventions: least-privilege `permissions: contents: read`,
   `timeout-minutes`, concurrency group, `workflow_dispatch` for manual runs.
   The binary is a checksum-pinned v0.1.1 release artifact — never
   `go install @latest`.
2. **Assemble-on-advisory runbook** (below) for the hours-after-disclosure
   window when the pinned catalogs don't yet cover a new campaign.

Bumblebee runs **only in CI and on operator endpoints** — it is a Go binary
and has no place in the deployed Cloudflare Worker.

### Exposure-catalog source (resolved)

Bumblebee ships no built-in advisory feed; catalogs are operator-supplied via
`--exposure-catalog`. Two sources, both resolved here:

- **(a) Scheduled scans use upstream `threat_intel/*.json`** — 10 maintained
  campaign catalogs (Mini Shai-Hulud waves, GlassWorm, node-ipc, GemStuffer,
  Laravel Lang, TrapDoor, and others) checked out at pinned upstream commit
  `bf685dde34e2d0a7cfea6a232b515fb53fcd7622`. Catalog content is a trust
  input, so the pin is bumped only via reviewed PRs — never tracked at a
  branch head.
- **(b) Optional broader corpus** — upstream's `tools/osvcatalog` converts
  the OSSF [malicious-packages](https://github.com/ossf/malicious-packages)
  OSV tree into a Bumblebee catalog, fully offline. Worth running during an
  incident when the curated catalogs feel too narrow. Caveat: v0.1 matches
  **exact versions only**, and many OSV records for malicious packages list
  no versions at all (every version is bad) — exact-match semantics
  undercount those.

---

## Incident runbook: assemble-on-advisory

When an advisory names a compromised package `X@v`:

1. **Check upstream first.** Look in
   [`threat_intel/`](https://github.com/perplexityai/bumblebee/tree/main/threat_intel)
   (at HEAD, not the pin) for a catalog already covering the campaign. If one
   exists, use it directly.
2. **Else write a minimal catalog.** The file must be a JSON **object** with
   `schema_version` and `entries` — bare arrays are rejected
   (`parse exposure catalog: root must be a JSON object with
   'schema_version' and 'entries' keys`):

   ```json
   {
     "schema_version": "0.1.0",
     "entries": [
       {
         "id": "INCIDENT-2026-NNNN",
         "name": "Short campaign description",
         "ecosystem": "npm",
         "package": "exact-package-name",
         "versions": ["1.2.3", "1.2.4"],
         "severity": "critical"
       }
     ]
   }
   ```

3. **Run locally** (deep is the incident-response profile and intentionally
   requires an explicit `--root`):

   ```sh
   bumblebee scan --profile deep --root <repo-path> \
     --exposure-catalog ./catalog.json --findings-only
   ```

   For a repo-only check, `--profile project --root <repo-path>` is faster
   and sufficient. Add `--root "$HOME"` under `deep` to also sweep
   endpoint-side surfaces (installed extensions, MCP host configs,
   skill-lock manifests).
4. **Any `record_type: "finding"` line is a confirmed exposure.** Findings do
   **not** change the exit code — inspect the NDJSON, don't trust `$?`.
   Handle per [`docs/security-policies.md` section 3](security-policies.md):
   Critical SCA, 7-day SLA, immediate day-0 triage.

### Binary install (pinned, checksum-verified)

Checksums come from the v0.1.1 release's `checksums.txt`. macOS arm64:

```sh
curl -fsSLO https://github.com/perplexityai/bumblebee/releases/download/v0.1.1/bumblebee_0.1.1_darwin_arm64.tar.gz \
  && echo "dc0a620e54e85f998c2280b0323763c342973a25eda475d8036d16b01820a2bf  bumblebee_0.1.1_darwin_arm64.tar.gz" | shasum -a 256 -c - \
  && tar -xzf bumblebee_0.1.1_darwin_arm64.tar.gz \
  && ./bumblebee selftest
```

Linux amd64 (what CI uses):
`0ef1c56c85a67c10f7211883c0eb5fb902de705cc30bbca0bc6f4d60941547da  bumblebee_0.1.1_linux_amd64.tar.gz`

---

## Verified gate behavior — why the jq pass is mandatory

Bumblebee's exit code reflects only operational failure, **not findings**. A
scan that confirms a trojaned package on disk still exits 0. The CI job
therefore gates on the NDJSON itself:

```sh
jq -s -e '([.[]|select(.record_type=="finding")]|length==0)
  and ([.[]|select(.record_type=="scan_summary")]|length==1)
  and (all(.[]|select(.record_type=="scan_summary"); .status=="complete"))' scan.ndjson
```

Verified locally against the real v0.1.1 binary (darwin_arm64,
checksum-verified) and the pinned upstream catalogs:

- Clean scan of this repo: `scan_summary` `status:"complete"`, 0 findings,
  911 package records (709 root lockfile + 202 hub lockfile) → gate exits 0.
- Synthetic catalog entry matching a real lockfile package version
  (`@cloudflare/kv-asset-handler@0.4.2`): scanner still exits 0, emits
  `finding` records → gate exits 1.
- `status` forced to `"partial"`, or `scan_summary` line removed (simulating
  a truncated/timed-out run) → gate exits 1 in both cases.
- Scanning a directory containing only catalog JSON files yields 0 package
  records and 0 findings — pointing `--root` at a workspace that also holds
  the checked-out `threat_intel/` is harmless.

---

## Threat model / security notes

The scanner itself is a supply-chain trust input; the integration is shaped
so adopting it does not widen the attack surface it exists to watch:

- **Pinned binary, verified before execution.** CI fetches the v0.1.1
  release tarball and `sha256sum -c`'s it against a checksum literal
  committed in the workflow file before untarring. A compromised release
  re-upload or a `latest` hijack fails the checksum, not the trust boundary.
  `go install @latest` is explicitly banned.
- **Pinned catalogs.** `--exposure-catalog` content decides what counts as a
  finding; a malicious catalog could *suppress* alerts (or spam them). CI
  checks catalogs out at a fixed upstream commit SHA; bumps are reviewed PRs.
- **Least privilege.** The workflow runs with `permissions: contents: read`,
  on `schedule`/`workflow_dispatch` only — no untrusted event payloads are
  interpolated anywhere, and no write scopes exist to escalate to.
- **Read-only by design.** Bumblebee inventories on-disk metadata; it
  executes no dependency code and never runs in the deployed Worker. The
  email-pipeline invariants in `SECURITY_SPEC.md` are untouched — this is a
  CI/endpoint control on the repo's *own* dependency surface.
- **Fail-closed gate.** The jq gate fails on incomplete runs
  (missing/duplicated `scan_summary`, non-`complete` status), so a scanner
  crash or truncated output surfaces as a red run instead of silent green.

---

## Why scoped adoption, not full

- The npm-lockfile surface is the only Bumblebee inventory source this repo
  actually commits (see scope corrections above) — a weekly repo scan plus
  on-advisory runbook captures all the available value at near-zero cost.
- Fleet/MDM endpoint rollout (where the skill/MCP/extension coverage pays
  off) is explicitly out of scope for #413; file separately if the
  repo-scoped scan proves valuable.
- Building a PhishSOC-branded exposure-catalog feed is the `hub/`
  destroylist's separate domain, not this adoption.
