# Security Policies

This document defines PhishSOC's remediation SLAs and merge-gate policies for
vulnerabilities surfaced by automated security tooling: Dependabot (SCA) and
CodeQL (SAST). It satisfies OSPS Baseline L3 requirements OSPS-VM-05.01,
OSPS-VM-05.02, and OSPS-VM-06.01.

---

## 1. SCA (Software Composition Analysis) — Dependabot

Dependabot runs weekly (every Monday, 07:00 UTC) and opens PRs against the
`main` branch for npm packages and GitHub Actions. Both npm manifests are
covered: the root app (`/`) and the community hub sub-app (`/hub`). See
[`.github/dependabot.yml`](../.github/dependabot.yml) for the full
configuration.

### 1.1 Severity definitions

Dependabot surfaces CVSS severity labels as assigned by GitHub Advisory
Database / NVD:

| Label | CVSS v3 range |
|-------|---------------|
| Critical | 9.0 – 10.0 |
| High | 7.0 – 8.9 |
| Medium | 4.0 – 6.9 |
| Low | 0.1 – 3.9 |

### 1.2 Remediation SLAs

| Severity | Maximum time to merge a fix or accept a workaround |
|----------|---------------------------------------------------|
| Critical | 7 days |
| High | 7 days |
| Medium | 30 days |
| Low | Next scheduled maintenance window (no hard deadline) |

SLA clock starts when GitHub marks the advisory as affecting this repository
(i.e., when the Dependabot alert is first opened, not when the PR is filed).

### 1.3 Merge-gate policy

**No PR may be merged into `main` while a Dependabot alert at Critical or High
severity is open on a dependency that PR touches.** This includes transitive
dependencies surfaced in the alert.

The gate is enforced operationally: the reviewer must confirm that no Critical
or High Dependabot alert relates to the PR's dependency surface before
approving. GitHub's dependency review action (if enabled) surfaces this
information in the PR diff.

If a high-severity CVE has no upstream fix available at the time the SLA
expires, the team must:

1. Document the decision in a GitHub Security Advisory or a tracking issue.
2. Apply a mitigating control (e.g. remove the affected package, pin to a
   known-safe fork, or add a WAF rule) within the SLA window.
3. Re-evaluate weekly until an upstream fix ships.

### 1.4 Waiver process

A finding may be waived if:

- The vulnerable code path is unreachable in the PhishSOC deployment topology
  (e.g., a Node.js-only code path in a package used only in Cloudflare Workers
  where that path is not bundled), **and**
- The waiver rationale is recorded in the Dependabot alert's "Dismiss" dialog
  with reason "Vulnerable code is not actually used" and a brief comment.

Waivers for Critical/High findings require a second maintainer to confirm
before the alert is dismissed.

---

## 2. SAST (Static Application Security Testing) — CodeQL

CodeQL runs on every pull request targeting `main`, on every push to `main`,
and on a weekly schedule (Mondays, 06:27 UTC). See
[`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml) for the
full workflow. The analysis targets `javascript-typescript` with the
`security-and-quality` query suite.

### 2.1 Severity definitions

CodeQL maps findings to CVSS-equivalent severity bands:

| Label | Meaning |
|-------|---------|
| Error / High | Direct security flaw; potential to exploit |
| Warning / Medium | Security-relevant but requires additional conditions |
| Note / Low | Defense-in-depth or quality concern |

### 2.2 Remediation SLAs

| Severity | Maximum time to resolve or suppress with rationale |
|----------|----------------------------------------------------|
| High (Error) | 14 days |
| Medium (Warning) | 30 days |
| Low (Note) | Next sprint / no hard deadline |

SLA clock starts when the CodeQL alert is first opened on the default branch
(or when it is introduced into a PR that is subsequently merged).

### 2.3 Merge-gate policy

**No PR may be merged into `main` if it introduces a new CodeQL alert at High
severity.** The CodeQL workflow is a required status check; a failing run
(due to a new High-severity alert) blocks the merge button.

Medium and Low alerts introduced by a PR should be resolved before merge when
feasible. If a Medium alert cannot be resolved in the same PR cycle, the
author must open a follow-up tracking issue within the PR's SLA window.

The `js/incomplete-url-substring-sanitization` query (high severity, SSRF /
redirect-bypass risk) is specifically enforced: URL-based routing logic —
including test-only mock dispatchers — must compare parsed `hostname` values
rather than using `startsWith` or `includes` on raw URL strings. See
[CLAUDE.md](../CLAUDE.md) for the canonical example.

### 2.4 Suppression process

A CodeQL alert may be suppressed inline (`// lgtm` or via a GitHub code
scanning dismissal) only if:

- The code path is unreachable or the finding is a confirmed false positive,
  **and**
- The dismissal includes a comment explaining why, **and**
- A second maintainer confirms the rationale.

Suppressing a High alert without a second-maintainer sign-off is not allowed.

---

## 3. Consistency with coordinated-disclosure timeline

The SLAs above are intentionally consistent with the vulnerability-disclosure
timeline in [`.github/SECURITY.md`](../.github/SECURITY.md):

| Event | Timeline |
|-------|----------|
| Acknowledgement of external report | 3 business days |
| Fix or mitigation for high-severity issue | 30 days |
| SCA High/Critical fix (Dependabot) | 7 days (stricter, because fixes are automated) |
| SAST High fix (CodeQL) | 14 days |

The 7-day SCA window is stricter than the external-report SLA because
Dependabot PRs are largely automated — the marginal effort to merge a
dependency bump is low. The 14-day SAST window reflects the additional
engineering judgment needed to fix a code-level finding.

---

## 4. Tooling references

| Tool | Configuration | Dashboard |
|------|--------------|-----------|
| Dependabot (SCA) | [`.github/dependabot.yml`](../.github/dependabot.yml) | GitHub → Security → Dependabot alerts |
| CodeQL (SAST) | [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml) | GitHub → Security → Code scanning alerts |

---

*This document was introduced to satisfy OSPS Baseline L3 controls
OSPS-VM-05.01 (SCA policy), OSPS-VM-05.02 (SCA merge gate), and
OSPS-VM-06.01 (SAST policy). Last updated: 2026-05-28.*
