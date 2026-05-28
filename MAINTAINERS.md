# Maintainers

## Active maintainers

| GitHub handle | Role | Responsibilities |
|---|---|---|
| [@schmug](https://github.com/schmug) | Primary maintainer | Code review, merge authority, release tagging, security-disclosure triage |

### Contact

For security vulnerabilities, use the private reporting path described in [SECURITY.md](.github/SECURITY.md). For general questions, open an issue.

## Roles and authorities

**Primary maintainer** — holds merge rights on `main`, release authority, and security-triage responsibility. Receives all CODEOWNERS review requests. Handles private vulnerability disclosures within the SLA documented in SECURITY.md (3 business days acknowledgement / 30 days for high-severity fixes).

## Solo-maintainer review waiver (OSPS-QA-07.01)

This project is currently solo-maintained. OSPS Baseline L3 control OSPS-QA-07.01 asks for ≥1 non-author approving review before merge. Meeting that requirement with a single active maintainer would block all progress on self-authored PRs.

**Waiver rationale:** The following compensating controls replace the peer-review gate:

- **CodeQL (SAST)** — required status check on every PR; high-severity alerts block merge.
- **Typecheck & Test** — required status checks on every PR (root workspace + hub workspace); red CI blocks merge.
- **Secret scanning + push protection** — GitHub-native; prevents accidental credential commits.
- **`enforce_admins: true`** — the maintainer cannot bypass status checks even on self-authored merges.
- **`allow_force_pushes: false`** — history on `main` is append-only.

This waiver is revisited whenever a second active maintainer joins the project, at which point the branch-protection rule will be updated to require ≥1 non-author approval.
