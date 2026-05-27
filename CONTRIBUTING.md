# Contributing to PhishSOC

External contributions are welcome. This guide covers how to propose a change, what CI runs, how to format commits, and where to report security issues.

## Prerequisites

- Node.js 20 (matches CI)
- `npm install` at repo root

For `hub/` changes: `cd hub && npm install` as well.

## Fork → branch → PR

1. Fork the repo on GitHub.
2. Create a feature branch off `main`:
   ```
   git checkout -b feat/my-change
   ```
   Branch names are free-form; conventional-commit prefixes apply to commit messages, not branches.
3. Make your changes. Run tests and typecheck locally before pushing (see below).
4. Open a pull request against `main` in `schmug/PhishSOC`. Fill out every section of the [PR template](.github/pull_request_template.md) — the template is short, keep all sections.
5. CI runs automatically. A reviewer will engage once CI is green.

## Running tests

**Root package (Workers + React app):**

```bash
npm test           # run unit tests once
npm run typecheck  # type-check all packages
```

**Hub sub-package** (run from `hub/`):

```bash
cd hub
npm test
npm run typecheck
```

CI runs both suites and CodeQL analysis on every PR. A PR must be green on all three before it can merge.

## Commit format

Use [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | When to use |
| --- | --- |
| `feat:` | new user-visible behavior |
| `fix:` | bug correction |
| `refactor:` | restructuring without behavior change |
| `test:` | test additions or corrections |
| `chore:` | tooling, deps, config |
| `docs:` | documentation only |
| `security:` | security fixes or hardening |

Keep the subject line under 72 characters. Add a body for non-obvious motivation.

## Developer Certificate of Origin

All commits must carry a DCO sign-off:

```bash
git commit -s -m "feat: add my change"
```

The `-s` flag appends `Signed-off-by: Your Name <you@example.com>` to the commit message, certifying you authored the work or have the right to submit it under the Apache 2.0 license. See [developercertificate.org](https://developercertificate.org/) for the full text.

## Reporting security issues

Do not file a public issue for security vulnerabilities. Use the private reporting process described in [SECURITY.md](.github/SECURITY.md).
