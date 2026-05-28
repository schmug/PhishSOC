# Testing

This document describes the test layout, how to run tests locally, how CI
exercises them, and the project's policy on test coverage.

## Directory layout

The project has two test trees, one for each side of the codebase.

### `test/` — unit tests for the security pipeline

```
test/
  fixtures/       # canned JSON / YAML payloads used across suites
    intel/
    security/
    tlsrpt-report.json
  security/       # Vitest unit tests for workers/security/ internals
    classification.test.ts
    crowdsec-blocklist.test.ts
    crowdsec-cti.test.ts
    deep-scan-cti.test.ts
    fakes.ts
    run-pipeline.test.ts
    sender-graph-detector.test.ts
    spamhaus-drop.test.ts
```

These tests run directly in Node via Vitest without a Cloudflare Worker
runtime, so they are fast and have no network dependencies.

### `tests/` — integration and frontend tests

```
tests/
  agent/          # EmailAgent / OrgAgent Durable Object behaviour
  bimi/           # BIMI record fetch & validation
  dkim/           # DKIM key-lookup and posture checks
  dmarc/          # DMARC aggregate-report ingest
  dnssec/         # DNSSEC posture check
  frontend/       # React component tests (jsdom + Testing Library)
  intel/          # Deep-scan: RDAP, URL resolver, Bloom filter, MISP, …
  lib/            # Shared backend helpers (settings resolution, attachments, …)
  mta-sts/        # MTA-STS policy fetch
  routes/         # Hono route handlers (cases, ACL, send-email, …)
  security/       # Higher-level security pipeline integration tests
  spf/            # SPF record fetch and posture scoring
  tlsrpt/         # TLS-RPT posture check
```

Frontend tests under `tests/frontend/` use
[Testing Library](https://testing-library.com/) with a jsdom environment.
All other suites exercise Workers code under the
`@cloudflare/vitest-pool-workers` pool.

### `hub/tests/` — hub workspace tests

The `hub/` directory is an independent npm workspace with its own lockfile and
Vitest configuration.

```
hub/tests/
  helpers/        # Shared test utilities
  lib/            # Hub library unit tests
  routes/         # Hub Hono route handler tests
```

## Running tests locally

### Root workspace (main app + workers)

```sh
# Run all tests once (mirrors CI)
npm test

# Run tests in watch mode during development
npm run test:watch

# Typecheck without running tests
npm run typecheck
```

`npm test` invokes `vitest run`, which discovers every `*.test.ts` /
`*.test.tsx` file under `test/` and `tests/`.

### Hub workspace

Run these commands from the `hub/` directory (or use `--prefix`):

```sh
# From the repo root
npm test --prefix hub
npm run typecheck --prefix hub

# Or from inside hub/
cd hub
npm test
npm run typecheck
```

## CI

All tests and typechecks run automatically on every pull request targeting
`main` and on every direct push to `main`.

The workflow is defined in `.github/workflows/ci.yml` and contains two jobs:

| Job | `working-directory` | Steps |
| --- | --- | --- |
| `verify` (Typecheck & Test) | repo root | `npm run typecheck` → `npm test` |
| `hub-verify` (Typecheck & Test (hub)) | `hub/` | `npm run typecheck` → `npm test` |

Both jobs run on `ubuntu-latest` with Node 20 and have a 15-minute timeout.
Pull-request runs are cancelled if a newer commit is pushed before they finish
(`cancel-in-progress: true`).

CI must pass before a pull request can be merged.

## Test policy

- **Major changes to behavior must add or update an automated test.** Any PR
  that modifies a security rule, pipeline stage, route handler, or
  user-visible feature is expected to include a corresponding test change.
  Reviewer approval alone does not substitute for automated coverage.
- New helper functions and pure utilities belong in the unit layer (`test/` or
  the relevant `tests/lib/` file). End-to-end flows that cross the Hono
  routing layer belong in `tests/routes/`.
- Frontend behaviour changes belong in `tests/frontend/` using Testing Library
  assertions against rendered output.
- URL-matching logic in test mock dispatchers must use parsed hostnames — never
  `url.startsWith(...)` or `url.includes(...)` — to satisfy CodeQL's
  `js/incomplete-url-substring-sanitization` rule (see `CLAUDE.md`).
