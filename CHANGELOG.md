# Changelog

All notable changes to PhishSOC are documented in this file.

This file is auto-maintained by [git-cliff](https://git-cliff.org/) using
conventional commits. For a machine-readable feed, see the GitHub Releases page.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note:** This file was seeded from git history prior to the first tagged
> release. Going forward it will be auto-maintained by `git-cliff` using the
> `cliff.toml` config at the repo root. Run `git-cliff --unreleased --tag vX.Y.Z`
> to regenerate before cutting a release.

---

## [Unreleased]

### Security

- **security:** Enforce send-risk step-up on reply and forward routes ([e7907bc](https://github.com/schmug/PhishSOC/commit/e7907bc333fc8178b28bff894651a419eb3ea853))
- **security:** Wire send-risk classifier into POST /emails + preflight endpoint (#15 slice 3) ([98bd0f5](https://github.com/schmug/PhishSOC/commit/98bd0f59cf8dac3195ceaa648b4ae8604b4e19c4))
- **security:** Step-up confirm endpoint + one-shot JWT (#15 slice 2) ([c9467ae](https://github.com/schmug/PhishSOC/commit/c9467ae86f4f12752c019fe4fcabe02fddbe24a9))
- **security:** Outbound send-risk classifier + agent guard for tagged verdicts (#15 slices 1+5) ([c1d41b2](https://github.com/schmug/PhishSOC/commit/c1d41b245052ab5689b0f74eb04f8bcc0970db00))

### Features

- Mailbox ACL ownership transfer (#293) ([0753c3f](https://github.com/schmug/PhishSOC/commit/0753c3f8455aa06b3bb5426d3e791a44b4bfa07e))
- Mailbox ACL member-management UI (#291) ([d6f42bb](https://github.com/schmug/PhishSOC/commit/d6f42bb9dbd185181d7447014d78a67f6d9c3c42))
- Bulk lock-down for all unscoped mailboxes (#294) ([47f69a3](https://github.com/schmug/PhishSOC/commit/47f69a34c8c27d26f97935ebe22a4faeaedc78a1))
- Public destroylist endpoint + corroboration counts in hub feeds (Closes #23) ([fa171f9](https://github.com/schmug/PhishSOC/commit/fa171f94c73c571f4a6ac82bb8241e60d2effcc2))
- Wire composer step-up confirm flow to /api/v1/confirm (Closes #285) ([848db0f](https://github.com/schmug/PhishSOC/commit/848db0f4c01843a43c1c1f7c5a7ac8560ea925c0))
- Composer send-risk UI — preflight call, Tier 0/1/2 button states, Tier-2 phrase confirm (#263) ([536cede](https://github.com/schmug/PhishSOC/commit/536cede8586c72c5e1b728eeff3f1ea2f936ce13))
- SOC-framed first-run checklist + CF Access error UX in home (#68) ([884ae67](https://github.com/schmug/PhishSOC/commit/884ae678892c38eae6500a70abd3da0f6295575c))
- Committed .claude/settings.json hook enforcing stripDefaultEqual + MTA-STS invariants (#278) ([bcbdb57](https://github.com/schmug/PhishSOC/commit/bcbdb57ee93c2d5ad013e09ec815495c0dd3d782))
- Per-mailbox Attachment scanner settings UI toggle (yaramail sidecar) ([3c11cb7](https://github.com/schmug/PhishSOC/commit/3c11cb79ce2d3823be6a77c3e5c87c618894f741))
- Wire fireYaraScan into receiveEmail + callback route + DO verdict update ([2fd33ce](https://github.com/schmug/PhishSOC/commit/2fd33ce1631872917b74d3971d238b7afccac4a0))
- Created_by drafts column + agent-authored tier bump (#266) ([31c3f19](https://github.com/schmug/PhishSOC/commit/31c3f190a8ca4d2a1eacb2eda711727715f56774))
- Yaramail async sidecar signal module, schema, and migration (#256) ([ae5a592](https://github.com/schmug/PhishSOC/commit/ae5a5927f5e57b155c6588745fdcc5a450013a0a))
- BIMI posture lookup on /domains/:domain (#245) ([b1778a2](https://github.com/schmug/PhishSOC/commit/b1778a2edbff683c0956bec64f9791712336bfd3))
- Acl_status on mailbox list + one-time lock-down endpoint (#241) ([c093676](https://github.com/schmug/PhishSOC/commit/c09367675db8b1567926d077b046942e3a469211))
- Mailbox ACL member management API (add/remove members, #240) ([8a4645b](https://github.com/schmug/PhishSOC/commit/8a4645b78bba555215722b605e7193b04f1f103d))
- Per-mailbox ACL scoping (#27) ([cc108e9](https://github.com/schmug/PhishSOC/commit/cc108e9ddfbf1738456bf0f9989a95829b5cfeb0))

### Bug Fixes

- *(No bug-fix commits recorded before first release)*

### Documentation

- Add per-subsystem CLAUDE.md files for workers/, app/, hub/, sidecar/ (#282) ([e112578](https://github.com/schmug/PhishSOC/commit/e11257833f967ded6fdb8ee40af0f179094135ab))
- Add codebase map to CLAUDE.md and link from README (#281) ([7e8685e](https://github.com/schmug/PhishSOC/commit/7e8685e54de2ef205e71cd83f51606d28034be34))
- Yaramail sidecar deployment guide and interface contract (#259) ([5a4c78c](https://github.com/schmug/PhishSOC/commit/5a4c78cd0eb5b8d00ffa9b70471f75e716a8adf3))

### Testing

- **tlsrpt:** Add explicit NXDOMAIN test for fetchTlsRptPosture (#248) ([dfb1bcc](https://github.com/schmug/PhishSOC/commit/dfb1bccd6f3fc20ffbe56db46dc31cd4daea10f4))

### Miscellaneous

- Allowlist read-only git fetch / gh search code / pnpm lint ([5e26676](https://github.com/schmug/PhishSOC/commit/5e26676c79023b653b18c5411613d10c902f1b9c))
- **deps:** Bump the npm_and_yarn group across 2 directories with 2 updates ([c1606b8](https://github.com/schmug/PhishSOC/commit/c1606b8fb5f6f9ecd4871ad88f70a055d2efa7bf))

<!-- generated by git-cliff -->
