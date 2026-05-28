# Release Support Policy

This document describes the release support policy for PhishSOC: which release
branches receive security fixes, expected support windows, and end-of-life (EOL)
guidelines for older releases.

> **Status (2026-05-28):** No releases have been cut yet. This policy takes
> effect from the first tagged release (`v0.1.0` or later) onward. The policy
> is documented now so adopters can plan accordingly before deploying production
> instances.

---

## Supported Branches

| Branch / Release | Status | Security fixes | Notes |
|---|---|---|---|
| `main` | Active development | Yes — always | Tracks the latest code; suitable for self-hosters who auto-deploy from `main` |
| Latest tagged release | **Current** | Yes — backport patches | The most recent `vX.Y.Z` tag; operators who pin a release should stay on this |
| Previous tagged release | **Maintenance** | Security fixes only, for up to **6 months** after superseded | Minor bugs will not be backported; only CVE-severity issues |
| Older releases | **EOL** | None | No patches; upgrade to the latest release |

PhishSOC currently ships as a single-branch project (`main`) deployed via
Cloudflare Workers. A "release branch" will be created when the first tag is
cut (e.g., `release/v0.1`). Until then, `main` is the only supported branch.

---

## Security Fix Policy

Security vulnerabilities are treated with the highest priority regardless of
the release stream:

1. **Critical / High severity** — A patch is prepared within **7 days** of
   confirmation and backported to both the current and maintenance releases.
2. **Medium severity** — Patched in the next scheduled release; backported to
   the current release. The maintenance release receives a backport if the issue
   is remotely exploitable.
3. **Low severity** — Addressed in the next minor or patch release; not
   backported to older releases.

Security reports should be filed via the [GitHub Security Advisory
form](https://github.com/schmug/PhishSOC/security/advisories/new). Do not open
public issues for unpatched vulnerabilities.

---

## Expected Support Window per Release

| Release type | Support duration | Security fixes |
|---|---|---|
| Major (`vX.0.0`) | Until the next major release, then 12 months maintenance | Yes (see severity policy above) |
| Minor (`vX.Y.0`) | Until superseded by the next minor, then 6 months maintenance | Yes for current + maintenance window |
| Patch (`vX.Y.Z`) | Replaced immediately by the next patch | Current only |

**Example timeline** — if `v0.1.0` is tagged in July 2026 and `v0.2.0` follows
in October 2026:

- `v0.1.x` enters maintenance status in October 2026.
- `v0.1.x` reaches EOL in April 2027 (6 months after being superseded).
- Security issues in `v0.1.x` receive backports only until April 2027.

---

## End-of-Life Policy

A release is considered **end-of-life (EOL)** when:

- Its maintenance window has expired (see table above), **or**
- The release branch is explicitly marked EOL in the
  [GitHub Releases page](https://github.com/schmug/PhishSOC/releases).

Once a release is EOL:

- No further patches, security or otherwise, will be issued.
- The release tag remains on GitHub for archival purposes.
- Issues referencing EOL releases will be closed with a request to upgrade.

Operators running EOL releases in production are strongly encouraged to upgrade.
PhishSOC is deployed as a Cloudflare Worker — re-deploying from a newer tag
requires only `npm run deploy`; there is no database migration step for minor
version bumps unless the release notes call one out explicitly.

---

## Cloudflare-Specific Notes

Because PhishSOC runs on Cloudflare Workers, the runtime itself is managed by
Cloudflare and updated independently. PhishSOC tracks the latest stable
[Workers Runtime compatibility date](https://developers.cloudflare.com/workers/platform/compatibility-dates/)
defined in `wrangler.jsonc`. Operators who self-host from source should keep
the compatibility date current; pinning to a very old date may expose the
deployment to platform-level bugs that are fixed in newer compatibility
milestones.

---

## Changelog

Release notes and a full changelog are maintained at [`CHANGELOG.md`](../CHANGELOG.md)
in the repository root. The changelog is auto-generated from conventional
commits using [git-cliff](https://git-cliff.org/) (config: [`cliff.toml`](../cliff.toml)).
