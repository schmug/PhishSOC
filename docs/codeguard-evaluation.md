# CoSAI Project CodeGuard — Evaluation and Adoption Decision

**Decision:** Partial-adopt — three rule categories installed under `.claude/rules/`  
**Date:** 2026-05-25 · **Issue:** #321  
**License:** CodeGuard is [CC BY 4.0](https://github.com/cosai-oasis/project-codeguard/blob/main/LICENSE.md). Vendored rule content in `.claude/rules/` is attributed at the file head. Compatible with this repo's Apache-2.0 license (CC BY 4.0 is attribution-only with no copyleft; satisfies Apache-2.0's attribution/NOTICE requirements).

---

## Coverage table

| Category | CodeGuard rules | PhishSOC existing coverage | Decision |
|---|---|---|---|
| **Cryptography** | `codeguard-1-crypto-algorithms.md`, `codeguard-1-digital-certificates.md` | Global CLAUDE.md: "never hand-roll crypto"; no banned-algorithm list for TS/CF Workers | ✅ **Adopt** — banned-algo list (MD5, SHA-1, RC4, DES), AES-GCM requirement, key storage guidance for KV/Secrets |
| **Input Validation** | `codeguard-0-input-validation-injection.md`, SSRF rule | `CLAUDE.md`: `new URL(url).hostname` rule; CodeQL gate on `js/incomplete-url-substring-sanitization` | ✅ **Adopt** (complementary) — D1 parameterized query pattern, prototype pollution in React; URL-host parsing already fully covered by existing rule |
| **Supply Chain** | `codeguard-0-supply-chain-security.md` | No explicit CLAUDE.md rule; `ci.yml` already uses `npm ci` for the deployable artifact | ✅ **Adopt** — SCA gate guidance, SBOM awareness, `npm ci` discipline for all subdirectories |
| **Authentication** | `codeguard-0-authentication-mfa.md`, `codeguard-1-hardcoded-credentials.md` | Global CLAUDE.md: JWT rules; CF Access as auth layer; `SECURITY_SPEC.md` Rule 3: authserv-id allowlist | ❌ **Decline** — CF Access handles MFA/authn at the edge; `jose` with pinned `HS256` covers JWT; `SECURITY_SPEC.md` Rule 3 covers email-specific auth-header parsing |
| **Authorization** | `codeguard-0-authorization-access-control.md` | `SECURITY_SPEC.md` Rule 6: agent send confirmation; ACL subsystem in `workers/routes/` | ❌ **Decline** — Rule 6 covers the highest-risk authorization invariant (human-in-the-loop before send); IDOR risk is low with CF Access scoping every resource lookup to the authenticated mailbox owner |
| **Cloud Security** | `codeguard-0-iac-security.md`, Kubernetes/container rules | Global CLAUDE.md: CF Access service-token defaults; `wrangler.jsonc` is effective IaC | ❌ **Decline** — K8s/container rules don't apply to CF Workers serverless; IaC guidance is Terraform-centric rather than wrangler-specific; no actionable delta |
| **Platform Security** | `codeguard-0-api-web-services.md`, `codeguard-0-client-side-web-security.md` | `SECURITY_SPEC.md` Rules 1–4 for email pipeline; CF Workers adds default security headers | ❌ **Decline** — CF Workers and Cloudflare edge handle most header security by default; the existing spec covers the critical email-pipeline surface; CSP for the React SPA is future work with no reported incident |
| **Data Protection** | `codeguard-0-privacy-data-protection.md`, `codeguard-0-data-storage.md` | R2 encryption at rest (platform-managed); Cloudflare data residency | ❌ **Decline** — R2 provides encryption at rest out of the box; PII retention/classification rules are operator policy for a security operations tool where email storage is the primary product value |

**Coverage summary:** 3 of 8 categories have meaningful new coverage. 5 are already covered by existing PhishSOC invariants or the Cloudflare platform. The ≥80%-redundant-means-decline threshold is not met (62.5% covered) → partial-adopt the three additive categories.

---

## Integration shape chosen: static rules under `.claude/`

The lower-cost static path was chosen over the CodeGuard MCP server because:

- PhishSOC is a single-repo project. An always-on MCP server adds operational overhead (deployment, TLS, SSO, renewal) that isn't justified when three adapted rule files under `.claude/rules/` achieve the same goal.
- The MCP server is the right choice for multi-repo organizations that want centrally-managed rule updates across many codebases. PhishSOC already operates `EmailMCP` for email tooling; adding a second MCP for dev-loop rules would need its own infra story.
- Static rules load into every Claude Code session automatically via `CLAUDE.md` reference. Zero operational cost.

---

## Synthetic violation example — crypto hook firing

The PreToolUse hook added to `.claude/settings.json` catches the following pattern when editing any `workers/**/*.ts` or `app/**/*.ts` file:

```typescript
// ❌ VIOLATION — triggers hook, edit is blocked
const hash = await crypto.subtle.digest("SHA-1", data);
//                                        ^^^^^
```

Hook output:
```
Blocked (CodeGuard crypto rule): "SHA-1" and MD5 are banned hash algorithms.
Use "SHA-256" or stronger. See .claude/rules/codeguard-selected-rules.md.
```

```typescript
// ✅ CORRECT — already in production use
// workers/intel/report.ts, workers/lib/confirm-token.ts
const hash = await crypto.subtle.digest("SHA-256", data);
```

The hook uses `exit 2` (same pattern as the existing MTA-STS and `stripDefaultEqual` hooks) to block the `Edit`/`Write` tool call before the file is written to disk.

---

## Why the declined categories are closed, not deferred

- **Authentication**: The combination of CF Access (edge MFA), `jose` with pinned algorithm headers, and `SECURITY_SPEC.md` Rule 3 makes this a complete story. The CodeGuard auth rules would add guidance about Argon2id password hashing and WebAuthn — neither applies to PhishSOC, which delegates all authn to CF Access and stores no passwords.
- **Authorization**: SECURITY_SPEC.md Rule 6 is a stronger invariant than CodeGuard's generic authorization guidance for this specific threat model (indirect prompt injection via agent → send escalation). The ACL system uses CF Access identity, not user-supplied IDs.
- **Cloud Security**: Kubernetes rules apply to an entirely different infra model. The wrangler.jsonc IaC concern is real but not addressed by CodeGuard's Terraform/Helm-centric guidance. File a separate issue if wrangler configuration hardening becomes a priority.
- **Platform Security**: Cloudflare's default response headers already enforce `X-Content-Type-Options`, `X-Frame-Options`, and HSTS on Workers responses. CSP for the React SPA is a future work item (no reported XSS incident in production).
- **Data Protection**: Platform-handled (R2 encrypted at rest, Cloudflare data residency). PII retention SLAs are operator configuration, not code convention.

---

## Files installed

| File | Purpose |
|---|---|
| `.claude/rules/codeguard-selected-rules.md` | Three adapted CodeGuard rules for TS/CF Workers |
| `.claude/settings.json` (edit) | Added PreToolUse hook for banned crypto algorithms |
| `CLAUDE.md` (edit) | Added "CodeGuard rules" section in Conventions |
