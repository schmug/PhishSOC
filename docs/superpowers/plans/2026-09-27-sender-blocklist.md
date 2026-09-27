# Sender Blocklist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user block a sender address or domain so future mail from it is silently dropped, bounced with an SMTP message, or filed to Spam.

**Architecture:** Block rules live in a new top-level `blocklist` field on the mailbox, domain and org settings blobs in R2. The settings PUT endpoints never touch it; dedicated endpoints own it. `receiveEmail` evaluates the rules right after the mailbox-exists check and before any storage. `drop` and `reject` return early and write one row to a new `blocked_log` MailboxDO table. For `reject`, the `email()` handler then calls `setReject`. `spam` stores into the Spam folder, and the security pipeline still runs and may escalate to Quarantine. The UI adds a Block sender dialog to the email toolbar and a Blocked senders panel to the three settings pages.

**Tech Stack:** Cloudflare Workers + Durable Objects (SQLite), Hono, Zod, React 19 / React Router v7, `@cloudflare/kumo`, Vitest (Node pool, `node:sqlite` adapters for DO logic).

**Spec:** `docs/superpowers/specs/2026-09-27-sender-blocklist-design.md`

## Global Constraints

- The blocklist is a top-level settings field, never under `security`, because `security` whole-replaces across tiers.
- Actions: exactly `"drop" | "reject" | "spam"`. The UI defaults to `spam`, and to the full address.
- Default reject reason, verbatim: `Unsolicited commercial email refused by recipient`.
- Reject reason: strip CR, LF and other control characters; printable ASCII only; max 200 chars. Empty → the default.
- Refuse public-suffix domain rules. Shared domains (`gmail.com`, `googlemail.com`, `outlook.com`, `hotmail.com`, `live.com`, `yahoo.com`, `icloud.com`, `aol.com`, `proton.me`, `protonmail.com`, `sendgrid.net`, `amazonses.com`, `resend.dev`, `mailgun.org`) require `confirm_shared_domain: true`.
- A domain rule `d` matches the sender domain `d` and any `*.d`. It never matches a parent domain.
- Precedence: mailbox > domain > org. Within a tier, an address rule beats a domain rule. Remaining ties go to the strictest action: `reject` > `drop` > `spam`. An allowlist entry suppresses the block only when it is at a strictly more specific tier than the winning rule.
- Fail open: any error while evaluating the blocklist logs and delivers normally.
- Sidecar (Gmail-polled) mailboxes, identified by `normalized.providerMessageId` being set: `reject` becomes `drop`.
- `blocked_log`: capped at the newest 500 rows and rows under 30 days old; `message_id` UNIQUE with `INSERT OR IGNORE`; `subject` truncated to 120 chars.
- Every settings-tier write runs `stripDefaultEqual` before `BUCKET.put` (repo CLAUDE.md). An empty `blocklist` counts as default-equal.
- Test mocks that route on URLs must parse the hostname, never substring-match (repo CLAUDE.md, CodeQL).
- New files start with `// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.`
- Commit prefixes: `feat:`, `test:`, `fix:`, `docs:`. End each commit message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **A general settings save wipes the blocklist.** Saving the unrelated mailbox, domain or org settings form must leave `blocklist` untouched (Task 2 tests all three PUTs).
2. **Spam-routed mail triggers auto-draft or a desktop notification.** Mail filed to Spam by a rule must not get an agent auto-draft reply, and its notification folder must be `spam` (Task 5 test).
3. **Sender address with odd casing, an IDN domain, or trailing whitespace.** `Noreply@RES.PodView.com` and a Unicode domain must match rules stored in lowercase A-label form (Task 3 test).
4. **An existing receive test fixture lacks `domain`/`org` on the resolved settings.** Evaluation must fail open and still deliver to Inbox (Task 5 test).
5. **A sidecar replay re-drops the same message.** Exactly one `blocked_log` row, and a Gmail replay must not throw (Task 4 test on `INSERT OR IGNORE`).

---

### Task 1: Shared rule schema and validation

**Files:**
- Create: `shared/blocklist.ts`
- Test: `tests/lib/blocklist-rule.test.ts`

**Interfaces:**
- Produces:
  - `BlockAction` (zod enum + type)
  - `BlockRule` (zod + type: `{ id: string; match: string; action: BlockAction; reason?: string; created_at: string }`)
  - `Blocklist` (zod array, max 1000)
  - `DEFAULT_REJECT_REASON: string`
  - `SHARED_SENDER_DOMAINS: ReadonlySet<string>`
  - `toALabel(domain: string): string | null`
  - `normalizeMatch(raw: string): { kind: "address" | "domain"; value: string } | null`
  - `isPublicSuffix(domain: string): boolean`
  - `registrableDomain(domain: string): string`
  - `sanitizeRejectReason(raw: string | undefined): string`
  - `validateBlockRuleInput(input: BlockRuleInput): BlockRuleValidation`
  - `BlockRuleInput = { match: string; action: BlockAction; reason?: string; confirm_shared_domain?: boolean }`
  - `BlockRuleValidation = { ok: true; rule: { match: string; action: BlockAction; reason?: string } } | { ok: false; code: "invalid_match" | "invalid_action" | "public_suffix" | "shared_domain_unconfirmed"; error: string }`

- [ ] **Step 1: Write the failing test**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	DEFAULT_REJECT_REASON,
	isPublicSuffix,
	normalizeMatch,
	registrableDomain,
	sanitizeRejectReason,
	validateBlockRuleInput,
} from "../../shared/blocklist";

describe("normalizeMatch", () => {
	it("lowercases and trims an address", () => {
		expect(normalizeMatch("  Noreply@RES.PodView.com ")).toEqual({ kind: "address", value: "noreply@res.podview.com" });
	});
	it("treats a bare host as a domain", () => {
		expect(normalizeMatch("PodView.com")).toEqual({ kind: "domain", value: "podview.com" });
	});
	it("converts a Unicode domain to its A-label", () => {
		expect(normalizeMatch("bücher.example")).toEqual({ kind: "domain", value: "xn--bcher-kva.example" });
		expect(normalizeMatch("a@bücher.example")).toEqual({ kind: "address", value: "a@xn--bcher-kva.example" });
	});
	it("rejects garbage", () => {
		for (const bad of ["", "@", "a@", "@x.com", "a b@x.com", "x.com/path", "a@@x.com", "http://x.com"]) {
			expect(normalizeMatch(bad), bad).toBeNull();
		}
	});
});

describe("isPublicSuffix / registrableDomain", () => {
	it("flags single labels and multi-label suffixes", () => {
		expect(isPublicSuffix("com")).toBe(true);
		expect(isPublicSuffix("co.uk")).toBe(true);
		expect(isPublicSuffix("podview.com")).toBe(false);
	});
	it("returns the registrable domain", () => {
		expect(registrableDomain("res.podview.com")).toBe("podview.com");
		expect(registrableDomain("mail.foo.co.uk")).toBe("foo.co.uk");
		expect(registrableDomain("podview.com")).toBe("podview.com");
	});
});

describe("sanitizeRejectReason", () => {
	it("defaults when empty", () => {
		expect(sanitizeRejectReason(undefined)).toBe(DEFAULT_REJECT_REASON);
		expect(sanitizeRejectReason("   ")).toBe(DEFAULT_REJECT_REASON);
	});
	it("strips CR/LF and control chars, drops non-ASCII, caps at 200", () => {
		expect(sanitizeRejectReason("Stop\r\n250 OK\tnow")).toBe("Stop250 OKnow");
		expect(sanitizeRejectReason("héllo")).toBe("hllo");
		expect(sanitizeRejectReason("x".repeat(300))).toHaveLength(200);
	});
});

describe("validateBlockRuleInput", () => {
	it("accepts an address rule", () => {
		const r = validateBlockRuleInput({ match: "noreply@res.podview.com", action: "spam" });
		expect(r).toEqual({ ok: true, rule: { match: "noreply@res.podview.com", action: "spam" } });
	});
	it("sanitizes the reason only for reject", () => {
		const r = validateBlockRuleInput({ match: "podview.com", action: "reject", reason: "Go away\r\n" });
		expect(r).toEqual({ ok: true, rule: { match: "podview.com", action: "reject", reason: "Go away" } });
		const s = validateBlockRuleInput({ match: "podview.com", action: "drop", reason: "ignored" });
		expect(s).toEqual({ ok: true, rule: { match: "podview.com", action: "drop" } });
	});
	it("refuses a public suffix", () => {
		expect(validateBlockRuleInput({ match: "co.uk", action: "drop" })).toMatchObject({ ok: false, code: "public_suffix" });
	});
	it("requires confirmation for a shared domain but not for an address on it", () => {
		expect(validateBlockRuleInput({ match: "gmail.com", action: "drop" })).toMatchObject({ ok: false, code: "shared_domain_unconfirmed" });
		expect(validateBlockRuleInput({ match: "gmail.com", action: "drop", confirm_shared_domain: true })).toMatchObject({ ok: true });
		expect(validateBlockRuleInput({ match: "spammer@gmail.com", action: "drop" })).toMatchObject({ ok: true });
	});
	it("refuses an unknown action", () => {
		expect(validateBlockRuleInput({ match: "a@b.com", action: "nuke" as never })).toMatchObject({ ok: false, code: "invalid_action" });
	});
});
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `npx vitest run tests/lib/blocklist-rule.test.ts`
Expected: FAIL. The import `../../shared/blocklist` cannot be resolved.

- [ ] **Step 3: Implement `shared/blocklist.ts`**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sender blocklist rule schema + validation, shared by the UI and Workers.
 * Rules live in a top-level `blocklist` field on the mailbox / domain / org
 * settings blobs (never under `security`, which whole-replaces across tiers).
 * Spec: docs/superpowers/specs/2026-09-27-sender-blocklist-design.md
 */

import { z } from "zod";

export const BlockAction = z.enum(["drop", "reject", "spam"]);
export type BlockAction = z.infer<typeof BlockAction>;

export const BlockRule = z.object({
	id: z.string().min(1),
	match: z.string().min(1),
	action: BlockAction,
	reason: z.string().max(200).optional(),
	created_at: z.string(),
});
export type BlockRule = z.infer<typeof BlockRule>;

export const Blocklist = z.array(BlockRule).max(1000);

export const DEFAULT_REJECT_REASON = "Unsolicited commercial email refused by recipient";

/** Two-label public suffixes common enough to guard against. Not a full PSL:
 *  the guard only refuses obviously-too-broad rules. Single-label domains
 *  (`com`) are refused separately. */
const MULTI_LABEL_PUBLIC_SUFFIXES: ReadonlySet<string> = new Set([
	"co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
	"com.au", "net.au", "org.au", "edu.au", "gov.au",
	"co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "co.za", "co.in",
	"com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.hk",
]);

/** Freemail + ESP bounce domains: a domain rule here blocks unrelated senders. */
export const SHARED_SENDER_DOMAINS: ReadonlySet<string> = new Set([
	"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
	"yahoo.com", "icloud.com", "aol.com", "proton.me", "protonmail.com",
	"sendgrid.net", "amazonses.com", "resend.dev", "mailgun.org",
]);

const HOST_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;

/** Lowercase + IDNA A-label a bare hostname. Null when it is not one. */
export function toALabel(domain: string): string | null {
	const d = domain.trim();
	if (!d || /[\s/:?#@\\]/.test(d)) return null;
	try {
		const host = new URL(`http://${d}`).hostname;
		return HOST_RE.test(host) ? host : null;
	} catch {
		return null;
	}
}

export function normalizeMatch(raw: string): { kind: "address" | "domain"; value: string } | null {
	const v = raw.trim();
	if (!v) return null;
	const at = v.indexOf("@");
	if (at === -1) {
		const host = toALabel(v);
		return host ? { kind: "domain", value: host } : null;
	}
	if (at !== v.lastIndexOf("@")) return null;
	const local = v.slice(0, at);
	if (!local || /[\s]/.test(local)) return null;
	const host = toALabel(v.slice(at + 1));
	return host ? { kind: "address", value: `${local.toLowerCase()}@${host}` } : null;
}

export function isPublicSuffix(domain: string): boolean {
	return !domain.includes(".") || MULTI_LABEL_PUBLIC_SUFFIXES.has(domain);
}

export function registrableDomain(domain: string): string {
	const labels = domain.split(".");
	if (labels.length <= 2) return domain;
	const lastTwo = labels.slice(-2).join(".");
	return MULTI_LABEL_PUBLIC_SUFFIXES.has(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

export function sanitizeRejectReason(raw: string | undefined): string {
	const cleaned = (raw ?? "").replace(/[^\x20-\x7e]/g, "").trim().slice(0, 200);
	return cleaned || DEFAULT_REJECT_REASON;
}

export interface BlockRuleInput {
	match: string;
	action: BlockAction;
	reason?: string;
	confirm_shared_domain?: boolean;
}

export type BlockRuleValidation =
	| { ok: true; rule: { match: string; action: BlockAction; reason?: string } }
	| { ok: false; code: "invalid_match" | "invalid_action" | "public_suffix" | "shared_domain_unconfirmed"; error: string };

export function validateBlockRuleInput(input: BlockRuleInput): BlockRuleValidation {
	const action = BlockAction.safeParse(input?.action);
	if (!action.success) return { ok: false, code: "invalid_action", error: "action must be drop, reject or spam" };
	const m = typeof input.match === "string" ? normalizeMatch(input.match) : null;
	if (!m) return { ok: false, code: "invalid_match", error: "match must be an email address or a domain" };
	if (m.kind === "domain") {
		if (isPublicSuffix(m.value)) {
			return { ok: false, code: "public_suffix", error: `${m.value} is a public suffix; block a specific domain instead` };
		}
		if (SHARED_SENDER_DOMAINS.has(m.value) && input.confirm_shared_domain !== true) {
			return {
				ok: false,
				code: "shared_domain_unconfirmed",
				error: `${m.value} is shared by many unrelated senders; confirm to block the whole domain`,
			};
		}
	}
	const rule: { match: string; action: BlockAction; reason?: string } = { match: m.value, action: action.data };
	if (action.data === "reject") rule.reason = sanitizeRejectReason(input.reason);
	return { ok: true, rule };
}
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `npx vitest run tests/lib/blocklist-rule.test.ts`
Expected: PASS (all tests).

- [ ] **Step 5: Commit**

```bash
git add shared/blocklist.ts tests/lib/blocklist-rule.test.ts
git commit -m "feat(blocklist): shared rule schema and validation"
```

---

### Task 2: Settings schemas and PUT preservation

**Files:**
- Modify: `shared/mailbox-settings.ts:408-423` (MailboxSettings)
- Modify: `shared/domain-settings.ts:118-129` (DomainSettings)
- Modify: `shared/org-settings.ts:32-71` (OrgSettings)
- Modify: `workers/lib/mailbox-settings.ts:455` (`isDefaultEqual`)
- Modify: `workers/lib/org-settings.ts:103-127` (`mergeOrgSettingsPut`)
- Modify: `workers/index.ts:1238-1265` (mailbox PUT); `workers/index.ts:860-885` (domain PUT)
- Test: `tests/routes/blocklist-settings-preserve.test.ts`; extend `tests/lib/merge-org-settings-put.test.ts`

**Interfaces:**
- Consumes: `Blocklist` from Task 1.
- Produces: `MailboxSettings.blocklist`, `DomainSettings.blocklist`, `OrgSettings.blocklist` (all `BlockRule[] | undefined`). `stripDefaultEqual` drops `blocklist: []`. All three general PUTs keep the persisted `blocklist`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/lib/merge-org-settings-put.test.ts`:

```ts
it("preserves the persisted blocklist and ignores an incoming one", () => {
	const rule = { id: "r1", match: "podview.com", action: "drop" as const, created_at: "2026-09-27T00:00:00Z" };
	const merged = mergeOrgSettingsPut(
		{ blocklist: [rule] },
		{ agentModel: "x", blocklist: [] },
	);
	expect(merged.blocklist).toEqual([rule]);
	const mergedNone = mergeOrgSettingsPut({}, { blocklist: [rule] });
	expect(mergedNone.blocklist).toBeUndefined();
});
```

Create `tests/routes/blocklist-settings-preserve.test.ts`:

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * `blocklist` is owned by the dedicated blocklist endpoints. The general
 * mailbox and domain settings PUTs must never wipe or rewrite it
 * (spec: sender-blocklist-design, API section).
 */

import { beforeEach, describe, expect, it } from "vitest";
import { app } from "../../workers/index";
import { stripDefaultEqual } from "../../workers/lib/mailbox-settings";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";

const RULE = { id: "r1", match: "podview.com", action: "drop", created_at: "2026-09-27T00:00:00Z" };

function makeR2(initial: Record<string, string> = {}) {
	const store = new Map<string, string>(Object.entries(initial));
	return {
		async get(key: string) {
			if (!store.has(key)) return null;
			const val = store.get(key)!;
			return { etag: "etag-1", async json() { return JSON.parse(val); } };
		},
		async head(key: string) { return store.has(key) ? { key } : null; },
		async put(key: string, val: string) { store.set(key, val); },
		read(key: string) { return store.get(key); },
	};
}

beforeEach(() => {
	clearDomainSettingsCache();
	clearOrgSettingsCache();
});

describe("stripDefaultEqual", () => {
	it("drops an empty blocklist", () => {
		expect(stripDefaultEqual({ blocklist: [] })).toEqual({});
		expect(stripDefaultEqual({ blocklist: [RULE] })).toEqual({ blocklist: [RULE] });
	});
});

describe("settings PUTs preserve blocklist", () => {
	it("domain PUT keeps the persisted blocklist", async () => {
		const bucket = makeR2({ "domains/example.com.json": JSON.stringify({ blocklist: [RULE] }) });
		const env = { BUCKET: bucket, DOMAINS: "example.com" };
		const res = await app.request(
			"/api/v1/domains/example.com/settings",
			{ method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ settings: { agentModel: "x", blocklist: [] } }) },
			env,
		);
		expect(res.status).toBe(200);
		expect(JSON.parse(bucket.read("domains/example.com.json")!).blocklist).toEqual([RULE]);
	});
});
```

The mailbox PUT runs behind `requireMailbox`/ACL in `app`. Test it at the helper level instead. Extract the preservation into an exported pure helper `preserveOwnedMailboxFields(existing, incoming)` in `workers/lib/mailbox-settings.ts` and add to the same file:

```ts
import { preserveOwnedMailboxFields } from "../../workers/lib/mailbox-settings";

describe("preserveOwnedMailboxFields", () => {
	it("keeps persisted honeypot and blocklist, drops incoming blocklist", () => {
		const out = preserveOwnedMailboxFields(
			{ blocklist: [RULE] as never, honeypot: { provisioned: true } as never },
			{ agentModel: "x", blocklist: [] as never },
		);
		expect(out).toEqual({ agentModel: "x", blocklist: [RULE], honeypot: { provisioned: true } });
		expect(preserveOwnedMailboxFields({}, { blocklist: [RULE] as never })).toEqual({});
	});
});
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `npx vitest run tests/routes/blocklist-settings-preserve.test.ts tests/lib/merge-org-settings-put.test.ts`
Expected: FAIL on `blocklist` assertions and the missing `preserveOwnedMailboxFields` export. The existing merge tests still pass.

- [ ] **Step 3: Implement**

Add `blocklist: Blocklist.optional(),` to `MailboxSettings`, `DomainSettings` and `OrgSettings`, with `import { Blocklist } from "./blocklist";`. Add a doc comment on each: `/** Sender block rules (spec 2026-09-27-sender-blocklist). Written ONLY by the /blocklist endpoints; general PUTs preserve it. */`.

In `workers/lib/mailbox-settings.ts`, add a case to `isDefaultEqual`:

```ts
		case "blocklist":
			return Array.isArray(value) && value.length === 0;
```

Also add the helper:

```ts
/**
 * Fields the general mailbox PUT must never write: `honeypot` (operator
 * provisioning, #24) and `blocklist` (owned by the /blocklist endpoints).
 * Persisted values win; incoming values are discarded.
 */
export function preserveOwnedMailboxFields(existing: MailboxSettings, incoming: MailboxSettings): MailboxSettings {
	const out: MailboxSettings = { ...incoming };
	delete out.blocklist;
	if (existing.honeypot) out.honeypot = existing.honeypot;
	if (existing.blocklist?.length) out.blocklist = existing.blocklist;
	return out;
}
```

In the mailbox PUT (`workers/index.ts` ~1260), replace
```ts
	if (existing.honeypot) {
		settings.honeypot = existing.honeypot;
	}
	await c.env.BUCKET.put(key, JSON.stringify(settings));
```
with the following, and keep the existing comment above it:
```ts
	const toWrite = preserveOwnedMailboxFields(existing, settings);
	await c.env.BUCKET.put(key, JSON.stringify(toWrite));
	return c.json({ id: mailboxId, name: mailboxId, email: mailboxId, settings: toWrite });
```
Delete the old `return` line that follows it.

In the mailbox create (`app.post("/api/v1/mailboxes"`, `workers/index.ts:1034`), after its `stripDefaultEqual` call, add `delete settings.blocklist;` (use that handler's local variable name). Add this comment: "blocklist is owned by /blocklist; a create never seeds it."

In the domain PUT, before `putDomainSettings(c.env, domain, stripped)`:
```ts
	// blocklist is owned by /api/v1/domains/:domain/blocklist — never written here.
	const currentDomain = await getDomainSettings(c.env, domain);
	delete (stripped as DomainSettings).blocklist;
	if (currentDomain.blocklist?.length) (stripped as DomainSettings).blocklist = currentDomain.blocklist;
```

In `mergeOrgSettingsPut`, after the `domains` block:
```ts
	// blocklist is owned by /api/v1/org/blocklist — never trust a PUT payload.
	if (current.blocklist?.length) merged.blocklist = current.blocklist;
	else delete merged.blocklist;
```
Add `- \`blocklist\` — written via POST/DELETE \`/api/v1/org/blocklist\`` to its doc comment list.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `npx vitest run tests/routes/blocklist-settings-preserve.test.ts tests/lib/merge-org-settings-put.test.ts tests/routes/domain-settings-put.test.ts tests/lib/resolve-mailbox-settings.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shared/mailbox-settings.ts shared/domain-settings.ts shared/org-settings.ts workers/lib/mailbox-settings.ts workers/lib/org-settings.ts workers/index.ts tests/routes/blocklist-settings-preserve.test.ts tests/lib/merge-org-settings-put.test.ts
git commit -m "feat(blocklist): settings field, owned-field preservation on PUTs"
```

---

### Task 3: Matcher

**Files:**
- Create: `workers/security/blocklist.ts`
- Test: `test/security/blocklist.test.ts`

**Interfaces:**
- Consumes: `BlockRule`, `toALabel` from `shared/blocklist.ts`. `ResolvedMailboxSettings` (fields `raw`, `domain`, `org`) from `workers/lib/mailbox-settings.ts`.
- Produces:
  - `type BlockTier = "mailbox" | "domain" | "org"`
  - `interface BlockHit { rule: BlockRule; tier: BlockTier }`
  - `interface TierInput { blocklist?: readonly BlockRule[]; allowlist_senders?: readonly string[]; allowlist_domains?: readonly string[] }`
  - `type TierInputs = Partial<Record<BlockTier, TierInput>>`
  - `normalizeSenderAddress(raw: string | null | undefined): string | null`
  - `ruleMatches(match: string, sender: string): "address" | "domain" | null`
  - `matchBlocklist(tiers: TierInputs, fromAddress: string | null | undefined): BlockHit | null`
  - `tierInputsFromResolved(r: { raw?: unknown; domain?: unknown; org?: unknown }): TierInputs`
  - `safeMatchBlocklist(r: { raw?: unknown; domain?: unknown; org?: unknown }, fromAddress: string | null | undefined): BlockHit | null`
  - `applyBlockedOutcome(event: { setReject?: (reason: string) => void }, result: { blocked?: ReceiveBlocked } | null | undefined): void`
  - `interface ReceiveBlocked { action: "drop" | "reject"; ruleId: string; tier: BlockTier; reason?: string }`

- [ ] **Step 1: Write the failing test**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it, vi } from "vitest";
import {
	applyBlockedOutcome,
	matchBlocklist,
	normalizeSenderAddress,
	ruleMatches,
	safeMatchBlocklist,
	type TierInputs,
} from "../../workers/security/blocklist";

const rule = (id: string, match: string, action: "drop" | "reject" | "spam") => ({ id, match, action, created_at: "t" });

describe("normalizeSenderAddress", () => {
	it("lowercases, trims and A-labels the domain", () => {
		expect(normalizeSenderAddress(" Noreply@RES.PodView.com ")).toBe("noreply@res.podview.com");
		expect(normalizeSenderAddress("a@bücher.example")).toBe("a@xn--bcher-kva.example");
	});
	it("returns null for missing or malformed", () => {
		expect(normalizeSenderAddress(undefined)).toBeNull();
		expect(normalizeSenderAddress("")).toBeNull();
		expect(normalizeSenderAddress("no-at-sign")).toBeNull();
	});
});

describe("ruleMatches", () => {
	it("matches address exactly and domain + subdomains, never parents", () => {
		expect(ruleMatches("noreply@res.podview.com", "noreply@res.podview.com")).toBe("address");
		expect(ruleMatches("podview.com", "noreply@res.podview.com")).toBe("domain");
		expect(ruleMatches("res.podview.com", "x@podview.com")).toBeNull();
		expect(ruleMatches("podview.com", "x@notpodview.com")).toBeNull();
	});
});

describe("matchBlocklist", () => {
	it("returns null with no rules or no sender", () => {
		expect(matchBlocklist({}, "a@b.com")).toBeNull();
		expect(matchBlocklist({ mailbox: { blocklist: [rule("1", "b.com", "drop")] } }, undefined)).toBeNull();
	});
	it("most specific tier wins", () => {
		const tiers: TierInputs = {
			org: { blocklist: [rule("o", "podview.com", "reject")] },
			mailbox: { blocklist: [rule("m", "podview.com", "spam")] },
		};
		expect(matchBlocklist(tiers, "x@podview.com")).toMatchObject({ tier: "mailbox", rule: { id: "m" } });
	});
	it("address beats domain within a tier, then strictest action", () => {
		const tiers: TierInputs = {
			mailbox: { blocklist: [rule("d", "podview.com", "reject"), rule("a", "x@podview.com", "spam")] },
		};
		expect(matchBlocklist(tiers, "x@podview.com")?.rule.id).toBe("a");
		const tie: TierInputs = { mailbox: { blocklist: [rule("s", "podview.com", "spam"), rule("r", "podview.com", "reject")] } };
		expect(matchBlocklist(tie, "x@podview.com")?.rule.id).toBe("r");
	});
	it("an allowlist entry suppresses only from a strictly more specific tier", () => {
		const orgBlock = { blocklist: [rule("o", "podview.com", "drop")] };
		expect(matchBlocklist({ org: orgBlock, mailbox: { allowlist_senders: ["x@podview.com"] } }, "x@podview.com")).toBeNull();
		expect(matchBlocklist({ org: { ...orgBlock, allowlist_domains: ["podview.com"] } }, "x@podview.com")?.rule.id).toBe("o");
		expect(matchBlocklist({ mailbox: { blocklist: [rule("m", "podview.com", "drop")] }, org: { allowlist_domains: ["podview.com"] } }, "x@podview.com")?.rule.id).toBe("m");
	});
	it("matches mixed-case and Unicode senders", () => {
		const tiers: TierInputs = { mailbox: { blocklist: [rule("1", "xn--bcher-kva.example", "drop"), rule("2", "noreply@res.podview.com", "drop")] } };
		expect(matchBlocklist(tiers, "Sales@BÜCHER.example")?.rule.id).toBe("1");
		expect(matchBlocklist(tiers, "NoReply@Res.PodView.com ")?.rule.id).toBe("2");
	});
});

describe("safeMatchBlocklist", () => {
	it("reads tiers off resolved settings and tolerates missing tiers", () => {
		expect(safeMatchBlocklist({ raw: {} }, "a@b.com")).toBeNull();
		expect(safeMatchBlocklist({ raw: { blocklist: [rule("1", "b.com", "drop")] } }, "a@b.com")).toMatchObject({ tier: "mailbox" });
	});
	it("fails open on malformed settings", () => {
		expect(safeMatchBlocklist({ raw: { blocklist: "nope" } }, "a@b.com")).toBeNull();
	});
});

describe("applyBlockedOutcome", () => {
	it("calls setReject once for reject and never otherwise", () => {
		const setReject = vi.fn();
		applyBlockedOutcome({ setReject }, { blocked: { action: "reject", ruleId: "r", tier: "mailbox", reason: "Go away" } });
		expect(setReject).toHaveBeenCalledExactlyOnceWith("Go away");
		setReject.mockClear();
		applyBlockedOutcome({ setReject }, { blocked: { action: "drop", ruleId: "r", tier: "mailbox" } });
		applyBlockedOutcome({ setReject }, null);
		expect(setReject).not.toHaveBeenCalled();
	});
});
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `npx vitest run test/security/blocklist.test.ts`
Expected: FAIL. The module `workers/security/blocklist` does not exist.

- [ ] **Step 3: Implement `workers/security/blocklist.ts`**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sender blocklist matcher. Pure — no I/O. Called from `receiveEmail` before
 * any storage. Precedence: mailbox > domain > org; address beats domain
 * within a tier; ties → strictest action. An allowlist entry suppresses a
 * block only from a strictly more specific tier. Any error fails open.
 * Spec: docs/superpowers/specs/2026-09-27-sender-blocklist-design.md
 */

import { toALabel, type BlockRule } from "../../shared/blocklist";

export type BlockTier = "mailbox" | "domain" | "org";
export interface BlockHit { rule: BlockRule; tier: BlockTier }
export interface TierInput {
	blocklist?: readonly BlockRule[];
	allowlist_senders?: readonly string[];
	allowlist_domains?: readonly string[];
}
export type TierInputs = Partial<Record<BlockTier, TierInput>>;
export interface ReceiveBlocked { action: "drop" | "reject"; ruleId: string; tier: BlockTier; reason?: string }

const TIER_RANK: Record<BlockTier, number> = { mailbox: 3, domain: 2, org: 1 };
const ACTION_RANK: Record<BlockRule["action"], number> = { reject: 3, drop: 2, spam: 1 };
const TIERS: BlockTier[] = ["mailbox", "domain", "org"];

export function normalizeSenderAddress(raw: string | null | undefined): string | null {
	const v = (raw ?? "").trim();
	const at = v.lastIndexOf("@");
	if (at <= 0 || at === v.length - 1) return null;
	const host = toALabel(v.slice(at + 1));
	return host ? `${v.slice(0, at).toLowerCase()}@${host}` : null;
}

function domainOf(sender: string): string {
	return sender.slice(sender.lastIndexOf("@") + 1);
}

function domainCovers(ruleDomain: string, senderDomain: string): boolean {
	return senderDomain === ruleDomain || senderDomain.endsWith(`.${ruleDomain}`);
}

export function ruleMatches(match: string, sender: string): "address" | "domain" | null {
	const m = match.toLowerCase();
	if (m.includes("@")) return m === sender ? "address" : null;
	return domainCovers(m, domainOf(sender)) ? "domain" : null;
}

function allowedAt(input: TierInput | undefined, sender: string): boolean {
	if (!input) return false;
	const d = domainOf(sender);
	return (
		(input.allowlist_senders ?? []).some((s) => s.toLowerCase() === sender) ||
		(input.allowlist_domains ?? []).some((a) => domainCovers(a.toLowerCase(), d))
	);
}

export function matchBlocklist(tiers: TierInputs, fromAddress: string | null | undefined): BlockHit | null {
	const sender = normalizeSenderAddress(fromAddress);
	if (!sender) return null;
	let best: { hit: BlockHit; kind: "address" | "domain" } | null = null;
	for (const tier of TIERS) {
		for (const rule of tiers[tier]?.blocklist ?? []) {
			const kind = ruleMatches(rule.match, sender);
			if (!kind) continue;
			const cand = { hit: { rule, tier }, kind };
			if (!best || better(cand, best)) best = cand;
		}
	}
	if (!best) return null;
	const winningRank = TIER_RANK[best.hit.tier];
	const suppressed = TIERS.some((t) => TIER_RANK[t] > winningRank && allowedAt(tiers[t], sender));
	return suppressed ? null : best.hit;
}

function better(
	a: { hit: BlockHit; kind: "address" | "domain" },
	b: { hit: BlockHit; kind: "address" | "domain" },
): boolean {
	const t = TIER_RANK[a.hit.tier] - TIER_RANK[b.hit.tier];
	if (t !== 0) return t > 0;
	if (a.kind !== b.kind) return a.kind === "address";
	return ACTION_RANK[a.hit.rule.action] > ACTION_RANK[b.hit.rule.action];
}

function tierInput(blob: unknown): TierInput | undefined {
	if (!blob || typeof blob !== "object") return undefined;
	const b = blob as { blocklist?: unknown; security?: { allowlist_senders?: unknown; allowlist_domains?: unknown } };
	const arr = (v: unknown) => (Array.isArray(v) ? v : undefined);
	return {
		blocklist: arr(b.blocklist) as BlockRule[] | undefined,
		allowlist_senders: arr(b.security?.allowlist_senders) as string[] | undefined,
		allowlist_domains: arr(b.security?.allowlist_domains) as string[] | undefined,
	};
}

export function tierInputsFromResolved(r: { raw?: unknown; domain?: unknown; org?: unknown }): TierInputs {
	return { mailbox: tierInput(r.raw), domain: tierInput(r.domain), org: tierInput(r.org) };
}

export function safeMatchBlocklist(
	r: { raw?: unknown; domain?: unknown; org?: unknown },
	fromAddress: string | null | undefined,
): BlockHit | null {
	try {
		return matchBlocklist(tierInputsFromResolved(r), fromAddress);
	} catch (e) {
		console.error("blocklist evaluation failed (fail-open):", (e as Error).message);
		return null;
	}
}

export function applyBlockedOutcome(
	event: { setReject?: (reason: string) => void },
	result: { blocked?: ReceiveBlocked } | null | undefined,
): void {
	if (result?.blocked?.action === "reject" && result.blocked.reason) {
		event.setReject?.(result.blocked.reason);
	}
}
```

The malformed-settings test passes a string where the array belongs. `tierInput` coerces a non-array to `undefined`, so there is no throw. The `try` guards any future throw.

- [ ] **Step 4: Run the test and confirm it passes**

Run: `npx vitest run test/security/blocklist.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/security/blocklist.ts test/security/blocklist.test.ts
git commit -m "feat(blocklist): tiered sender matcher with fail-open wrapper"
```

---

### Task 4: MailboxDO — `blocked_log`, `blocked_by_rule`, bulk move

**Files:**
- Create: `workers/durableObject/blocked-log.ts`
- Modify: `workers/durableObject/migrations.ts` (append after `33_send_risk_llm_cache`, ~line 730)
- Modify: `workers/db/schema.ts:12-40` (`emails` table)
- Modify: `workers/durableObject/index.ts:108` (`EmailData`), `:958-1005` (`createEmail` values), plus delegates near `moveEmail` (`:661`)
- Test: `test/durableObject/blocked-log.test.ts`

**Interfaces:**
- Consumes: `ruleMatches`, `normalizeSenderAddress` from Task 3.
- Produces:
  - `BLOCKED_LOG_MAX_ROWS = 500`, `BLOCKED_LOG_MAX_AGE_MS = 30 * 86_400_000`
  - `interface BlockedLogInput { ts: string; rule_id: string; tier: string; action: "drop" | "reject"; sender: string; subject: string; message_id: string | null }`
  - `_appendBlockedLogImpl(sql: SqlLike, row: BlockedLogInput, nowMs?: number): void`
  - `_listBlockedLogImpl(sql: SqlLike, limit?: number): Array<BlockedLogInput & { id: number }>`
  - `_moveEmailsFromSenderImpl(sql: SqlLike, match: string, fromFolders: readonly string[], toFolder: string): number`
  - DO methods: `appendBlockedLog(row)`, `listBlockedLog(limit)`, `moveEmailsFromSender(match, toFolder)` (from Inbox and Archive only)
  - `EmailData.blocked_by_rule?: string | null`, holding JSON `{"id","match","tier"}`

- [ ] **Step 1: Write the failing test**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import type { SqlLike } from "../../workers/durableObject/catchall-intel";
import {
	BLOCKED_LOG_MAX_ROWS,
	_appendBlockedLogImpl,
	_listBlockedLogImpl,
	_moveEmailsFromSenderImpl,
} from "../../workers/durableObject/blocked-log";
import { mailboxMigrations } from "../../workers/durableObject/migrations";

function makeSqlLike(): SqlLike {
	const db = new DatabaseSync(":memory:");
	const blocked = mailboxMigrations.find((m) => m.name === "34_blocked_log")!;
	db.exec(blocked.sql);
	db.exec(`CREATE TABLE emails (id TEXT PRIMARY KEY, folder_id TEXT NOT NULL, sender TEXT)`);
	return {
		exec(sql: string, ...params: unknown[]) {
			const stmt = db.prepare(sql);
			return /^\s*select/i.test(sql) ? (stmt.all(...(params as never[])) as never) : (stmt.run(...(params as never[])), [] as never);
		},
	};
}

const row = (i: number, over: Partial<Parameters<typeof _appendBlockedLogImpl>[1]> = {}) => ({
	ts: new Date(Date.UTC(2026, 8, 27, 0, 0, i)).toISOString(),
	rule_id: "r1", tier: "mailbox", action: "drop" as const,
	sender: "x@podview.com", subject: "s", message_id: `m${i}@x`, ...over,
});

describe("blocked_log", () => {
	it("appends, lists newest first, truncates subject to 120", () => {
		const sql = makeSqlLike();
		_appendBlockedLogImpl(sql, row(1, { subject: "y".repeat(300) }), Date.UTC(2026, 8, 27));
		_appendBlockedLogImpl(sql, row(2), Date.UTC(2026, 8, 27));
		const rows = _listBlockedLogImpl(sql, 10);
		expect(rows.map((r) => r.message_id)).toEqual(["m2@x", "m1@x"]);
		expect(rows[1].subject).toHaveLength(120);
	});
	it("dedupes on message_id (sidecar replay) but keeps null ids", () => {
		const sql = makeSqlLike();
		_appendBlockedLogImpl(sql, row(1), Date.UTC(2026, 8, 27));
		_appendBlockedLogImpl(sql, row(1), Date.UTC(2026, 8, 27));
		_appendBlockedLogImpl(sql, row(2, { message_id: null }), Date.UTC(2026, 8, 27));
		_appendBlockedLogImpl(sql, row(3, { message_id: null }), Date.UTC(2026, 8, 27));
		expect(_listBlockedLogImpl(sql, 10)).toHaveLength(3);
	});
	it("prunes beyond the row cap and older than 30 days", () => {
		const sql = makeSqlLike();
		const now = Date.UTC(2026, 8, 27);
		_appendBlockedLogImpl(sql, row(0, { ts: new Date(now - 31 * 86_400_000).toISOString() }), now);
		for (let i = 1; i <= BLOCKED_LOG_MAX_ROWS + 5; i++) _appendBlockedLogImpl(sql, row(i), now);
		const rows = _listBlockedLogImpl(sql, 1000);
		expect(rows).toHaveLength(BLOCKED_LOG_MAX_ROWS);
		expect(rows.some((r) => r.message_id === "m0@x")).toBe(false);
	});
});

describe("_moveEmailsFromSenderImpl", () => {
	it("moves matching senders from the listed folders only", () => {
		const sql = makeSqlLike();
		sql.exec(`INSERT INTO emails VALUES ('1','inbox','noreply@res.podview.com'), ('2','archive','a@podview.com'), ('3','sent','a@podview.com'), ('4','inbox','a@notpodview.com')`);
		expect(_moveEmailsFromSenderImpl(sql, "podview.com", ["inbox", "archive"], "spam")).toBe(2);
		const folders = [...sql.exec<{ id: string; folder_id: string }>(`SELECT id, folder_id FROM emails ORDER BY id`)];
		expect(folders.map((f) => f.folder_id)).toEqual(["spam", "spam", "sent", "inbox"]);
	});
});
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `npx vitest run test/durableObject/blocked-log.test.ts`
Expected: FAIL. The module `blocked-log` does not exist and migration `34_blocked_log` is undefined.

- [ ] **Step 3: Implement**

Append the migrations to `mailboxMigrations`:

```ts
	{
		// Sender blocklist audit log (spec 2026-09-27-sender-blocklist). One
		// row per dropped/rejected inbound message — those are never stored,
		// so this is the only trace. message_id UNIQUE + INSERT OR IGNORE
		// absorbs sidecar at-least-once replays (NULLs never collide).
		// Pruned on insert to 500 rows / 30 days (blocked-log.ts).
		name: "34_blocked_log",
		sql: `
            CREATE TABLE IF NOT EXISTS blocked_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT NOT NULL,
                rule_id    TEXT NOT NULL,
                tier       TEXT NOT NULL,
                action     TEXT NOT NULL,
                sender     TEXT NOT NULL,
                subject    TEXT NOT NULL,
                message_id TEXT UNIQUE
            );
            CREATE INDEX IF NOT EXISTS idx_blocked_log_ts ON blocked_log(ts DESC);
        `,
	},
	{
		// Rule that filed a message into Spam (JSON {id, match, tier}); NULL
		// otherwise. Read by SecurityVerdictPanel. Forward-only ALTER.
		name: "35_emails_blocked_by_rule",
		sql: `ALTER TABLE emails ADD COLUMN blocked_by_rule TEXT;`,
	},
```

In `workers/db/schema.ts` `emails`, after `raw_headers`:
```ts
	// Sender-blocklist rule that routed this message to Spam (JSON {id, match, tier}).
	blocked_by_rule: text("blocked_by_rule"),
```

In `EmailData` add `blocked_by_rule?: string | null;`. In `createEmail` `.values({...})` add `blocked_by_rule: email.blocked_by_rule ?? null,`.

Create `workers/durableObject/blocked-log.ts`:

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sender-blocklist audit log + bulk sender move. Pure `_xImpl(sql, ...)`
 * functions, testable on node:sqlite (same pattern as sidecar-state.ts).
 */

import type { SqlLike } from "./catchall-intel";
import { normalizeSenderAddress, ruleMatches } from "../security/blocklist";

export const BLOCKED_LOG_MAX_ROWS = 500;
export const BLOCKED_LOG_MAX_AGE_MS = 30 * 86_400_000;

export interface BlockedLogInput {
	ts: string;
	rule_id: string;
	tier: string;
	action: "drop" | "reject";
	sender: string;
	subject: string;
	message_id: string | null;
}

export function _appendBlockedLogImpl(sql: SqlLike, row: BlockedLogInput, nowMs = Date.now()): void {
	sql.exec(
		`INSERT OR IGNORE INTO blocked_log (ts, rule_id, tier, action, sender, subject, message_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
		row.ts, row.rule_id, row.tier, row.action, row.sender, row.subject.slice(0, 120), row.message_id,
	);
	sql.exec(`DELETE FROM blocked_log WHERE ts < ?`, new Date(nowMs - BLOCKED_LOG_MAX_AGE_MS).toISOString());
	sql.exec(
		`DELETE FROM blocked_log WHERE id NOT IN (SELECT id FROM blocked_log ORDER BY ts DESC, id DESC LIMIT ?)`,
		BLOCKED_LOG_MAX_ROWS,
	);
}

export function _listBlockedLogImpl(sql: SqlLike, limit = 50): Array<BlockedLogInput & { id: number }> {
	const n = Math.min(Math.max(Math.trunc(limit) || 50, 1), BLOCKED_LOG_MAX_ROWS);
	return [
		...sql.exec<BlockedLogInput & { id: number }>(
			`SELECT id, ts, rule_id, tier, action, sender, subject, message_id
             FROM blocked_log ORDER BY ts DESC, id DESC LIMIT ?`,
			n,
		),
	];
}

export function _moveEmailsFromSenderImpl(
	sql: SqlLike,
	match: string,
	fromFolders: readonly string[],
	toFolder: string,
): number {
	if (fromFolders.length === 0) return 0;
	const placeholders = fromFolders.map(() => "?").join(", ");
	const rows = [
		...sql.exec<{ id: string; sender: string | null }>(
			`SELECT id, sender FROM emails WHERE folder_id IN (${placeholders})`,
			...fromFolders,
		),
	];
	let moved = 0;
	for (const r of rows) {
		const sender = normalizeSenderAddress(r.sender);
		if (!sender || !ruleMatches(match, sender)) continue;
		sql.exec(`UPDATE emails SET folder_id = ? WHERE id = ?`, toFolder, r.id);
		moved++;
	}
	return moved;
}
```

Add delegates to `MailboxDO` next to `moveEmail`:

```ts
	// ── Sender blocklist (spec 2026-09-27-sender-blocklist) ─────────────
	async appendBlockedLog(row: BlockedLogInput) {
		_appendBlockedLogImpl(this.ctx.storage.sql as SqlLike, row);
	}

	async listBlockedLog(limit = 50) {
		return _listBlockedLogImpl(this.ctx.storage.sql as SqlLike, limit);
	}

	/** Retroactive block: file existing Inbox/Archive mail from `match` into `toFolder`. */
	async moveEmailsFromSender(match: string, toFolder: string) {
		return _moveEmailsFromSenderImpl(this.ctx.storage.sql as SqlLike, match, [Folders.INBOX, Folders.ARCHIVE], toFolder);
	}
```

Also add `import { _appendBlockedLogImpl, _listBlockedLogImpl, _moveEmailsFromSenderImpl, type BlockedLogInput } from "./blocked-log";`.

- [ ] **Step 4: Run the test and confirm it passes**

Run: `npx vitest run test/durableObject/blocked-log.test.ts test/durableObject/sidecar-state.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/durableObject/blocked-log.ts workers/durableObject/migrations.ts workers/db/schema.ts workers/durableObject/index.ts test/durableObject/blocked-log.test.ts
git commit -m "feat(blocklist): MailboxDO blocked_log, blocked_by_rule column, bulk sender move"
```

---

### Task 5: Enforce in `receiveEmail` and `email()`

**Files:**
- Modify: `workers/index.ts:1643-1646` (`ReceiveEmailResult`), `:1663-1760` (`receiveEmail` head and `createEmail` folder), `:1840-1870` (pipeline `targetFolder` and the quarantine move), `:1936-1941` (`finalFolder`), `:2033-2045` (auto-draft gate)
- Modify: `workers/app.ts:170-190` (`email()` handler)
- Test: `tests/workers/receive-email-blocklist.test.ts`

**Interfaces:**
- Consumes: `safeMatchBlocklist`, `applyBlockedOutcome`, `ReceiveBlocked` (Task 3); DO `appendBlockedLog` (Task 4); `EmailData.blocked_by_rule` (Task 4).
- Produces: `ReceiveEmailResult.blocked?: ReceiveBlocked`. For `drop`/`reject`: `{ messageId, verdict: null, blocked }`. The sidecar caller (`workers/providers/workspace.ts:345`) already `continue`s on a null verdict, so it needs no change.

- [ ] **Step 1: Write the failing test**

Copy the harness from `tests/workers/receive-email-result.test.ts` lines 1-100: the mocks, `makeNormalized`, `makeStub`, `makeEnv`, `makeCtx` and `makeResolvedSettings`. Add `appendBlockedLog: vi.fn().mockResolvedValue(undefined)` to `makeStub`, and extend `makeResolvedSettings` to accept `domain`/`org`. Then:

```ts
const DROP = { id: "r-drop", match: "evil.example", action: "drop", created_at: "t" };
const REJECT = { id: "r-rej", match: "evil.example", action: "reject", reason: "Go away", created_at: "t" };
const SPAM = { id: "r-spam", match: "attacker@evil.example", action: "spam", created_at: "t" };

describe("receiveEmail sender blocklist", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		mockedPipeline.mockResolvedValue({ verdict: null, skipped: true, stageTrace: [] } as never);
	});

	it("drop: stores nothing, writes one audit row", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		mockedResolve.mockResolvedValue(makeResolvedSettings({ raw: { blocklist: [DROP] } }));
		const res = await receiveEmail(makeNormalized(), env, makeCtx());
		expect(res?.blocked).toMatchObject({ action: "drop", ruleId: "r-drop", tier: "mailbox" });
		expect(stub.createEmail).not.toHaveBeenCalled();
		expect(env.BUCKET.put).not.toHaveBeenCalled();
		expect(mockedPipeline).not.toHaveBeenCalled();
		expect(stub.appendBlockedLog).toHaveBeenCalledOnce();
	});

	it("reject: returns the reason for setReject", async () => {
		const stub = makeStub();
		mockedResolve.mockResolvedValue(makeResolvedSettings({ raw: { blocklist: [REJECT] } }));
		const res = await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());
		expect(res?.blocked).toEqual({ action: "reject", ruleId: "r-rej", tier: "mailbox", reason: "Go away" });
		expect(stub.createEmail).not.toHaveBeenCalled();
	});

	it("reject on a sidecar mailbox downgrades to drop", async () => {
		const stub = makeStub();
		mockedResolve.mockResolvedValue(makeResolvedSettings({ raw: { blocklist: [REJECT] } }));
		const res = await receiveEmail({ ...makeNormalized(), providerMessageId: "g-1" }, makeEnv(stub), makeCtx());
		expect(res?.blocked?.action).toBe("drop");
		expect(res?.blocked?.reason).toBeUndefined();
	});

	it("an audit write failure still drops", async () => {
		const stub = makeStub();
		stub.appendBlockedLog.mockRejectedValue(new Error("do down"));
		mockedResolve.mockResolvedValue(makeResolvedSettings({ raw: { blocklist: [DROP] } }));
		const res = await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());
		expect(res?.blocked?.action).toBe("drop");
		expect(stub.createEmail).not.toHaveBeenCalled();
	});

	it("spam: stores in Spam with the rule, runs the pipeline with targetFolder spam, no auto-draft", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		mockedResolve.mockResolvedValue(makeResolvedSettings({ raw: { blocklist: [SPAM] }, autoDraft: { enabled: true } }));
		const res = await receiveEmail(makeNormalized(), env, makeCtx());
		expect(res?.blocked).toBeUndefined();
		expect(stub.createEmail).toHaveBeenCalledWith(
			"spam",
			expect.objectContaining({ blocked_by_rule: JSON.stringify({ id: "r-spam", match: "attacker@evil.example", tier: "mailbox" }) }),
			expect.anything(),
		);
		expect(mockedPipeline).toHaveBeenCalledWith(expect.objectContaining({ targetFolder: "spam" }));
		expect(stub.notifyNewEmail).toHaveBeenCalledWith(expect.any(String), "spam");
		expect(env.EMAIL_AGENT.get).not.toHaveBeenCalled();
	});

	it("spam + pipeline quarantine escalates to Quarantine", async () => {
		const stub = makeStub();
		mockedResolve.mockResolvedValue(makeResolvedSettings({ raw: { blocklist: [SPAM] } }));
		mockedPipeline.mockResolvedValue({
			verdict: { action: "quarantine", score: 80, explanation: "x", signals: [], confidence: 0.9 },
			skipped: false, stageTrace: [],
		} as never);
		await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());
		expect(stub.moveEmail).toHaveBeenCalledWith(expect.any(String), "quarantine");
	});

	it("fails open when resolved settings lack domain/org and a settings read throws", async () => {
		const stub = makeStub();
		mockedResolve.mockRejectedValueOnce(new Error("r2 down")).mockResolvedValue(makeResolvedSettings({}));
		const res = await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());
		expect(res?.blocked).toBeUndefined();
		expect(stub.createEmail).toHaveBeenCalledWith("inbox", expect.anything(), expect.anything());
	});
});
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `npx vitest run tests/workers/receive-email-blocklist.test.ts`
Expected: FAIL. `res.blocked` is undefined and `createEmail` is called with `"inbox"`.

- [ ] **Step 3: Implement**

`ReceiveEmailResult` becomes:
```ts
export interface ReceiveEmailResult {
	messageId: string;
	verdict: FinalVerdict | null;
	/** Set when a sender-blocklist drop/reject rule stopped the message before storage. */
	blocked?: ReceiveBlocked;
}
```

In `receiveEmail`, directly after the mailbox-exists `head` check and before `const stub = …`:

```ts
	// Sender blocklist (spec 2026-09-27-sender-blocklist). Runs before any
	// storage. Fail-open: a settings read or evaluation error delivers normally.
	const blockSettings = await resolveMailboxSettings(env, mailboxId).catch((e) => {
		console.error("blocklist settings resolve failed (fail-open):", (e as Error).message);
		return null;
	});
	const blockHit = blockSettings ? safeMatchBlocklist(blockSettings, parsedEmail.from?.address) : null;
```

Then, after `const stub = env.MAILBOX.get(...)`:

```ts
	if (blockHit && blockHit.rule.action !== "spam") {
		// No SMTP session to reject on for API-polled (sidecar) mailboxes.
		const action = blockHit.rule.action === "reject" && !normalized.providerMessageId ? "reject" : "drop";
		await (stub as any)
			.appendBlockedLog({
				ts: new Date().toISOString(),
				rule_id: blockHit.rule.id,
				tier: blockHit.tier,
				action,
				sender: (parsedEmail.from?.address || "").toLowerCase(),
				subject: parsedEmail.subject || "",
				message_id: parsedEmail.messageId ? parsedEmail.messageId.replace(/^<|>$/g, "") : null,
			})
			.catch((e: Error) => console.error("appendBlockedLog failed:", e.message));
		const blocked: ReceiveBlocked = { action, ruleId: blockHit.rule.id, tier: blockHit.tier };
		if (action === "reject") blocked.reason = sanitizeRejectReason(blockHit.rule.reason);
		return { messageId, verdict: null, blocked };
	}
	const spamRule = blockHit?.rule.action === "spam" ? blockHit : null;
	const inboundFolder = spamRule ? Folders.SPAM : Folders.INBOX;
```

In `stub.createEmail(Folders.INBOX, {...})`, change the first argument to `inboundFolder` and add
`blocked_by_rule: spamRule ? JSON.stringify({ id: spamRule.rule.id, match: spamRule.rule.match, tier: spamRule.tier }) : null,`.

In `runSecurityPipeline({... targetFolder: Folders.INBOX ...})`, change it to `targetFolder: inboundFolder`. Update the comment above it: "Blocklist `spam` rules land mail in SPAM; the folder-bypass tier honours that folder's policy."

`finalFolder`: replace `: Folders.INBOX;` with `: inboundFolder;`.

Auto-draft gate: change `if (mailboxSettings.raw?.sidecar || !mailboxSettings.autoDraft.enabled)` to `if (spamRule || mailboxSettings.raw?.sidecar || !mailboxSettings.autoDraft.enabled)`. Add a comment: "Never auto-draft replies to mail the user blocked to Spam."

Add these imports: `safeMatchBlocklist`, `type ReceiveBlocked` from `./security/blocklist`, and `sanitizeRejectReason` from `../shared/blocklist`.

In `workers/app.ts` `email()`:
- Add `setReject?: (reason: string) => void` to the `event` type, with the comment: "Runtime ForwardableEmailMessage method; permanent SMTP reject during the session (no backscatter)."
- Change `await receiveEmail(normalized, env, ctx);` to:
```ts
				applyBlockedOutcome(event, await receiveEmail(normalized, env, ctx));
```
- Import `applyBlockedOutcome` from `./security/blocklist`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `npx vitest run tests/workers/ tests/providers/workspace-poll.test.ts tests/providers/workspace-verdict.test.ts tests/routes/honeypot-receive-guard.test.ts tests/routes/new-email-notify.test.ts tests/dmarc/receive-email-ruf.test.ts tests/security/thread-auth-gate.test.ts`
Expected: PASS. The existing receive tests are unaffected because their resolved settings have no `blocklist`.

- [ ] **Step 5: Commit**

```bash
git add workers/index.ts workers/app.ts tests/workers/receive-email-blocklist.test.ts
git commit -m "feat(blocklist): enforce drop/reject/spam at ingest before storage"
```

---

### Task 6: Blocklist API routes

**Files:**
- Create: `workers/routes/blocklist.ts`
- Modify: `workers/index.ts:~171` (mount routes)
- Test: `tests/routes/blocklist.test.ts`

**Interfaces:**
- Consumes: `validateBlockRuleInput` (Task 1); `stripDefaultEqual` (Task 2); DO `moveEmailsFromSender`, `listBlockedLog` (Task 4); `getOrgSettings`, `putOrgSettings`, `clearOrgSettingsCache` (`workers/lib/org-settings.ts`); `getDomainSettings`, `putDomainSettings` (`workers/lib/domain-settings.ts`); the owned-domain check used by the domain PUT at `workers/index.ts:870-877`.
- Produces:
  - `mailboxBlocklistRoutes` (Hono<MailboxContext>), mounted at `/api/v1/mailboxes/:mailboxId`. Routes: `POST /blocklist` → `201 { rule, moved }`; `DELETE /blocklist/:ruleId` → `204` or `404`; `GET /blocked-log?limit=` → `{ rows }`.
  - `orgBlocklistRoutes`, mounted at `/api/v1/org/blocklist`: `POST /` and `DELETE /:ruleId`.
  - `domainBlocklistRoutes`, mounted at `/api/v1/domains/:domain/blocklist`: `POST /` and `DELETE /:ruleId`; `403` when the domain is not owned.
  - Error responses: `400 { error, code }` with `code` from `BlockRuleValidation`.
  - Pure helper `appendRule(existing: BlockRule[] | undefined, rule, now: string, id: string): BlockRule[]`. It replaces any existing rule with the same `match`, so each match has one action per tier.

- [ ] **Step 1: Write the failing test**

Mailbox routes: use the `tests/routes/cases.test.ts` pattern. Mock `requireMailbox` to a no-op and inject `mailboxStub` via a parent middleware. Org and domain routes: use `app.request` with the `makeR2` store from `tests/routes/domain-settings-put.test.ts`. Tests:

```ts
// mailbox tier
it("POST appends a validated rule, strips defaults, moves existing mail", async () => {
	const bucket = makeR2({ "mailboxes/a@x.com.json": JSON.stringify({ agentModel: "custom" }) });
	const stub = { moveEmailsFromSender: vi.fn().mockResolvedValue(3), listBlockedLog: vi.fn() };
	const res = await makeMailboxApp(stub).request(
		"/api/v1/mailboxes/a%40x.com/blocklist",
		{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ match: "NoReply@Res.PodView.com", action: "spam", move_existing: true }) },
		{ BUCKET: bucket },
	);
	expect(res.status).toBe(201);
	const body = await res.json();
	expect(body.moved).toBe(3);
	expect(body.rule).toMatchObject({ match: "noreply@res.podview.com", action: "spam" });
	const saved = JSON.parse(bucket.read("mailboxes/a@x.com.json")!);
	expect(saved.agentModel).toBe("custom");
	expect(saved.blocklist).toHaveLength(1);
	expect(stub.moveEmailsFromSender).toHaveBeenCalledWith("noreply@res.podview.com", "spam");
});

const post = (app: { request: Function }, path: string, body: unknown, env: unknown) =>
	app.request(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }, env);

it("POST with the same match replaces the old rule's action", async () => {
	const bucket = makeR2({ "mailboxes/a@x.com.json": "{}" });
	const app = makeMailboxApp({ moveEmailsFromSender: vi.fn(), listBlockedLog: vi.fn() });
	await post(app, "/api/v1/mailboxes/a%40x.com/blocklist", { match: "podview.com", action: "drop" }, { BUCKET: bucket });
	await post(app, "/api/v1/mailboxes/a%40x.com/blocklist", { match: "podview.com", action: "spam" }, { BUCKET: bucket });
	const saved = JSON.parse(bucket.read("mailboxes/a@x.com.json")!);
	expect(saved.blocklist).toHaveLength(1);
	expect(saved.blocklist[0].action).toBe("spam");
});

it("POST rejects a public suffix with 400 code public_suffix", async () => {
	const bucket = makeR2({ "mailboxes/a@x.com.json": "{}" });
	const res = await post(makeMailboxApp({}), "/api/v1/mailboxes/a%40x.com/blocklist", { match: "co.uk", action: "drop" }, { BUCKET: bucket });
	expect(res.status).toBe(400);
	expect((await res.json()).code).toBe("public_suffix");
	expect(JSON.parse(bucket.read("mailboxes/a@x.com.json")!).blocklist).toBeUndefined();
});

it("POST shared domain without confirm → 400; with confirm → 201", async () => {
	const bucket = makeR2({ "mailboxes/a@x.com.json": "{}" });
	const app = makeMailboxApp({ moveEmailsFromSender: vi.fn() });
	const no = await post(app, "/api/v1/mailboxes/a%40x.com/blocklist", { match: "gmail.com", action: "drop" }, { BUCKET: bucket });
	expect(no.status).toBe(400);
	expect((await no.json()).code).toBe("shared_domain_unconfirmed");
	const yes = await post(app, "/api/v1/mailboxes/a%40x.com/blocklist", { match: "gmail.com", action: "drop", confirm_shared_domain: true }, { BUCKET: bucket });
	expect(yes.status).toBe(201);
});

it("DELETE removes by id; unknown id → 404; last rule removed → blocklist key stripped", async () => {
	const rule = { id: "r1", match: "podview.com", action: "drop", created_at: "t" };
	const bucket = makeR2({ "mailboxes/a@x.com.json": JSON.stringify({ agentModel: "custom", blocklist: [rule] }) });
	const app = makeMailboxApp({});
	const missing = await app.request("/api/v1/mailboxes/a%40x.com/blocklist/nope", { method: "DELETE" }, { BUCKET: bucket });
	expect(missing.status).toBe(404);
	const ok = await app.request("/api/v1/mailboxes/a%40x.com/blocklist/r1", { method: "DELETE" }, { BUCKET: bucket });
	expect(ok.status).toBe(204);
	expect(JSON.parse(bucket.read("mailboxes/a@x.com.json")!)).toEqual({ agentModel: "custom" });
});

it("GET blocked-log passes limit through", async () => {
	const listBlockedLog = vi.fn().mockResolvedValue([{ id: 1, sender: "x@podview.com" }]);
	const res = await makeMailboxApp({ listBlockedLog }).request("/api/v1/mailboxes/a%40x.com/blocked-log?limit=7", {}, { BUCKET: makeR2() });
	expect(res.status).toBe(200);
	expect((await res.json()).rows).toHaveLength(1);
	expect(listBlockedLog).toHaveBeenCalledWith(7);
});

// org tier (via the real app)
it("org POST writes the org blocklist and a later org settings PUT keeps it", async () => {
	const bucket = makeR2({ "org/settings.json": JSON.stringify({ agentModel: "custom" }) });
	const env = { BUCKET: bucket, DOMAINS: "" };
	const res = await post(app, "/api/v1/org/blocklist", { match: "podview.com", action: "reject", reason: "Stop" }, env);
	expect(res.status).toBe(201);
	await app.request("/api/v1/org/settings", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ settings: { agentModel: "other" } }) }, env);
	const saved = JSON.parse(bucket.read("org/settings.json")!);
	expect(saved.agentModel).toBe("other");
	expect(saved.blocklist).toHaveLength(1);
	expect(saved.blocklist[0]).toMatchObject({ match: "podview.com", action: "reject", reason: "Stop" });
});

// domain tier
it("domain POST for a non-owned domain → 403", async () => {
	const bucket = makeR2();
	const res = await post(app, "/api/v1/domains/not-owned.example/blocklist", { match: "podview.com", action: "drop" }, { BUCKET: bucket, DOMAINS: "example.com" });
	expect(res.status).toBe(403);
	expect(bucket.read("domains/not-owned.example.json")).toBeUndefined();
});
```

`makeMailboxApp(stub)` mirrors `makeApp` in `tests/routes/cases.test.ts:183-197`. It builds `new Hono<MailboxContext>()`, a middleware that sets `mailboxStub` to the stub, and `.route("/api/v1/mailboxes/:mailboxId", mailboxBlocklistRoutes)`. `app` is `import { app } from "../../workers/index"`. `makeR2` is the store from `tests/routes/blocklist-settings-preserve.test.ts` (Task 2). If `app.request` for the org routes hits the Access middleware, use the same env shape `tests/routes/domain-settings-put.test.ts` uses; it calls `workers/index`'s `app` directly, which does not include the `workers/app.ts` Access gate.

- [ ] **Step 2: Run the test and confirm it fails**

Run: `npx vitest run tests/routes/blocklist.test.ts`
Expected: FAIL. `workers/routes/blocklist` is not found.

- [ ] **Step 3: Implement `workers/routes/blocklist.ts`**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sender blocklist endpoints (spec 2026-09-27-sender-blocklist). These are
 * the ONLY writers of the top-level `blocklist` settings field; the general
 * settings PUTs preserve it. Every write runs stripDefaultEqual.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import { requireMailbox, type MailboxContext } from "../lib/mailbox";
import type { Env } from "../types";
import { validateBlockRuleInput, type BlockRule, type BlockRuleInput } from "../../shared/blocklist";
import { stripDefaultEqual } from "../lib/mailbox-settings";
import { getOrgSettings, putOrgSettings } from "../lib/org-settings";
import { getDomainSettings, putDomainSettings } from "../lib/domain-settings";
import { Folders } from "../../shared/folders";
import { isOwnedDomain } from "../lib/owned-domains";

export function appendRule(existing: readonly BlockRule[] | undefined, rule: Omit<BlockRule, "id" | "created_at">, now: string, id: string): BlockRule[] {
	const kept = (existing ?? []).filter((r) => r.match !== rule.match);
	return [...kept, { ...rule, id, created_at: now }];
}

async function parseRule(c: Context): Promise<{ ok: true; rule: Omit<BlockRule, "id" | "created_at">; body: BlockRuleInput & { move_existing?: boolean } } | { ok: false; res: Response }> {
	const body = (await c.req.json().catch(() => ({}))) as BlockRuleInput & { move_existing?: boolean };
	const v = validateBlockRuleInput(body);
	if (!v.ok) return { ok: false, res: c.json({ error: v.error, code: v.code }, 400) };
	return { ok: true, rule: v.rule, body };
}

// ── Mailbox tier ────────────────────────────────────────────────────
export const mailboxBlocklistRoutes = new Hono<MailboxContext>();
mailboxBlocklistRoutes.use("*", requireMailbox);

mailboxBlocklistRoutes.post("/blocklist", async (c) => {
	const mailboxId = decodeURIComponent(c.req.param("mailboxId")!);
	const parsed = await parseRule(c);
	if (!parsed.ok) return parsed.res;
	const key = `mailboxes/${mailboxId}.json`;
	const obj = await c.env.BUCKET.get(key);
	if (!obj) return c.json({ error: "Not found" }, 404);
	const current = (await obj.json().catch(() => ({}))) as Record<string, unknown> & { blocklist?: BlockRule[] };
	const blocklist = appendRule(current.blocklist, parsed.rule, new Date().toISOString(), crypto.randomUUID());
	await c.env.BUCKET.put(key, JSON.stringify(stripDefaultEqual({ ...current, blocklist })));
	const rule = blocklist[blocklist.length - 1];
	let moved = 0;
	if (parsed.body.move_existing) {
		moved = await (c.var.mailboxStub as any).moveEmailsFromSender(rule.match, Folders.SPAM);
	}
	return c.json({ rule, moved }, 201);
});

mailboxBlocklistRoutes.delete("/blocklist/:ruleId", async (c) => {
	const mailboxId = decodeURIComponent(c.req.param("mailboxId")!);
	const key = `mailboxes/${mailboxId}.json`;
	const obj = await c.env.BUCKET.get(key);
	if (!obj) return c.json({ error: "Not found" }, 404);
	const current = (await obj.json().catch(() => ({}))) as Record<string, unknown> & { blocklist?: BlockRule[] };
	const next = (current.blocklist ?? []).filter((r) => r.id !== c.req.param("ruleId"));
	if (next.length === (current.blocklist ?? []).length) return c.json({ error: "Rule not found" }, 404);
	await c.env.BUCKET.put(key, JSON.stringify(stripDefaultEqual({ ...current, blocklist: next })));
	return c.body(null, 204);
});

mailboxBlocklistRoutes.get("/blocked-log", async (c) => {
	const limit = Number.parseInt(c.req.query("limit") ?? "50", 10);
	const rows = await (c.var.mailboxStub as any).listBlockedLog(Number.isFinite(limit) ? limit : 50);
	return c.json({ rows });
});

// ── Org tier ────────────────────────────────────────────────────────
export const orgBlocklistRoutes = new Hono<{ Bindings: Env }>();

orgBlocklistRoutes.post("/", async (c) => {
	const parsed = await parseRule(c);
	if (!parsed.ok) return parsed.res;
	const current = await getOrgSettings(c.env);
	const blocklist = appendRule(current.blocklist, parsed.rule, new Date().toISOString(), crypto.randomUUID());
	await putOrgSettings(c.env, stripDefaultEqual({ ...current, blocklist }));
	return c.json({ rule: blocklist[blocklist.length - 1] }, 201);
});

orgBlocklistRoutes.delete("/:ruleId", async (c) => {
	const current = await getOrgSettings(c.env);
	const next = (current.blocklist ?? []).filter((r) => r.id !== c.req.param("ruleId"));
	if (next.length === (current.blocklist ?? []).length) return c.json({ error: "Rule not found" }, 404);
	await putOrgSettings(c.env, stripDefaultEqual({ ...current, blocklist: next }));
	return c.body(null, 204);
});

// ── Domain tier ─────────────────────────────────────────────────────
export const domainBlocklistRoutes = new Hono<{ Bindings: Env }>();

domainBlocklistRoutes.use("*", async (c, next) => {
	const domain = c.req.param("domain")!.toLowerCase();
	if (!(await isOwnedDomain(c.env, domain))) {
		return c.json({ error: "Domain is not in this org's domains; add it via POST /api/v1/org/domains first." }, 403);
	}
	await next();
});

domainBlocklistRoutes.post("/", async (c) => {
	const domain = c.req.param("domain")!.toLowerCase();
	const parsed = await parseRule(c);
	if (!parsed.ok) return parsed.res;
	const current = await getDomainSettings(c.env, domain);
	const blocklist = appendRule(current.blocklist, parsed.rule, new Date().toISOString(), crypto.randomUUID());
	await putDomainSettings(c.env, domain, stripDefaultEqual({ ...current, blocklist }));
	return c.json({ rule: blocklist[blocklist.length - 1] }, 201);
});

domainBlocklistRoutes.delete("/:ruleId", async (c) => {
	const domain = c.req.param("domain")!.toLowerCase();
	const current = await getDomainSettings(c.env, domain);
	const next = (current.blocklist ?? []).filter((r) => r.id !== c.req.param("ruleId"));
	if (next.length === (current.blocklist ?? []).length) return c.json({ error: "Rule not found" }, 404);
	await putDomainSettings(c.env, domain, stripDefaultEqual({ ...current, blocklist: next }));
	return c.body(null, 204);
});
```

`isOwnedDomain`: the domain PUT at `workers/index.ts:870-877` computes ownership inline (DOMAINS env ∪ `org.domains`). Extract that check verbatim into `workers/lib/owned-domains.ts` as `export async function isOwnedDomain(env: Env, domain: string): Promise<boolean>`, call it from the domain PUT as well, and keep the domain PUT's existing tests green. If a helper with this job already exists (`grep -rn "org's domains" workers/`), import that instead and skip the extraction.

Mount the routes in `workers/index.ts` next to the other `app.route` calls (~line 171). They must come before `app.route("/api/v1/mailboxes/:mailboxId", sendEmailRoutes)`:

```ts
app.route("/api/v1/mailboxes/:mailboxId", mailboxBlocklistRoutes);
app.route("/api/v1/org/blocklist", orgBlocklistRoutes);
app.route("/api/v1/domains/:domain/blocklist", domainBlocklistRoutes);
```

The mailbox routes run through `requireMailbox`, which enforces the mailbox ACL. The org and domain routes get the same Access gate as `/api/v1/org/settings` and the domain settings PUT (the global middleware in `workers/app.ts`); they add no extra ACL, which matches those endpoints.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `npx vitest run tests/routes/blocklist.test.ts tests/routes/domain-settings-put.test.ts tests/routes/blocklist-settings-preserve.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/routes/blocklist.ts workers/lib/owned-domains.ts workers/index.ts tests/routes/blocklist.test.ts
git commit -m "feat(blocklist): mailbox/domain/org blocklist endpoints and blocked-log read"
```

---

### Task 7: Block sender dialog

**Files:**
- Create: `app/components/BlockSenderButton.tsx`
- Modify: `app/components/email-panel/EmailPanelToolbar.tsx:191` (render next to `ReportPhishButton`)
- Modify: `app/types/index.ts:~202` (`Email.blocked_by_rule?: string | null`)
- Test: `tests/frontend/block-sender-button.test.tsx`

**Interfaces:**
- Consumes: `POST /api/v1/mailboxes/:mailboxId/blocklist` (Task 6); `registrableDomain`, `DEFAULT_REJECT_REASON`, `SHARED_SENDER_DOMAINS` (Task 1); `useFeedback` (`~/lib/feedback`); `Dialog`, `Button`, `Tooltip`, `Banner` (`@cloudflare/kumo`); `ProhibitIcon` (`@phosphor-icons/react`).
- Produces: `<BlockSenderButton mailboxId email isSidecar />`. It parses `email.security_verdict` to read `auth.dmarc` / `auth.trusted` for the unauthenticated warning.

- [ ] **Step 1: Write the failing test**

Use `renderWithProviders` from `tests/frontend/test-utils.tsx` and stub `global.fetch` with `vi.fn`. Tests:

```tsx
it("defaults to the full address and Spam, and posts move_existing", async () => {
	// render with email { sender: "noreply@res.podview.com", security_verdict: JSON.stringify({ auth: { dmarc: "pass", trusted: true } }) }
	// click "Block sender", then "Block"
	// expect fetch called with /api/v1/mailboxes/clodcast%40cortech.online/blocklist and body
	//   { match: "noreply@res.podview.com", action: "spam", move_existing: true }
});
it("offers podview.com and res.podview.com as domain choices", async () => {});
it("shows the reason textarea only for Bounce, prefilled with the default", async () => {});
it("warns when the sender is not DMARC-authenticated", async () => {
	// security_verdict auth { dmarc: "fail" } → text /may be forged/
});
it("on a sidecar mailbox labels Bounce as unavailable (will drop)", async () => {});
it("on 400 shared_domain_unconfirmed shows a confirm checkbox and resends with confirm_shared_domain", async () => {});
```

Write each case in full. Pull element queries (`getByRole("button", { name: "Block sender" })`, `getByLabelText(...)`) from the component labels defined in Step 3.

- [ ] **Step 2: Run the test and confirm it fails**

Run: `npx vitest run tests/frontend/block-sender-button.test.tsx`
Expected: FAIL. The module is not found.

- [ ] **Step 3: Implement**

Build the component on the `ReportPhishButton` plus `CreateCaseModal` patterns: a ghost square `Button` with `ProhibitIcon` and `aria-label="Block sender"`, opening a `Dialog.Root`. The dialog contents, in order:

- Radio group "Block", options: `noreply@res.podview.com` (default), `podview.com (and subdomains)`, and `res.podview.com (and subdomains)`. The last is shown only when it differs from the registrable domain.
- Radio group "Action": `Move to Spam` (default), `Drop silently`, `Bounce with message`. On sidecar mailboxes the Bounce label reads `Bounce (unavailable for Google Workspace — will drop)`.
- When Bounce is selected: `<textarea aria-label="Bounce message" maxLength={200}>`, prefilled with `DEFAULT_REJECT_REASON`.
- Checkbox `Also move existing mail from this sender to Spam` (checked).
- A `Banner` warning when `!(auth?.dmarc === "pass" && auth?.trusted)`: `This message's sender is not authenticated — the From address may be forged. Blocking it may block the real sender.`
- When the chosen domain is in `SHARED_SENDER_DOMAINS`, or the server returns `code: "shared_domain_unconfirmed"`: checkbox `I understand this blocks every sender at <domain>`. Checking it sends `confirm_shared_domain: true`.
- `Block` (primary) and `Cancel` buttons. On 201: `feedback.success("Blocked <match>. Moved <n> existing message(s) to Spam.")`, then close. On other errors: `feedback.error(body.error)`.

`isSidecar`: `EmailPanel.tsx` already receives the mailbox. Pass `Boolean(mailbox?.settings?.sidecar)`. If `EmailPanel` does not have the mailbox object, add an `isSidecar?: boolean` prop to `EmailPanelToolbar` and pass `false` from call sites that lack it. The Bounce option then stays enabled and the server downgrades it.

Render `<BlockSenderButton mailboxId={mailboxId} email={email} isSidecar={isSidecar} />` right after `<ReportPhishButton … />` in `EmailPanelToolbar.tsx`, hidden when `isDraftFolder`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `npx vitest run tests/frontend/block-sender-button.test.tsx tests/frontend/email-panel-send-risk.test.tsx`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/components/BlockSenderButton.tsx app/components/email-panel/EmailPanelToolbar.tsx app/types/index.ts tests/frontend/block-sender-button.test.tsx
git commit -m "feat(blocklist): Block sender dialog on the email toolbar"
```

---

### Task 8: Blocked senders panel, Spam ordering, verdict line

**Files:**
- Create: `app/components/BlockedSendersPanel.tsx`
- Modify: `app/routes/settings.tsx:~836`, `app/routes/domain-settings.tsx:~445`, `app/routes/org-settings.tsx:~415` (render the panel under `SecuritySettingsPanel`)
- Modify: `shared/folders.ts:29-36` (`SYSTEM_FOLDER_IDS`: insert `Folders.SPAM` before `Folders.QUARANTINE`; update its doc comment "excludes spam" → "includes spam since sender-blocklist")
- Modify: `app/components/email-panel/SecurityVerdictPanel.tsx` (the blocked-by line)
- Test: `tests/frontend/blocked-senders-panel.test.tsx`; extend `tests/frontend/security-verdict-panel.test.tsx` and `tests/frontend/shell-folder-nav.test.tsx`

**Interfaces:**
- Consumes: Task 6 endpoints; GET settings responses (mailbox `GET /api/v1/mailboxes/:id` settings, domain `GET /api/v1/domains/:d/settings`, `GET /api/v1/org/settings`), whose `blocklist` field appears via the passthrough schemas; `GET /api/v1/mailboxes/:id/settings/effective` for inherited rules (`settings.domain.blocklist`, `settings.org.blocklist`).
- Produces: `<BlockedSendersPanel tier="mailbox" | "domain" | "org" mailboxId? domain? />`

- [ ] **Step 1: Write the failing tests**

`blocked-senders-panel.test.tsx`:
- The mailbox tier lists its own rules with Remove buttons, and inherited domain/org rules read-only, each with a tier badge.
- Remove calls `DELETE .../blocklist/<id>` and the row disappears.
- The mailbox tier shows the last `blocked_log` rows (sender, subject, action, time).
- The org tier has an "Add rule" form (match + action + reason). It posts to `/api/v1/org/blocklist`, and a 400 `public_suffix` shows the server's error text.

`security-verdict-panel.test.tsx`: an email with `blocked_by_rule: JSON.stringify({ id: "r", match: "podview.com", tier: "mailbox" })` renders `Blocked by rule: podview.com (mailbox)`.

`shell-folder-nav.test.tsx`: with folders `[inbox, custom "Receipts", spam, quarantine]`, Spam renders after Inbox and before Quarantine, ahead of "Receipts".

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `npx vitest run tests/frontend/blocked-senders-panel.test.tsx tests/frontend/security-verdict-panel.test.tsx tests/frontend/shell-folder-nav.test.tsx`
Expected: FAIL. The panel module is missing, there is no blocked-by text, and Spam sorts after the custom folder.

- [ ] **Step 3: Implement**

- `BlockedSendersPanel`: fetch the tier's settings and, for mailbox, the effective settings plus `blocked-log?limit=50`. Render a table: Tier | Match | Action | Added | (Remove). Remove appears only on rows at the panel's own tier. The domain and org tiers show the add-rule form; the mailbox tier adds rules via the toolbar button, plus the same form. Refetch after each mutation (use react-query `invalidateQueries` if the route's data comes from `app/queries/*`, otherwise local state).
- `SecurityVerdictPanel`: parse `email.blocked_by_rule` in a try/catch. When it is valid, render a row `Blocked by rule: {match} ({tier})` above the signals list.
- `shared/folders.ts`: make the `SYSTEM_FOLDER_IDS` change. `SecuritySettingsPanel` now renders a Spam folder-policy row too; that is expected, and the existing `tests/frontend/security-settings.test.tsx` must still pass (update a folder-row count assertion if one exists).

- [ ] **Step 4: Run the full frontend suite**

Run: `npx vitest run tests/frontend`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/components/BlockedSendersPanel.tsx app/routes/settings.tsx app/routes/domain-settings.tsx app/routes/org-settings.tsx shared/folders.ts app/components/email-panel/SecurityVerdictPanel.tsx tests/frontend/
git commit -m "feat(blocklist): blocked senders settings panel, Spam in system folders, verdict rule line"
```

---

### Task 9: Gates, follow-ups, ship

**Files:** none new.

- [ ] **Step 1: Full gates.** Run each and record the counts:

```bash
npm test
```
Expected: all passing. Record "N passing, 0 failing".

```bash
npm run typecheck
```
Expected: exit 0.

```bash
npm run build
```
Expected: exit 0.

- [ ] **Step 2: Spec re-read.** Walk every section of `docs/superpowers/specs/2026-09-27-sender-blocklist-design.md` and tick each requirement against a task. File a `/issue` for any gap; never silently cut scope.

- [ ] **Step 3: File the follow-up issues** from the spec's Non-goals, with `/issue`, as prompts:
  1. One-click List-Unsubscribe (RFC 8058) with an SSRF-safe fetcher.
  2. Route classifier `spam` labels to the Spam folder. Cite the triggering email: jev spam 0.93 → verdict allow, score 14.
  3. Blocklist on the catch-all and gateway-passthrough ingest paths.
  4. Consolidate `receiveEmail`'s repeated `resolveMailboxSettings` calls.

- [ ] **Step 4: Ship** via `/shipofclaudius:ship` (PR to `main` with the test output). After the merge deploys (Workers Builds deploys prod on merge), do the browser check on https://inbox.cortech.online:
  - Open the PodView email in `clodcast@cortech.online`.
  - Block `podview.com` → Move to Spam.
  - Confirm the email is now in Spam, Spam sorts with the system folders, and the rule appears under Settings → Blocked senders.
