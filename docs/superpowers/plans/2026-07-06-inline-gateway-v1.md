# Inline Gateway Mode v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Per-domain inline gateway: scored inbound mail relays to a backend (Google Workspace) over SMTP submission with an ARC seal and verdict headers; quarantined mail never relays.

**Architecture:** A `relay` policy block on the domain settings tier turns a domain into gateway mode. After the existing sync security pipeline produces a verdict in `receiveEmail()`, a new relay branch maps the verdict through the policy's action table, prepends `X-PhishPilot-*` headers to the raw RFC-5322 bytes, ARC-seals with a single org-level key, and submits over `cloudflare:sockets` to the policy target. Unregistered recipients on gateway domains flow through a new tag-capped, stateless passthrough path.

**Tech Stack:** Cloudflare Workers (no `node:` imports in `workers/`), Zod, Hono, `crypto.subtle` (RSASSA-PKCS1-v1_5/SHA-256), `cloudflare:sockets`, Vitest (Node pool for `tests/**` + `test/**`), `mailauth` (devDependency, Node-side test verification ONLY).

**Spec:** `docs/superpowers/specs/2026-07-06-inline-gateway-design.md`. One recorded deviation: the spec left the ARC sealer internals to a mailauth-on-workerd spike; `workers/CLAUDE.md` forbids `node:` imports/`Buffer` in workers code, which mailauth requires, so the sealer is owned code on `crypto.subtle` and mailauth verifies our seals in Node-side tests instead. A second minor deviation: the spec sketch used Zod `.default()`; repo convention (see `CatchallIntelSettings`) is all-optional schemas with defaults in code constants, so the plan does that.

## Global Constraints

- **Workers runtime only in `workers/` and `shared/`**: no `node:` imports, no `Buffer`, no `process.env` (`workers/CLAUDE.md`). Tests under `tests/**`/`test/**` run in the Node pool and may use Node APIs.
- **Every settings-tier write runs `stripDefaultEqual`** before `BUCKET.put` (root `CLAUDE.md`). The new `relay`/`gateway` blocks ride existing endpoints, which already strip — but the strip map needs cases for the new keys (Tasks 1–2).
- **Test mocks must parse URLs, never substring-match hosts** (`new URL(u).hostname === "..."`, root `CLAUDE.md`; CodeQL gates PRs).
- **Never hand-roll crypto primitives**: all signing via `crypto.subtle`; only canonicalization/protocol framing is owned code, cross-verified against mailauth.
- **Conventional commit prefixes** (`feat:`, `fix:`, `test:`, `docs:`).
- **Settings schemas**: all fields `.optional()`, `.passthrough()` objects, defaults in code constants — absent-key-inherits semantics.
- **Verdict actions are fixed**: `"allow" | "tag" | "quarantine" | "block"` (`workers/security/verdict.ts:101`). Relay behaviors are `"relay" | "hold" | "drop"`.
- **Fail-open on scan/seal failure, fail-closed on quarantine**: a gateway must never eat mail because scanning broke; it must never relay mail the (default) policy quarantines.
- Run tests from repo root: `npx vitest run <file>` for a single file; `npm test` for everything; `npm run typecheck` for types.

---

### Task 1: `RelaySettings` schema on the domain tier

**Files:**
- Modify: `shared/domain-settings.ts` (schema block ends ~line 81)
- Modify: `workers/lib/mailbox-settings.ts:439-` (`stripDefaultEqual`'s `isDefaultEqual`)
- Test: `tests/lib/relay-settings.test.ts` (create)

**Interfaces:**
- Produces: `RelaySettings` Zod schema + type; `DomainSettings` gains optional `relay`; `stripDefaultEqual` strips inert `relay` blocks. Task 3's resolver consumes `DomainSettings["relay"]`.

- [ ] **Step 1: Write the failing test**

```ts
// tests/lib/relay-settings.test.ts
import { describe, expect, it } from "vitest";
import { DomainSettings, RelaySettings } from "../../shared/domain-settings";
import { stripDefaultEqual } from "../../workers/lib/mailbox-settings";

describe("RelaySettings schema", () => {
	it("accepts a full relay block", () => {
		const parsed = DomainSettings.safeParse({
			relay: {
				enabled: true,
				target: { host: "smtp-relay.gmail.com", port: 587, implicitTls: false },
				credentialsSecret: "RELAY_CREDS_EXAMPLE_COM",
				actions: { quarantine: "relay" },
			},
		});
		expect(parsed.success).toBe(true);
		expect(parsed.success && parsed.data.relay?.target?.host).toBe("smtp-relay.gmail.com");
	});

	it("accepts an empty object (all fields optional)", () => {
		expect(RelaySettings.safeParse({}).success).toBe(true);
	});

	it("rejects invalid action behaviors and ports", () => {
		expect(RelaySettings.safeParse({ actions: { allow: "bounce" } }).success).toBe(false);
		expect(RelaySettings.safeParse({ target: { host: "h", port: 0 } }).success).toBe(false);
		expect(RelaySettings.safeParse({ target: { host: "h", port: 70000 } }).success).toBe(false);
	});
});

describe("stripDefaultEqual: relay", () => {
	it("strips a disabled/empty relay block", () => {
		expect(stripDefaultEqual({ relay: { enabled: false } })).toEqual({});
		expect(stripDefaultEqual({ relay: {} })).toEqual({});
	});

	it("keeps an enabled relay block", () => {
		const v = { relay: { enabled: true, target: { host: "smtp-relay.gmail.com" } } };
		expect(stripDefaultEqual(v)).toEqual(v);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/lib/relay-settings.test.ts`
Expected: FAIL — `RelaySettings` is not exported.

- [ ] **Step 3: Add the schema to `shared/domain-settings.ts`**

Insert above the `DomainSettings` declaration (after `CatchallIntelSettings`), matching the file's doc-comment style:

```ts
/**
 * Per-domain inline-gateway relay policy (issue #32).
 *
 * When `enabled` with a `target.host`, inbound mail for this domain is
 * relayed to the backend over SMTP submission after the security pipeline
 * runs; the verdict action maps through `actions` to decide relay/hold/drop.
 *
 * All fields optional so absent-key-inherits semantics are preserved.
 * Defaults (port 587, STARTTLS, the fail-closed action map) live in
 * `workers/lib/relay-policy.ts`, not on this schema.
 */
export const RelayActionBehavior = z.enum(["relay", "hold", "drop"]);
export type RelayActionBehavior = z.infer<typeof RelayActionBehavior>;

export const RelaySettings = z
	.object({
		enabled: z.boolean().optional(),
		target: z
			.object({
				host: z.string().min(1).optional(),
				port: z.number().int().min(1).max(65535).optional(),
				implicitTls: z.boolean().optional(),
			})
			.passthrough()
			.optional(),
		/** Name of the Worker Secret holding `{"user":"...","pass":"..."}` JSON. */
		credentialsSecret: z.string().optional(),
		actions: z
			.object({
				allow: RelayActionBehavior.optional(),
				tag: RelayActionBehavior.optional(),
				quarantine: RelayActionBehavior.optional(),
				block: RelayActionBehavior.optional(),
			})
			.passthrough()
			.optional(),
	})
	.passthrough();

export type RelaySettings = z.infer<typeof RelaySettings>;
```

Add to the `DomainSettings` object, after `catchall_intel`:

```ts
		relay: RelaySettings.optional(),
```

- [ ] **Step 4: Add the strip case in `workers/lib/mailbox-settings.ts`**

In `isDefaultEqual`'s `switch`, after the `catchall_intel` case (mirror the `honeypot` pattern):

```ts
		case "relay":
			// Off by default — strip the disabled/empty default so absent-key
			// semantics are preserved; an enabled relay policy survives.
			return deepEqual(value, { enabled: false }) || deepEqual(value, {});
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/lib/relay-settings.test.ts`
Expected: PASS (6 tests)

- [ ] **Step 6: Typecheck and commit**

Run: `npm run typecheck` — expected clean.

```bash
git add shared/domain-settings.ts workers/lib/mailbox-settings.ts tests/lib/relay-settings.test.ts
git commit -m "feat(gateway): RelaySettings schema on the domain settings tier"
```

---

### Task 2: Org-tier `gateway` block + `ARC_SEAL_PRIVATE_KEY` env

**Files:**
- Modify: `shared/org-settings.ts` (schema object, ~line 31-59)
- Modify: `workers/types.ts` (`Env` interface, near `CONFIRMATION_TOKEN_SECRET` ~line 32)
- Modify: `workers/lib/mailbox-settings.ts` (`isDefaultEqual`)
- Test: `tests/lib/gateway-org-settings.test.ts` (create)

**Interfaces:**
- Produces: `OrgSettings` gains optional `gateway: { arcSealerDomain?: string; arcSelector?: string }`; `Env.ARC_SEAL_PRIVATE_KEY?: string`. Task 8 consumes both.

- [ ] **Step 1: Write the failing test**

```ts
// tests/lib/gateway-org-settings.test.ts
import { describe, expect, it } from "vitest";
import { OrgSettings } from "../../shared/org-settings";
import { stripDefaultEqual } from "../../workers/lib/mailbox-settings";

describe("OrgSettings.gateway", () => {
	it("accepts ARC sealer config", () => {
		const parsed = OrgSettings.safeParse({
			gateway: { arcSealerDomain: "gw.example.com", arcSelector: "arc1" },
		});
		expect(parsed.success).toBe(true);
		expect(parsed.success && parsed.data.gateway?.arcSelector).toBe("arc1");
	});

	it("strips an empty gateway block, keeps a configured one", () => {
		expect(stripDefaultEqual({ gateway: {} })).toEqual({});
		const v = { gateway: { arcSealerDomain: "gw.example.com" } };
		expect(stripDefaultEqual(v)).toEqual(v);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/lib/gateway-org-settings.test.ts`
Expected: FAIL — `gateway` is stripped by `.passthrough()` but the strip assertion fails (no `gateway` case) OR parse lacks the typed field; either way the strip test fails.

- [ ] **Step 3: Implement**

In `shared/org-settings.ts`, add to the `OrgSettings` object after `domains`:

```ts
		/**
		 * Inline-gateway ARC sealer identity (issue #32). One sealer per
		 * deployment; the PKCS8 private key lives in the
		 * `ARC_SEAL_PRIVATE_KEY` Worker Secret, never in this blob.
		 */
		gateway: z
			.object({
				arcSealerDomain: z.string().optional(),
				arcSelector: z.string().optional(),
			})
			.passthrough()
			.optional(),
```

In `workers/types.ts`, next to `CONFIRMATION_TOKEN_SECRET` in `Env`:

```ts
	/**
	 * PKCS8 PEM private key for ARC sealing on gateway relay (issue #32).
	 * Set with `wrangler secret put ARC_SEAL_PRIVATE_KEY`. Absent → relay
	 * proceeds unsealed.
	 */
	ARC_SEAL_PRIVATE_KEY?: string;
```

In `workers/lib/mailbox-settings.ts` `isDefaultEqual`, after the `relay` case:

```ts
		case "gateway":
			// Org-tier ARC sealer identity — strip only the empty object.
			return deepEqual(value, {});
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/lib/gateway-org-settings.test.ts`
Expected: PASS

- [ ] **Step 5: Typecheck and commit**

Run: `npm run typecheck` — expected clean.

```bash
git add shared/org-settings.ts workers/types.ts workers/lib/mailbox-settings.ts tests/lib/gateway-org-settings.test.ts
git commit -m "feat(gateway): org-tier ARC sealer config and ARC_SEAL_PRIVATE_KEY env"
```

---

### Task 3: Relay-policy resolver and verdict→behavior mapping

**Files:**
- Create: `workers/lib/relay-policy.ts`
- Test: `tests/lib/relay-policy.test.ts` (create)

**Interfaces:**
- Consumes: `DomainSettings` / `RelaySettings` (Task 1), `VerdictAction` from `workers/security/verdict.ts`.
- Produces (Tasks 8, 11, 12 consume):

```ts
export interface ResolvedRelayPolicy {
	target: { host: string; port: number; implicitTls: boolean };
	credentialsSecret?: string;
	actions: Record<VerdictAction, RelayActionBehavior>;
}
export function resolveRelayPolicy(settings: DomainSettings): ResolvedRelayPolicy | null;
export function behaviorFor(
	action: VerdictAction | null,
	policy: ResolvedRelayPolicy,
	opts?: { passthrough?: boolean },
): RelayActionBehavior;
export const DEFAULT_RELAY_ACTIONS: Record<VerdictAction, RelayActionBehavior>;
```

- [ ] **Step 1: Write the failing test**

```ts
// tests/lib/relay-policy.test.ts
import { describe, expect, it } from "vitest";
import {
	DEFAULT_RELAY_ACTIONS,
	behaviorFor,
	resolveRelayPolicy,
} from "../../workers/lib/relay-policy";

const enabled = {
	relay: { enabled: true, target: { host: "smtp-relay.gmail.com" } },
};

describe("resolveRelayPolicy", () => {
	it("returns null when relay is absent, disabled, or has no target host", () => {
		expect(resolveRelayPolicy({})).toBeNull();
		expect(resolveRelayPolicy({ relay: { enabled: false, target: { host: "h" } } })).toBeNull();
		expect(resolveRelayPolicy({ relay: { enabled: true } })).toBeNull();
		expect(resolveRelayPolicy({ relay: { enabled: true, target: {} } })).toBeNull();
	});

	it("applies defaults: port 587, STARTTLS, fail-closed action map", () => {
		const p = resolveRelayPolicy(enabled);
		expect(p).not.toBeNull();
		expect(p!.target).toEqual({ host: "smtp-relay.gmail.com", port: 587, implicitTls: false });
		expect(p!.actions).toEqual(DEFAULT_RELAY_ACTIONS);
		expect(DEFAULT_RELAY_ACTIONS).toEqual({
			allow: "relay",
			tag: "relay",
			quarantine: "hold",
			block: "drop",
		});
	});

	it("honours per-domain overrides", () => {
		const p = resolveRelayPolicy({
			relay: {
				enabled: true,
				target: { host: "h", port: 465, implicitTls: true },
				credentialsSecret: "RELAY_CREDS_X",
				actions: { quarantine: "relay" },
			},
		});
		expect(p!.target.port).toBe(465);
		expect(p!.target.implicitTls).toBe(true);
		expect(p!.credentialsSecret).toBe("RELAY_CREDS_X");
		expect(p!.actions.quarantine).toBe("relay"); // explicit override allowed
		expect(p!.actions.block).toBe("drop"); // untouched default
	});
});

describe("behaviorFor", () => {
	const p = resolveRelayPolicy(enabled)!;

	it("maps verdict actions through the policy table", () => {
		expect(behaviorFor("allow", p)).toBe("relay");
		expect(behaviorFor("tag", p)).toBe("relay");
		expect(behaviorFor("quarantine", p)).toBe("hold");
		expect(behaviorFor("block", p)).toBe("drop");
	});

	it("null verdict (scan skipped/failed) fails open to relay", () => {
		expect(behaviorFor(null, p)).toBe("relay");
	});

	it("passthrough degrades hold to relay (nothing to hold into)", () => {
		expect(behaviorFor("quarantine", p, { passthrough: true })).toBe("relay");
		expect(behaviorFor("block", p, { passthrough: true })).toBe("drop");
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/lib/relay-policy.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `workers/lib/relay-policy.ts`**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Per-domain inline-gateway relay policy resolution (issue #32).
 *
 * `RelaySettings` (shared/domain-settings.ts) is all-optional so
 * absent-key-inherits semantics hold; the defaults live here. A policy
 * only resolves when `enabled` is true AND a target host is configured —
 * everything else about the domain behaves exactly as before.
 */

import type { DomainSettings, RelayActionBehavior } from "../../shared/domain-settings";
import type { VerdictAction } from "../security/verdict";

export interface ResolvedRelayPolicy {
	target: { host: string; port: number; implicitTls: boolean };
	credentialsSecret?: string;
	actions: Record<VerdictAction, RelayActionBehavior>;
}

/**
 * Fail-closed defaults: quarantine holds locally, block drops. Relaying a
 * quarantine/block verdict requires an explicit per-domain override.
 */
export const DEFAULT_RELAY_ACTIONS: Record<VerdictAction, RelayActionBehavior> = {
	allow: "relay",
	tag: "relay",
	quarantine: "hold",
	block: "drop",
};

export function resolveRelayPolicy(settings: DomainSettings): ResolvedRelayPolicy | null {
	const relay = settings.relay;
	if (!relay?.enabled) return null;
	const host = relay.target?.host;
	if (!host) return null;
	return {
		target: {
			host,
			port: relay.target?.port ?? 587,
			implicitTls: relay.target?.implicitTls ?? false,
		},
		credentialsSecret: relay.credentialsSecret,
		actions: { ...DEFAULT_RELAY_ACTIONS, ...(relay.actions ?? {}) },
	};
}

/**
 * Map a verdict action to a relay behavior.
 *
 * - `null` verdict (pipeline skipped or threw) fails OPEN to `relay`: a
 *   gateway must never eat mail because scanning broke. The stored mirror
 *   copy (registered mailboxes) still preserves auditability.
 * - `passthrough` (unregistered recipient): `hold` degrades to `relay` —
 *   there is no mailbox to hold into, and delivering tagged beats losing
 *   mail. `drop` is honoured as configured.
 */
export function behaviorFor(
	action: VerdictAction | null,
	policy: ResolvedRelayPolicy,
	opts?: { passthrough?: boolean },
): RelayActionBehavior {
	if (action === null) return "relay";
	let behavior = policy.actions[action];
	if (opts?.passthrough && behavior === "hold") behavior = "relay";
	return behavior;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/lib/relay-policy.test.ts`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add workers/lib/relay-policy.ts tests/lib/relay-policy.test.ts
git commit -m "feat(gateway): relay-policy resolver with fail-closed action defaults"
```

---

### Task 4: ARC module part 1 — raw-message split + relaxed canonicalization

**Files:**
- Create: `workers/lib/arc-seal.ts`
- Test: `tests/lib/arc-canonicalization.test.ts` (create)

**Interfaces:**
- Produces (Task 5 consumes, internal to the module but exported for tests):

```ts
export function splitRawMessage(raw: Uint8Array): { headerBlock: string; body: Uint8Array };
export function parseRawHeaders(headerBlock: string): Array<{ name: string; raw: string }>;
export function canonicalizeHeaderRelaxed(rawHeader: string): string;
export function canonicalizeBodyRelaxed(body: Uint8Array): Uint8Array;
export function latin1Encode(s: string): Uint8Array;
```

**Why owned code is safe here:** these are pure string/byte transforms (RFC 6376 §3.4); the actual signing is `crypto.subtle` (Task 5). Every transform is pinned to the RFC's own test vectors below and cross-verified end-to-end by mailauth in Task 5.

- [ ] **Step 1: Write the failing test**

```ts
// tests/lib/arc-canonicalization.test.ts
import { describe, expect, it } from "vitest";
import {
	canonicalizeBodyRelaxed,
	canonicalizeHeaderRelaxed,
	latin1Encode,
	parseRawHeaders,
	splitRawMessage,
} from "../../workers/lib/arc-seal";

const enc = (s: string) => latin1Encode(s);
const dec = (b: Uint8Array) => Array.from(b, (c) => String.fromCharCode(c)).join("");

describe("splitRawMessage", () => {
	it("splits at the first CRLFCRLF", () => {
		const raw = enc("Subject: hi\r\nFrom: a@b\r\n\r\nbody line\r\n");
		const { headerBlock, body } = splitRawMessage(raw);
		expect(headerBlock).toBe("Subject: hi\r\nFrom: a@b\r\n");
		expect(dec(body)).toBe("body line\r\n");
	});

	it("handles a missing body (headers only)", () => {
		const { headerBlock, body } = splitRawMessage(enc("Subject: hi\r\n\r\n"));
		expect(headerBlock).toBe("Subject: hi\r\n");
		expect(body.length).toBe(0);
	});
});

describe("parseRawHeaders", () => {
	it("keeps folded headers as one entry", () => {
		const hs = parseRawHeaders("A: X\r\nB : Y\t\r\n\tZ  \r\n");
		expect(hs).toEqual([
			{ name: "a", raw: "A: X" },
			{ name: "b", raw: "B : Y\t\r\n\tZ  " },
		]);
	});
});

// Vectors straight from RFC 6376 §3.4.5.
describe("relaxed canonicalization (RFC 6376 §3.4.5 vectors)", () => {
	it("canonicalizes headers", () => {
		expect(canonicalizeHeaderRelaxed("A: X")).toBe("a:X");
		expect(canonicalizeHeaderRelaxed("B : Y\t\r\n\tZ  ")).toBe("b:Y Z");
	});

	it("canonicalizes the body", () => {
		const out = canonicalizeBodyRelaxed(enc(" C \r\nD \t E\r\n\r\n\r\n"));
		expect(dec(out)).toBe(" C\r\nD E\r\n");
	});

	it("empty body canonicalizes to empty; non-empty gains trailing CRLF", () => {
		expect(canonicalizeBodyRelaxed(enc("")).length).toBe(0);
		expect(dec(canonicalizeBodyRelaxed(enc("x")))).toBe("x\r\n");
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/lib/arc-canonicalization.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the canonicalization half of `workers/lib/arc-seal.ts`**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * ARC sealing (RFC 8617) for inline-gateway relay (issue #32).
 *
 * Owned protocol code by design: `workers/CLAUDE.md` forbids `node:`
 * imports/Buffer in workers code, which rules out mailauth at runtime. The
 * cryptographic primitive is `crypto.subtle` RSASSA-PKCS1-v1_5/SHA-256 —
 * never hand-rolled. Canonicalization (RFC 6376 §3.4 relaxed/relaxed) is
 * pinned to the RFC's own vectors in tests, and every seal this module
 * produces is cross-verified by mailauth's independent validator in
 * `tests/lib/arc-seal.test.ts`.
 *
 * v1 seals only when the message carries no prior ARC chain (we are i=1,
 * cv=none). Messages with an existing chain relay unsealed — validating a
 * prior chain is out of scope (spec), and asserting cv= without validating
 * would be dishonest.
 */

/** Encode a string whose code points are all <= 0xFF back to raw bytes. */
export function latin1Encode(s: string): Uint8Array {
	const out = new Uint8Array(s.length);
	for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
	return out;
}

const latin1Decoder = new TextDecoder("latin1");

/**
 * Split raw RFC-5322 bytes into the header block (latin1 string, 1:1 with
 * bytes, including the trailing CRLF of the last header) and body bytes.
 * The CRLFCRLF separator belongs to neither part.
 */
export function splitRawMessage(raw: Uint8Array): { headerBlock: string; body: Uint8Array } {
	for (let i = 0; i + 3 < raw.length; i++) {
		if (raw[i] === 13 && raw[i + 1] === 10 && raw[i + 2] === 13 && raw[i + 3] === 10) {
			return {
				headerBlock: latin1Decoder.decode(raw.subarray(0, i + 2)),
				body: raw.subarray(i + 4),
			};
		}
	}
	// No body separator: the whole message is headers.
	return { headerBlock: latin1Decoder.decode(raw), body: new Uint8Array(0) };
}

/**
 * Parse a raw header block into `{ name, raw }` entries. `raw` is the
 * exact original text (folding preserved, no trailing CRLF); `name` is
 * lowercased for lookups.
 */
export function parseRawHeaders(headerBlock: string): Array<{ name: string; raw: string }> {
	const out: Array<{ name: string; raw: string }> = [];
	// Split on CRLF NOT followed by whitespace (folded continuations stay).
	const lines = headerBlock.split(/\r\n(?![ \t])/);
	for (const line of lines) {
		if (!line) continue;
		const colon = line.indexOf(":");
		if (colon <= 0) continue;
		out.push({ name: line.slice(0, colon).trim().toLowerCase(), raw: line });
	}
	return out;
}

/** RFC 6376 §3.4.2 relaxed header canonicalization → `name:value` (no CRLF). */
export function canonicalizeHeaderRelaxed(rawHeader: string): string {
	const colon = rawHeader.indexOf(":");
	const name = rawHeader.slice(0, colon).trim().toLowerCase();
	let value = rawHeader.slice(colon + 1);
	value = value.replace(/\r\n/g, ""); // unfold
	value = value.replace(/[ \t]+/g, " "); // collapse WSP runs
	value = value.trim();
	return `${name}:${value}`;
}

/** RFC 6376 §3.4.4 relaxed body canonicalization. */
export function canonicalizeBodyRelaxed(body: Uint8Array): Uint8Array {
	if (body.length === 0) return body;
	const text = latin1Decoder.decode(body);
	const lines = text.split("\r\n").map((l) => l.replace(/[ \t]+/g, " ").replace(/[ \t]+$/, ""));
	while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
	if (lines.length === 0) return new Uint8Array(0);
	return latin1Encode(lines.join("\r\n") + "\r\n");
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/lib/arc-canonicalization.test.ts`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add workers/lib/arc-seal.ts tests/lib/arc-canonicalization.test.ts
git commit -m "feat(gateway): relaxed canonicalization core for ARC sealing"
```

---

### Task 5: ARC module part 2 — AAR/AMS/AS generation, cross-verified by mailauth

**Files:**
- Modify: `workers/lib/arc-seal.ts` (append to Task 4's module)
- Modify: `package.json` (add `mailauth` to devDependencies)
- Test: `tests/lib/arc-seal.test.ts` (create)

**Interfaces:**
- Consumes: Task 4's canonicalization exports; `AuthVerdict`-shaped results (plain strings).
- Produces (Task 8 consumes):

```ts
export interface ArcSealOptions {
	auth: { spf: string; dkim: string; dmarc: string }; // AuthResult strings, e.g. "pass"/"fail"/"none"
	sealerDomain: string;
	selector: string;
	privateKeyPem: string; // PKCS8 PEM
	now?: number;          // unix seconds; defaults to Date.now()/1000 (injectable for tests)
}
/** Three-header ARC block ending in CRLF, ready to prepend — or null when an existing chain forces the skip. */
export function sealMessage(raw: Uint8Array, opts: ArcSealOptions): Promise<string | null>;
export function hasExistingArcChain(raw: Uint8Array): boolean;
```

- [ ] **Step 1: Install mailauth as a devDependency**

Run: `npm install --save-dev mailauth`
Expected: `mailauth@^4.13.3` in `devDependencies`. It is Node-only and MUST NOT be imported from `workers/**` or `shared/**` — tests only.

- [ ] **Step 2: Write the failing test**

```ts
// tests/lib/arc-seal.test.ts
import { describe, expect, it, beforeAll } from "vitest";
// mailauth is Node-only — fine here (tests run in the Node pool), forbidden in workers/.
import { authenticate } from "mailauth";
import { hasExistingArcChain, latin1Encode, sealMessage } from "../../workers/lib/arc-seal";

const SEALER = "gw.example.com";
const SELECTOR = "arc1";

let privateKeyPem: string;
let publicKeyB64: string;

function pemWrap(label: string, b64: string): string {
	const lines = b64.match(/.{1,64}/g) ?? [];
	return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

beforeAll(async () => {
	// Generate a throwaway RSA-2048 keypair per run — nothing committed.
	const kp = await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	);
	const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
	const spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
	const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
	privateKeyPem = pemWrap("PRIVATE KEY", b64(pkcs8));
	publicKeyB64 = b64(spki);
});

// DNS resolver stub for mailauth: serves our test public key for the
// sealer's selector record, NXDOMAIN for everything else. Parses names —
// never substring-matches (CodeQL rule).
async function resolver(name: string, rr: string): Promise<string[][]> {
	if (rr === "TXT" && name.toLowerCase() === `${SELECTOR}._domainkey.${SEALER}`) {
		return [[`v=DKIM1; k=rsa; p=${publicKeyB64}`]];
	}
	const err = new Error(`queryTxt ENOTFOUND ${name}`) as Error & { code: string };
	err.code = "ENOTFOUND";
	throw err;
}

const MESSAGE = [
	"Received: from mx.origin.test (mx.origin.test [192.0.2.1])",
	"\tby cf.example.net for <user@example.com>; Mon, 6 Jul 2026 10:00:00 +0000",
	"From: Sender <sender@origin.test>",
	"To: user@example.com",
	"Subject: gateway seal test",
	"Date: Mon, 6 Jul 2026 10:00:00 +0000",
	"Message-ID: <seal-test-1@origin.test>",
	"X-PhishPilot-Verdict: allow",
	"X-PhishPilot-Score: 5",
	"",
	"Hello from the gateway test.",
	"",
].join("\r\n");

const OPTS = () => ({
	auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
	sealerDomain: SEALER,
	selector: SELECTOR,
	privateKeyPem,
	now: 1_783_400_400,
});

describe("sealMessage", () => {
	it("produces a seal that mailauth independently validates as arc=pass", async () => {
		const raw = latin1Encode(MESSAGE);
		const block = await sealMessage(raw, OPTS());
		expect(block).not.toBeNull();
		expect(block).toMatch(/^ARC-Seal: i=1; a=rsa-sha256; cv=none;/);
		expect(block).toContain("ARC-Message-Signature: i=1;");
		expect(block).toContain(`ARC-Authentication-Results: i=1; ${SEALER};`);

		const sealed = block! + MESSAGE;
		const res = await authenticate(sealed, {
			resolver,
			ip: "192.0.2.1",
			helo: "mx.origin.test",
			sender: "sender@origin.test",
			disableBimi: true,
		});
		expect(res.arc?.status?.result).toBe("pass");
	});

	it("a tampered body fails mailauth ARC validation", async () => {
		const raw = latin1Encode(MESSAGE);
		const block = await sealMessage(raw, OPTS());
		const tampered = block! + MESSAGE.replace("Hello from", "Howdy from");
		const res = await authenticate(tampered, {
			resolver,
			ip: "192.0.2.1",
			helo: "mx.origin.test",
			sender: "sender@origin.test",
			disableBimi: true,
		});
		expect(res.arc?.status?.result).not.toBe("pass");
	});

	it("returns null when the message already carries an ARC chain", async () => {
		const withChain = "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=x.test; s=s; b=abc\r\n" + MESSAGE;
		const raw = latin1Encode(withChain);
		expect(hasExistingArcChain(raw)).toBe(true);
		expect(await sealMessage(raw, OPTS())).toBeNull();
	});
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run tests/lib/arc-seal.test.ts`
Expected: FAIL — `sealMessage` / `hasExistingArcChain` not exported.

- [ ] **Step 4: Implement sealing (append to `workers/lib/arc-seal.ts`)**

```ts
const ARC_HEADER_NAMES = new Set(["arc-seal", "arc-message-signature", "arc-authentication-results"]);

/** Headers AMS signs when present, in this fixed order. Never ARC-* (RFC 8617 §4.1.2). */
const AMS_SIGNED_HEADERS = [
	"from",
	"to",
	"cc",
	"subject",
	"date",
	"message-id",
	"mime-version",
	"content-type",
	"x-phishpilot-verdict",
	"x-phishpilot-score",
];

export function hasExistingArcChain(raw: Uint8Array): boolean {
	const { headerBlock } = splitRawMessage(raw);
	return parseRawHeaders(headerBlock).some((h) => ARC_HEADER_NAMES.has(h.name));
}

function toBase64(bytes: Uint8Array): string {
	let bin = "";
	const CHUNK = 0x8000;
	for (let i = 0; i < bytes.length; i += CHUNK) {
		bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
	}
	return btoa(bin);
}

function fromBase64(b64: string): Uint8Array {
	const bin = atob(b64);
	return latin1Encode(bin);
}

async function importPkcs8(pem: string): Promise<CryptoKey> {
	const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
	return crypto.subtle.importKey(
		"pkcs8",
		fromBase64(b64).buffer as ArrayBuffer,
		{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		false,
		["sign"],
	);
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.buffer as ArrayBuffer));
}

async function rsaSign(key: CryptoKey, data: string): Promise<string> {
	const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, latin1Encode(data).buffer as ArrayBuffer);
	return toBase64(new Uint8Array(sig));
}

export interface ArcSealOptions {
	auth: { spf: string; dkim: string; dmarc: string };
	sealerDomain: string;
	selector: string;
	privateKeyPem: string;
	/** Unix seconds; injectable so tests are deterministic. */
	now?: number;
}

/**
 * Build the i=1 ARC set for a message with no prior chain. Returns the
 * three headers (AS, AMS, AAR — newest-first, ready to prepend) ending in
 * CRLF, or null when a prior chain exists.
 */
export async function sealMessage(raw: Uint8Array, opts: ArcSealOptions): Promise<string | null> {
	if (hasExistingArcChain(raw)) return null;

	const { headerBlock, body } = splitRawMessage(raw);
	const headers = parseRawHeaders(headerBlock);
	const key = await importPkcs8(opts.privateKeyPem);
	const t = opts.now ?? Math.floor(Date.now() / 1000);
	const d = opts.sealerDomain;
	const s = opts.selector;

	// ── AAR ──────────────────────────────────────────────────────────
	const aar =
		`ARC-Authentication-Results: i=1; ${d}; ` +
		`spf=${opts.auth.spf || "none"}; dkim=${opts.auth.dkim || "none"}; dmarc=${opts.auth.dmarc || "none"}`;

	// ── AMS ──────────────────────────────────────────────────────────
	// h= lists each signed name once, matching the LAST occurrence of that
	// header in the message (DKIM verifiers select bottom-up).
	const present = AMS_SIGNED_HEADERS.filter((n) => headers.some((h) => h.name === n));
	const bh = toBase64(await sha256(canonicalizeBodyRelaxed(body)));
	const amsUnsigned =
		`ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; ` +
		`d=${d}; s=${s}; t=${t}; h=${present.join(":")}; bh=${bh}; b=`;
	let amsInput = "";
	for (const name of present) {
		const matches = headers.filter((h) => h.name === name);
		const last = matches[matches.length - 1];
		amsInput += canonicalizeHeaderRelaxed(last.raw) + "\r\n";
	}
	amsInput += canonicalizeHeaderRelaxed(amsUnsigned); // own header, b= empty, no CRLF
	const ams = amsUnsigned + (await rsaSign(key, amsInput));

	// ── AS ───────────────────────────────────────────────────────────
	// Signs the ARC set in instance order: AAR, AMS, AS(b=) (RFC 8617 §5.1.1).
	const asUnsigned = `ARC-Seal: i=1; a=rsa-sha256; cv=none; d=${d}; s=${s}; t=${t}; b=`;
	const asInput =
		canonicalizeHeaderRelaxed(aar) +
		"\r\n" +
		canonicalizeHeaderRelaxed(ams) +
		"\r\n" +
		canonicalizeHeaderRelaxed(asUnsigned);
	const arcSeal = asUnsigned + (await rsaSign(key, asInput));

	return `${arcSeal}\r\n${ams}\r\n${aar}\r\n`;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/lib/arc-seal.test.ts tests/lib/arc-canonicalization.test.ts`
Expected: PASS. If the mailauth cross-check fails, debug with `console.log(JSON.stringify(res.arc, null, 2))` — the usual culprits are h= ordering, a stray CRLF on the final signed header, or bh= computed over the un-canonicalized body. Do NOT loosen the assertion; the mailauth pass IS the acceptance gate for this module.

- [ ] **Step 6: Commit**

```bash
git add workers/lib/arc-seal.ts tests/lib/arc-seal.test.ts package.json package-lock.json
git commit -m "feat(gateway): ARC sealing (RFC 8617 i=1) cross-verified by mailauth"
```

---

### Task 6: Minimal SMTP submission client over `cloudflare:sockets`

**Files:**
- Create: `workers/lib/smtp-client.ts`
- Test: `tests/lib/smtp-client.test.ts` (create)

**Interfaces:**
- Produces (Task 7 consumes):

```ts
export class SmtpTransientError extends Error {} // 4xx, timeout, connection drop → caller throws to origin for retry
export class SmtpPermanentError extends Error {} // 5xx → caller alerts, does not retry
export interface SmtpSubmitOptions {
	host: string;
	port: number;
	implicitTls: boolean;
	auth?: { user: string; pass: string };
	mailFrom: string; // may be "" → MAIL FROM:<>
	rcptTo: string;
	raw: Uint8Array;
	heloHost?: string;          // default "phishsoc-gateway.invalid"
	timeoutMs?: number;         // per-response read timeout, default 30_000
	connectFn?: SmtpConnectFn;  // injected fake in tests; defaults to cloudflare:sockets connect (dynamic import)
}
export function submitRaw(opts: SmtpSubmitOptions): Promise<void>;
export type SmtpConnectFn = (
	addr: { hostname: string; port: number },
	options?: { secureTransport?: "on" | "off" | "starttls" },
) => SmtpSocketLike;
export interface SmtpSocketLike {
	readable: ReadableStream<Uint8Array>;
	writable: WritableStream<Uint8Array>;
	startTls?: () => SmtpSocketLike;
	close: () => Promise<void>;
}
```

**Protocol constraint (why this module exists):** Workers cannot connect on port 25; submission on 587 (STARTTLS) / 465 (implicit TLS) only. `cloudflare:sockets` requires `secureTransport: "starttls"` at connect time to later upgrade via `startTls()`. The module MUST NOT be imported eagerly by Node-pool test files — the production `connect` is loaded via dynamic `import("cloudflare:sockets")` only when `connectFn` is not injected.

- [ ] **Step 1: Write the failing test (scripted fake socket)**

```ts
// tests/lib/smtp-client.test.ts
import { describe, expect, it } from "vitest";
import {
	SmtpPermanentError,
	SmtpTransientError,
	submitRaw,
	type SmtpConnectFn,
	type SmtpSocketLike,
} from "../../workers/lib/smtp-client";

/**
 * Scripted fake SMTP server. Each entry: a regex the next client line must
 * match, and the reply to send. The greeting fires unprompted (expect: null).
 * `startTls()` continues the same script on a "new" socket.
 */
interface ScriptStep {
	expect: RegExp | null;
	reply: string;
}

function fakeSmtp(script: ScriptStep[]) {
	const clientLines: string[] = [];
	let step = 0;
	let controller!: ReadableStreamDefaultController<Uint8Array>;
	const enc = new TextEncoder();
	const dec = new TextDecoder();

	const pushReplies = () => {
		while (step < script.length && script[step].expect === null) {
			controller.enqueue(enc.encode(script[step].reply + "\r\n"));
			step++;
		}
	};

	const mkSocket = (): SmtpSocketLike => ({
		readable: new ReadableStream<Uint8Array>({
			start(c) {
				controller = c;
				pushReplies();
			},
		}),
		writable: new WritableStream<Uint8Array>({
			write(chunk) {
				// Accumulate and split on CRLF; DATA payload arrives as lines too.
				const text = dec.decode(chunk);
				for (const line of text.split("\r\n")) {
					if (line === "" && !text.endsWith("\r\n")) continue;
					if (line === "") continue;
					clientLines.push(line);
					const s = script[step];
					if (s?.expect && s.expect.test(line)) {
						controller.enqueue(enc.encode(s.reply + "\r\n"));
						step++;
						pushReplies();
					}
				}
			},
		}),
		startTls: () => mkSocket(),
		close: async () => {
			try {
				controller.close();
			} catch {
				/* already closed */
			}
		},
	});

	const connectFn: SmtpConnectFn = (addr) => {
		// Parse-compare, never substring (CodeQL js/incomplete-url-substring-sanitization).
		expect(addr.hostname).toBe("smtp-relay.gmail.com");
		return mkSocket();
	};
	return { connectFn, clientLines };
}

const RAW = new TextEncoder().encode(
	"Subject: t\r\n\r\nline one\r\n.hidden dot line\r\n",
);

const BASE = {
	host: "smtp-relay.gmail.com",
	port: 587,
	implicitTls: false,
	mailFrom: "sender@origin.test",
	rcptTo: "user@example.com",
	raw: RAW,
	timeoutMs: 2000,
};

function happyScript(): ScriptStep[] {
	return [
		{ expect: null, reply: "220 fake ESMTP" },
		{ expect: /^EHLO /, reply: "250-fake\r\n250-STARTTLS\r\n250 AUTH PLAIN" },
		{ expect: /^STARTTLS$/, reply: "220 go ahead" },
		{ expect: /^EHLO /, reply: "250-fake\r\n250 AUTH PLAIN" },
		{ expect: /^AUTH PLAIN /, reply: "235 ok" },
		{ expect: /^MAIL FROM:<sender@origin\.test>$/, reply: "250 ok" },
		{ expect: /^RCPT TO:<user@example\.com>$/, reply: "250 ok" },
		{ expect: /^DATA$/, reply: "354 go" },
		{ expect: /^\.$/, reply: "250 queued" },
		{ expect: /^QUIT$/, reply: "221 bye" },
	];
}

describe("submitRaw", () => {
	it("walks the full STARTTLS + AUTH submission flow and dot-stuffs", async () => {
		const { connectFn, clientLines } = fakeSmtp(happyScript());
		await submitRaw({ ...BASE, auth: { user: "u", pass: "p" }, connectFn });
		// AUTH PLAIN payload is base64("\0u\0p")
		expect(clientLines).toContain(`AUTH PLAIN ${btoa("\0u\0p")}`);
		// The leading-dot body line was stuffed on the wire.
		expect(clientLines).toContain("..hidden dot line");
		expect(clientLines).not.toContain(".hidden dot line");
	});

	it("throws SmtpTransientError on 4xx", async () => {
		const script = happyScript().slice(0, 5);
		script.push({ expect: /^MAIL FROM:/, reply: "451 try later" });
		const { connectFn } = fakeSmtp(script);
		await expect(
			submitRaw({ ...BASE, auth: { user: "u", pass: "p" }, connectFn }),
		).rejects.toBeInstanceOf(SmtpTransientError);
	});

	it("throws SmtpPermanentError on 5xx (bad credentials)", async () => {
		const script = happyScript().slice(0, 4);
		script.push({ expect: /^AUTH PLAIN /, reply: "535 auth failed" });
		const { connectFn } = fakeSmtp(script);
		await expect(
			submitRaw({ ...BASE, auth: { user: "u", pass: "p" }, connectFn }),
		).rejects.toBeInstanceOf(SmtpPermanentError);
	});

	it("skips STARTTLS on implicit TLS and skips AUTH without credentials", async () => {
		const script: ScriptStep[] = [
			{ expect: null, reply: "220 fake ESMTP" },
			{ expect: /^EHLO /, reply: "250 fake" },
			{ expect: /^MAIL FROM:<>$/, reply: "250 ok" },
			{ expect: /^RCPT TO:<user@example\.com>$/, reply: "250 ok" },
			{ expect: /^DATA$/, reply: "354 go" },
			{ expect: /^\.$/, reply: "250 queued" },
			{ expect: /^QUIT$/, reply: "221 bye" },
		];
		const { connectFn } = fakeSmtp(script);
		await submitRaw({ ...BASE, implicitTls: true, port: 465, mailFrom: "", connectFn });
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/lib/smtp-client.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `workers/lib/smtp-client.ts`**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Minimal SMTP *submission* client for inline-gateway relay (issue #32).
 *
 * Workers cannot open port 25 (platform block), so this client only speaks
 * authenticated submission: 587 with STARTTLS or 465 with implicit TLS.
 * `cloudflare:sockets` is imported dynamically so Node-pool tests can load
 * this module and inject a fake `connectFn`.
 *
 * Error taxonomy is the caller's control flow (see relayAfterVerdict):
 * 4xx/timeout/drop → SmtpTransientError (throw to origin → MTA retry);
 * 5xx → SmtpPermanentError (alert, don't retry).
 */

export class SmtpTransientError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "SmtpTransientError";
	}
}

export class SmtpPermanentError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "SmtpPermanentError";
	}
}

export interface SmtpSocketLike {
	readable: ReadableStream<Uint8Array>;
	writable: WritableStream<Uint8Array>;
	startTls?: () => SmtpSocketLike;
	close: () => Promise<void>;
}

export type SmtpConnectFn = (
	addr: { hostname: string; port: number },
	options?: { secureTransport?: "on" | "off" | "starttls" },
) => SmtpSocketLike;

export interface SmtpSubmitOptions {
	host: string;
	port: number;
	implicitTls: boolean;
	auth?: { user: string; pass: string };
	mailFrom: string;
	rcptTo: string;
	raw: Uint8Array;
	heloHost?: string;
	timeoutMs?: number;
	connectFn?: SmtpConnectFn;
}

interface SmtpResponse {
	code: number;
	text: string;
}

/** Buffered CRLF line reader over a socket's readable stream. */
class LineReader {
	private buffer = "";
	private reader: ReadableStreamDefaultReader<Uint8Array>;
	private decoder = new TextDecoder();

	constructor(stream: ReadableStream<Uint8Array>, private timeoutMs: number) {
		this.reader = stream.getReader();
	}

	async readLine(): Promise<string> {
		while (true) {
			const idx = this.buffer.indexOf("\r\n");
			if (idx >= 0) {
				const line = this.buffer.slice(0, idx);
				this.buffer = this.buffer.slice(idx + 2);
				return line;
			}
			const next = await Promise.race([
				this.reader.read(),
				new Promise<never>((_, reject) =>
					setTimeout(() => reject(new SmtpTransientError("SMTP read timeout")), this.timeoutMs),
				),
			]);
			if (next.done) throw new SmtpTransientError("SMTP connection closed unexpectedly");
			this.buffer += this.decoder.decode(next.value, { stream: true });
		}
	}

	releaseLock(): void {
		this.reader.releaseLock();
	}
}

/** Read one (possibly multiline) SMTP response: lines until `NNN<SP>`. */
async function readResponse(lines: LineReader): Promise<SmtpResponse> {
	const collected: string[] = [];
	while (true) {
		const line = await lines.readLine();
		collected.push(line);
		if (/^\d{3} /.test(line)) {
			return { code: Number.parseInt(line.slice(0, 3), 10), text: collected.join("\n") };
		}
		if (!/^\d{3}-/.test(line)) {
			throw new SmtpTransientError(`Malformed SMTP response line: ${line}`);
		}
	}
}

function classify(res: SmtpResponse, context: string): never {
	const msg = `SMTP ${context} failed: ${res.text}`;
	if (res.code >= 500) throw new SmtpPermanentError(msg);
	throw new SmtpTransientError(msg);
}

/** Dot-stuff the payload and guarantee a trailing CRLF (RFC 5321 §4.5.2). */
export function dotStuff(raw: Uint8Array): Uint8Array {
	// Manual 1:1 decode — TextDecoder("latin1") is windows-1252 and corrupts
	// bytes 0x80–0x9F on round-trip (see latin1Decode in arc-seal.ts).
	let text = "";
	const CHUNK = 0x8000;
	for (let i = 0; i < raw.length; i += CHUNK) {
		text += String.fromCharCode(...raw.subarray(i, i + CHUNK));
	}
	text = text.replace(/(^|\r\n)\./g, "$1..");
	if (!text.endsWith("\r\n")) text += "\r\n";
	const out = new Uint8Array(text.length);
	for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
	return out;
}

export async function submitRaw(opts: SmtpSubmitOptions): Promise<void> {
	const timeoutMs = opts.timeoutMs ?? 30_000;
	const heloHost = opts.heloHost ?? "phishsoc-gateway.invalid";
	const connectFn =
		opts.connectFn ??
		((await import("cloudflare:sockets")).connect as unknown as SmtpConnectFn);

	let socket: SmtpSocketLike;
	try {
		socket = connectFn(
			{ hostname: opts.host, port: opts.port },
			{ secureTransport: opts.implicitTls ? "on" : "starttls" },
		);
	} catch (e) {
		throw new SmtpTransientError(`SMTP connect failed: ${(e as Error).message}`);
	}

	let lines = new LineReader(socket.readable, timeoutMs);
	let writer = socket.writable.getWriter();
	const encoder = new TextEncoder();

	const send = async (cmd: string) => {
		await writer.write(encoder.encode(cmd + "\r\n"));
	};
	const expect = async (okCodes: number[], context: string): Promise<SmtpResponse> => {
		const res = await readResponse(lines);
		if (!okCodes.includes(res.code)) classify(res, context);
		return res;
	};

	try {
		await expect([220], "greeting");
		await send(`EHLO ${heloHost}`);
		await expect([250], "EHLO");

		if (!opts.implicitTls) {
			await send("STARTTLS");
			await expect([220], "STARTTLS");
			if (!socket.startTls) throw new SmtpTransientError("socket does not support startTls");
			lines.releaseLock();
			writer.releaseLock();
			socket = socket.startTls();
			lines = new LineReader(socket.readable, timeoutMs);
			writer = socket.writable.getWriter();
			await send(`EHLO ${heloHost}`);
			await expect([250], "EHLO (post-TLS)");
		}

		if (opts.auth) {
			await send(`AUTH PLAIN ${btoa(`\0${opts.auth.user}\0${opts.auth.pass}`)}`);
			await expect([235], "AUTH PLAIN");
		}

		await send(`MAIL FROM:<${opts.mailFrom}>`);
		await expect([250], "MAIL FROM");
		await send(`RCPT TO:<${opts.rcptTo}>`);
		await expect([250, 251], "RCPT TO");
		await send("DATA");
		await expect([354], "DATA");
		await writer.write(dotStuff(opts.raw));
		await writer.write(encoder.encode(".\r\n"));
		await expect([250], "message body");
		await send("QUIT");
	} finally {
		try {
			writer.releaseLock();
			await socket.close();
		} catch {
			/* connection teardown is best-effort */
		}
	}
}
```

Note: `AUTH PLAIN` credentials here are ASCII/latin1 (`btoa` throws on code points > 0xFF). Workspace app passwords and M365 client secrets are ASCII; if a non-ASCII password ever matters, switch to the `toBase64(new TextEncoder().encode(...))` helper from `arc-seal.ts` — do not add a Buffer dependency.

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/lib/smtp-client.test.ts`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add workers/lib/smtp-client.ts tests/lib/smtp-client.test.ts
git commit -m "feat(gateway): SMTP submission client over cloudflare:sockets"
```

---

### Task 7: `SmtpRelayProvider` — policy → credentials → wire

**Files:**
- Create: `workers/providers/smtp-relay.ts`
- Modify: `workers/providers/registry.ts` (add relay accessor at the bottom)
- Test: `tests/lib/smtp-relay-provider.test.ts` (create)

**Interfaces:**
- Consumes: `ResolvedRelayPolicy` (Task 3), `submitRaw`/error classes (Task 6).
- Produces (Task 8 consumes):

```ts
export interface RelayEnvelope { mailFrom: string; rcptTo: string }
export class SmtpRelayProvider {
	readonly id = "smtp-relay";
	relayRaw(env: Env, raw: Uint8Array, envelope: RelayEnvelope, policy: ResolvedRelayPolicy, connectFn?: SmtpConnectFn): Promise<void>;
}
export const smtpRelayProvider: SmtpRelayProvider;
// registry.ts:
export function getRelayProvider(): SmtpRelayProvider;
```

- [ ] **Step 1: Write the failing test**

```ts
// tests/lib/smtp-relay-provider.test.ts
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SmtpPermanentError } from "../../workers/lib/smtp-client";

// Mock only submitRaw; keep the real error classes.
vi.mock("../../workers/lib/smtp-client", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../../workers/lib/smtp-client")>();
	return { ...actual, submitRaw: vi.fn(async () => {}) };
});

import { submitRaw } from "../../workers/lib/smtp-client";
import { smtpRelayProvider } from "../../workers/providers/smtp-relay";
import type { Env } from "../../workers/types";

const policy = {
	target: { host: "smtp-relay.gmail.com", port: 587, implicitTls: false },
	credentialsSecret: "RELAY_CREDS_EXAMPLE_COM",
	actions: { allow: "relay", tag: "relay", quarantine: "hold", block: "drop" },
} as const;

const raw = new TextEncoder().encode("Subject: t\r\n\r\nbody\r\n");
const envelope = { mailFrom: "s@origin.test", rcptTo: "u@example.com" };

describe("SmtpRelayProvider.relayRaw", () => {
	beforeEach(() => vi.mocked(submitRaw).mockClear());

	it("resolves credentials from the named secret and calls submitRaw", async () => {
		const env = { RELAY_CREDS_EXAMPLE_COM: JSON.stringify({ user: "u", pass: "p" }) } as unknown as Env;
		await smtpRelayProvider.relayRaw(env, raw, envelope, policy);
		expect(submitRaw).toHaveBeenCalledWith(
			expect.objectContaining({
				host: "smtp-relay.gmail.com",
				port: 587,
				implicitTls: false,
				auth: { user: "u", pass: "p" },
				mailFrom: "s@origin.test",
				rcptTo: "u@example.com",
				raw,
			}),
		);
	});

	it("throws SmtpPermanentError when the secret is missing or malformed", async () => {
		await expect(
			smtpRelayProvider.relayRaw({} as Env, raw, envelope, policy),
		).rejects.toBeInstanceOf(SmtpPermanentError);
		const bad = { RELAY_CREDS_EXAMPLE_COM: "not-json" } as unknown as Env;
		await expect(
			smtpRelayProvider.relayRaw(bad, raw, envelope, policy),
		).rejects.toBeInstanceOf(SmtpPermanentError);
		expect(submitRaw).not.toHaveBeenCalled();
	});

	it("relays unauthenticated when the policy names no secret", async () => {
		const p = { ...policy, credentialsSecret: undefined };
		await smtpRelayProvider.relayRaw({} as Env, raw, envelope, p);
		expect(submitRaw).toHaveBeenCalledWith(expect.objectContaining({ auth: undefined }));
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/lib/smtp-relay-provider.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `workers/providers/smtp-relay.ts`**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Outbound relay provider for inline-gateway mode (issue #32).
 *
 * Relays the raw (verdict-header-prepended, ARC-sealed) RFC-5322 bytes to
 * the per-domain SMTP submission target. Credentials come from a Worker
 * Secret named by the policy (`{"user":"...","pass":"..."}` JSON) — never
 * from R2 settings blobs.
 *
 * A missing/malformed credentials secret is a PERMANENT failure: retrying
 * won't fix operator misconfiguration, and the caller alerts on it.
 */

import type { Env } from "../types";
import type { ResolvedRelayPolicy } from "../lib/relay-policy";
import { SmtpPermanentError, submitRaw, type SmtpConnectFn } from "../lib/smtp-client";

export interface RelayEnvelope {
	mailFrom: string;
	rcptTo: string;
}

export class SmtpRelayProvider {
	readonly id = "smtp-relay";

	async relayRaw(
		env: Env,
		raw: Uint8Array,
		envelope: RelayEnvelope,
		policy: ResolvedRelayPolicy,
		connectFn?: SmtpConnectFn,
	): Promise<void> {
		let auth: { user: string; pass: string } | undefined;
		if (policy.credentialsSecret) {
			const secret = (env as unknown as Record<string, unknown>)[policy.credentialsSecret];
			if (typeof secret !== "string" || secret.length === 0) {
				throw new SmtpPermanentError(
					`relay credentials secret ${policy.credentialsSecret} is not configured`,
				);
			}
			let parsed: { user?: unknown; pass?: unknown };
			try {
				parsed = JSON.parse(secret) as { user?: unknown; pass?: unknown };
			} catch {
				throw new SmtpPermanentError(
					`relay credentials secret ${policy.credentialsSecret} is not valid JSON`,
				);
			}
			if (typeof parsed.user !== "string" || typeof parsed.pass !== "string") {
				throw new SmtpPermanentError(
					`relay credentials secret ${policy.credentialsSecret} must be {"user","pass"} JSON`,
				);
			}
			auth = { user: parsed.user, pass: parsed.pass };
		}

		await submitRaw({
			host: policy.target.host,
			port: policy.target.port,
			implicitTls: policy.target.implicitTls,
			auth,
			mailFrom: envelope.mailFrom,
			rcptTo: envelope.rcptTo,
			raw,
			connectFn,
		});
	}
}

export const smtpRelayProvider = new SmtpRelayProvider();
```

In `workers/providers/registry.ts`: add the import at the top with the existing imports, and the accessor below `getProvider`, keeping its comment style:

```ts
import { smtpRelayProvider, type SmtpRelayProvider } from "./smtp-relay";

/**
 * Relay provider for inline-gateway mode (issue #32). Selected by
 * relay-policy presence on the recipient domain, not per-mailbox config —
 * see `resolveRelayPolicy` in workers/lib/relay-policy.ts.
 */
export function getRelayProvider(): SmtpRelayProvider {
	return smtpRelayProvider;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/lib/smtp-relay-provider.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 5: Typecheck and commit**

Run: `npm run typecheck` — expected clean.

```bash
git add workers/providers/smtp-relay.ts workers/providers/registry.ts tests/lib/smtp-relay-provider.test.ts
git commit -m "feat(gateway): SmtpRelayProvider with secret-named credentials"
```

---

### Task 8: `relayAfterVerdict` orchestrator — headers → seal → relay, error policy

**Files:**
- Create: `workers/lib/gateway-relay.ts`
- Test: `tests/lib/gateway-relay.test.ts` (create)

**Interfaces:**
- Consumes: `behaviorFor`/`ResolvedRelayPolicy` (Task 3), `sealMessage`/`latin1Encode` (Task 5), `smtpRelayProvider` (Task 7), `getOrgSettings` (`workers/lib/org-settings.ts`), `dispatchSecurityAlert` (`workers/lib/security-alert.ts:43`).
- Produces (Tasks 11, 12 consume):

```ts
export type RelayOutcome = "relayed" | "held" | "dropped" | "failed_permanent";
export interface RelayAfterVerdictOptions {
	env: Env;
	ctx: AlertExecutionContext | undefined;
	raw: Uint8Array;
	verdict: FinalVerdict | null;
	policy: ResolvedRelayPolicy;
	envelopeFrom: string;
	rcptTo: string;
	passthrough?: boolean;
	/** Test seam; defaults to smtpRelayProvider.relayRaw. */
	relayFn?: (env: Env, raw: Uint8Array, envelope: RelayEnvelope, policy: ResolvedRelayPolicy) => Promise<void>;
}
export function relayAfterVerdict(opts: RelayAfterVerdictOptions): Promise<RelayOutcome>;
export function prependHeaders(raw: Uint8Array, lines: string[]): Uint8Array;
```

**Error policy (from the spec, enforced here):**
- `SmtpTransientError` → rethrow always (origin MTA retries).
- `SmtpPermanentError` → registered path: alert + return `"failed_permanent"` (mirror copy is safe); passthrough: rethrow (bounce is the only honest outcome — no local copy).
- Seal failure → alert + relay **unsealed**.
- `verdict === null` (scan skipped/failed) → relay, no verdict headers, no seal (AAR needs auth results we don't have).

- [ ] **Step 1: Write the failing test**

```ts
// tests/lib/gateway-relay.test.ts
import { beforeEach, describe, expect, it, vi } from "vitest";
import { prependHeaders, relayAfterVerdict } from "../../workers/lib/gateway-relay";
import { SmtpPermanentError, SmtpTransientError } from "../../workers/lib/smtp-client";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";
import type { Env } from "../../workers/types";
import type { FinalVerdict } from "../../workers/security/verdict";

const dec = new TextDecoder();

function verdict(action: FinalVerdict["action"], score = 42): FinalVerdict {
	return {
		action,
		score,
		confidence: 0.9,
		explanation: "test",
		auth: { spf: "pass", dkim: "pass", dmarc: "pass", dkimObservations: [] },
		classification: { verdict: "ok", confidence: 0.9 } as FinalVerdict["classification"],
		signals: [],
	};
}

const policy = {
	target: { host: "smtp-relay.gmail.com", port: 587, implicitTls: false },
	actions: { allow: "relay", tag: "relay", quarantine: "hold", block: "drop" },
} as const;

/** Env whose BUCKET serves org settings; no ARC key unless added. */
function fakeEnv(orgSettings: Record<string, unknown>, extra: Record<string, unknown> = {}): Env {
	return {
		BUCKET: {
			get: async (key: string) =>
				key === "org/settings.json"
					? { etag: "e1", json: async () => orgSettings }
					: null,
		},
		...extra,
	} as unknown as Env;
}

const RAW = new TextEncoder().encode("Subject: t\r\nFrom: a@b.test\r\n\r\nbody\r\n");

describe("prependHeaders", () => {
	it("prepends CRLF-terminated lines, byte-preserving the rest", () => {
		const out = prependHeaders(RAW, ["X-PhishPilot-Verdict: allow"]);
		expect(dec.decode(out)).toBe("X-PhishPilot-Verdict: allow\r\n" + dec.decode(RAW));
	});
	it("is a no-op for an empty list", () => {
		expect(prependHeaders(RAW, [])).toBe(RAW);
	});
});

describe("relayAfterVerdict", () => {
	beforeEach(() => clearOrgSettingsCache());

	const base = (relayFn: (...a: never[]) => Promise<void>, env = fakeEnv({})) => ({
		env,
		ctx: undefined,
		raw: RAW,
		policy,
		envelopeFrom: "sender@origin.test",
		rcptTo: "user@example.com",
		relayFn: relayFn as never,
	});

	it("hold and drop short-circuit without touching the wire", async () => {
		const relayFn = vi.fn(async () => {});
		expect(await relayAfterVerdict({ ...base(relayFn), verdict: verdict("quarantine") })).toBe("held");
		expect(await relayAfterVerdict({ ...base(relayFn), verdict: verdict("block") })).toBe("dropped");
		expect(relayFn).not.toHaveBeenCalled();
	});

	it("relays with verdict headers; no seal when ARC is unconfigured", async () => {
		let sent: Uint8Array | undefined;
		const relayFn = vi.fn(async (_e: Env, raw: Uint8Array) => {
			sent = raw;
		});
		const out = await relayAfterVerdict({ ...base(relayFn as never), verdict: verdict("tag", 55) });
		expect(out).toBe("relayed");
		const text = dec.decode(sent!);
		expect(text.startsWith("X-PhishPilot-Verdict: tag\r\nX-PhishPilot-Score: 55\r\n")).toBe(true);
		expect(text).not.toContain("ARC-Seal");
	});

	it("seals when org gateway config + key are present", async () => {
		const kp = await crypto.subtle.generateKey(
			{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
			true,
			["sign", "verify"],
		);
		const pkcs8 = Buffer.from(await crypto.subtle.exportKey("pkcs8", kp.privateKey)).toString("base64");
		const pem = `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----`;
		const env = fakeEnv(
			{ gateway: { arcSealerDomain: "gw.example.com", arcSelector: "arc1" } },
			{ ARC_SEAL_PRIVATE_KEY: pem },
		);
		let sent: Uint8Array | undefined;
		const relayFn = async (_e: Env, raw: Uint8Array) => {
			sent = raw;
		};
		const out = await relayAfterVerdict({ ...base(relayFn as never, env), verdict: verdict("allow") });
		expect(out).toBe("relayed");
		expect(dec.decode(sent!).startsWith("ARC-Seal: i=1;")).toBe(true);
	});

	it("a broken ARC key alerts and relays unsealed, never blocks delivery", async () => {
		const env = fakeEnv(
			{ gateway: { arcSealerDomain: "gw.example.com", arcSelector: "arc1" } },
			{ ARC_SEAL_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----" },
		);
		let sent: Uint8Array | undefined;
		const relayFn = async (_e: Env, raw: Uint8Array) => {
			sent = raw;
		};
		const out = await relayAfterVerdict({ ...base(relayFn as never, env), verdict: verdict("allow") });
		expect(out).toBe("relayed");
		expect(dec.decode(sent!)).not.toContain("ARC-Seal");
	});

	it("null verdict relays as-is: no headers, no seal (fail-open)", async () => {
		let sent: Uint8Array | undefined;
		const relayFn = async (_e: Env, raw: Uint8Array) => {
			sent = raw;
		};
		const out = await relayAfterVerdict({ ...base(relayFn as never), verdict: null });
		expect(out).toBe("relayed");
		expect(sent).toBe(RAW);
	});

	it("permanent failure: alerts + failed_permanent on registered path, throws on passthrough", async () => {
		const relayFn = async () => {
			throw new SmtpPermanentError("535 nope");
		};
		expect(await relayAfterVerdict({ ...base(relayFn as never), verdict: verdict("allow") })).toBe(
			"failed_permanent",
		);
		await expect(
			relayAfterVerdict({ ...base(relayFn as never), verdict: verdict("allow"), passthrough: true }),
		).rejects.toBeInstanceOf(SmtpPermanentError);
	});

	it("transient failure always rethrows (origin retries)", async () => {
		const relayFn = async () => {
			throw new SmtpTransientError("451 later");
		};
		await expect(
			relayAfterVerdict({ ...base(relayFn as never), verdict: verdict("allow") }),
		).rejects.toBeInstanceOf(SmtpTransientError);
	});
});
```

Note: `clearOrgSettingsCache` — `workers/lib/org-settings.ts` mirrors `clearDomainSettingsCache` from `workers/lib/domain-settings.ts:129` (the module doc-comment says the two are pattern-identical). If the export name differs, use the actual one — check the file before writing the import.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/lib/gateway-relay.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `workers/lib/gateway-relay.ts`**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Verdict → relay orchestration for inline-gateway mode (issue #32).
 *
 * Called from `receiveEmail` (registered mailboxes; mirror copy already
 * stored) and `receiveGatewayPassthrough` (unregistered recipients; no
 * local copy). Maps the verdict through the domain's action table, then
 * for relaying behaviors: prepend X-PhishPilot verdict headers, ARC-seal
 * (best-effort), and submit to the policy target.
 *
 * Error policy:
 * - transient SMTP failure  → rethrow (CF defers; origin MTA retries)
 * - permanent SMTP failure  → registered: alert + "failed_permanent";
 *                             passthrough: rethrow (bounce — no local copy)
 * - seal failure            → alert + relay unsealed (deliverability
 *                             degrades; delivery never blocked on crypto)
 * - null verdict            → relay untouched (fail-open: a gateway must
 *                             never eat mail because scanning broke)
 */

import type { Env } from "../types";
import type { FinalVerdict } from "../security/verdict";
import { behaviorFor, type ResolvedRelayPolicy } from "./relay-policy";
import { latin1Encode, sealMessage } from "./arc-seal";
import { getOrgSettings } from "./org-settings";
import { dispatchSecurityAlert, type AlertExecutionContext } from "./security-alert";
import { SmtpPermanentError } from "./smtp-client";
import { smtpRelayProvider, type RelayEnvelope } from "../providers/smtp-relay";

export type RelayOutcome = "relayed" | "held" | "dropped" | "failed_permanent";

/** Prepend header lines (no CRLF of their own) to raw message bytes. */
export function prependHeaders(raw: Uint8Array, lines: string[]): Uint8Array {
	if (lines.length === 0) return raw;
	const block = latin1Encode(lines.map((l) => l + "\r\n").join(""));
	const out = new Uint8Array(block.length + raw.length);
	out.set(block, 0);
	out.set(raw, block.length);
	return out;
}

/** Prepend a pre-terminated (CRLF-ended) raw header block. */
function prependRawBlock(raw: Uint8Array, block: string): Uint8Array {
	const bytes = latin1Encode(block);
	const out = new Uint8Array(bytes.length + raw.length);
	out.set(bytes, 0);
	out.set(raw, bytes.length);
	return out;
}

export interface RelayAfterVerdictOptions {
	env: Env;
	ctx: AlertExecutionContext | undefined;
	raw: Uint8Array;
	verdict: FinalVerdict | null;
	policy: ResolvedRelayPolicy;
	envelopeFrom: string;
	rcptTo: string;
	passthrough?: boolean;
	relayFn?: (
		env: Env,
		raw: Uint8Array,
		envelope: RelayEnvelope,
		policy: ResolvedRelayPolicy,
	) => Promise<void>;
}

export async function relayAfterVerdict(opts: RelayAfterVerdictOptions): Promise<RelayOutcome> {
	const action = opts.verdict?.action ?? null;
	const behavior = behaviorFor(action, opts.policy, { passthrough: opts.passthrough });
	if (behavior === "hold") return "held";
	if (behavior === "drop") return "dropped";

	let outgoing = opts.raw;
	if (opts.verdict) {
		outgoing = prependHeaders(outgoing, [
			`X-PhishPilot-Verdict: ${opts.verdict.action}`,
			`X-PhishPilot-Score: ${opts.verdict.score}`,
		]);

		// ARC seal — best-effort. Sealing covers the verdict headers above.
		try {
			const gw = (await getOrgSettings(opts.env)).gateway;
			const pem = opts.env.ARC_SEAL_PRIVATE_KEY;
			if (gw?.arcSealerDomain && gw.arcSelector && pem) {
				const block = await sealMessage(outgoing, {
					auth: {
						spf: opts.verdict.auth.spf,
						dkim: opts.verdict.auth.dkim,
						dmarc: opts.verdict.auth.dmarc,
					},
					sealerDomain: gw.arcSealerDomain,
					selector: gw.arcSelector,
					privateKeyPem: pem,
				});
				if (block) outgoing = prependRawBlock(outgoing, block);
			}
		} catch (e) {
			console.error("gateway: ARC seal failed; relaying unsealed:", (e as Error).message);
			dispatchSecurityAlert(opts.env, opts.ctx, {
				type: "gateway_seal_failed",
				rcptTo: opts.rcptTo,
				error: (e as Error).message,
			});
		}
	}

	const relayFn = opts.relayFn ?? smtpRelayProvider.relayRaw.bind(smtpRelayProvider);
	try {
		await relayFn(opts.env, outgoing, { mailFrom: opts.envelopeFrom, rcptTo: opts.rcptTo }, opts.policy);
		return "relayed";
	} catch (e) {
		if (e instanceof SmtpPermanentError && !opts.passthrough) {
			console.error("gateway: permanent relay failure (mirror copy retained):", e.message);
			dispatchSecurityAlert(opts.env, opts.ctx, {
				type: "gateway_relay_failed",
				rcptTo: opts.rcptTo,
				target: opts.policy.target.host,
				error: e.message,
			});
			return "failed_permanent";
		}
		throw e;
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/lib/gateway-relay.test.ts`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add workers/lib/gateway-relay.ts tests/lib/gateway-relay.test.ts
git commit -m "feat(gateway): relayAfterVerdict orchestrator with fail-open/fail-closed error policy"
```

---

### Task 9: `stateless` option on `runSecurityPipeline`

**Files:**
- Modify: `workers/security/index.ts` (`RunPipelineInput` ~line 70; DO-touching sites at ~131, ~166, ~202, and the `persistAll` call)
- Test: `test/security/stateless-pipeline.test.ts` (create)

**Interfaces:**
- Produces: `RunPipelineInput.stateless?: boolean`. When true the pipeline never touches the MailboxDO: no DKIM-observation write, reputation is `null`, sender-graph detector skipped, `persistAll` skipped. Settings resolution is unchanged — an unregistered `mailboxId` falls through mailbox(absent) → domain → org → defaults, which is exactly how the passthrough path gets domain-tier settings (Task 12 consumes).

**Why:** `receiveGatewayPassthrough` scores mail for recipients with no mailbox. Calling the pipeline as-is would create a junk `MailboxDO` per unregistered address (`getMailboxStub` at `workers/security/index.ts:132,166,492` instantiates on first use) and persist verdicts nobody can see.

- [ ] **Step 1: Read the current DO-touching sites**

Read `workers/security/index.ts` lines 60–230 and the `persistAll` call site (`grep -n "persistAll(" workers/security/index.ts` — the definition is ~line 483; find the call inside `runSecurityPipeline`). The four sites to guard:
1. `recordDkimSelectorsObserved` fire-and-forget block (~line 131: `if (auth.dkimObservations.length > 0) { const stub = getMailboxStub(...)`).
2. Reputation fetch (~line 166: `const stub = getMailboxStub(env, mailboxId);` followed by `stub.getSenderReputation(sender)`).
3. Sender-graph detector (~line 202: `detector.score({ senderAddress: sender, senderName }, stub)`).
4. The `persistAll(...)` call near the end of `runSecurityPipeline`.

- [ ] **Step 2: Write the failing test**

Read `test/security/run-pipeline.test.ts` and `test/security/fakes.ts` first and mirror their harness (fake `Env`, fake mailbox stub). The test asserts, using a call-recording stub:

```ts
// test/security/stateless-pipeline.test.ts — adapt imports/harness to fakes.ts
import { describe, expect, it } from "vitest";
import { runSecurityPipeline } from "../../workers/security";
// ... same fake-env setup as run-pipeline.test.ts, with a stub that records
// every method call in `calls: string[]`.

describe("runSecurityPipeline stateless mode", () => {
	it("produces a verdict without touching the MailboxDO", async () => {
		// harness: security enabled via domain-tier settings, recording stub
		const result = await runSecurityPipeline({
			env,
			mailboxId: "nobody@example.com",
			messageId: "m1",
			targetFolder: "INBOX",
			stateless: true,
			parsedEmail: {
				subject: "hello",
				from: { address: "sender@origin.test" },
				text: "plain body",
				headers: [],
			},
		});
		expect(result.verdict).not.toBeNull();
		expect(calls).toEqual([]); // NO DO method was invoked
	});

	it("stateful default still persists (regression guard)", async () => {
		await runSecurityPipeline({ /* same, without stateless */ });
		expect(calls).toContain("persistSecurityVerdict");
	});
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run test/security/stateless-pipeline.test.ts`
Expected: FAIL — `stateless` is not a known property (TS) / DO calls recorded.

- [ ] **Step 4: Implement the guards**

Add to `RunPipelineInput` (after `targetFolder`):

```ts
	/**
	 * Gateway-passthrough mode (issue #32): score without touching the
	 * MailboxDO. No DKIM-observation write, reputation = null, sender-graph
	 * detector skipped, no persistence. Settings resolution is unchanged —
	 * an unregistered mailboxId falls through to domain/org/default tiers.
	 */
	stateless?: boolean;
```

Guard the four sites (exact shape depends on the surrounding code read in Step 1):
1. `if (!input.stateless && auth.dkimObservations.length > 0) { ... }`
2. Reputation: `const rep = input.stateless ? null : (sender ? await stub.getSenderReputation(sender) : null);` — and only construct `stub` when `!input.stateless`.
3. Detector: skip the `detector.score(...)` call when `input.stateless` (contribution `{ score: 0, reason: undefined }`).
4. `if (!input.stateless) { await persistAll(...); }` (keep the existing call args verbatim).

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run test/security/stateless-pipeline.test.ts test/security/run-pipeline.test.ts`
Expected: PASS — both the new tests and the existing pipeline suite (no behavior change when `stateless` is absent).

- [ ] **Step 6: Typecheck and commit**

Run: `npm run typecheck` — expected clean.

```bash
git add workers/security/index.ts test/security/stateless-pipeline.test.ts
git commit -m "feat(gateway): stateless mode on runSecurityPipeline for passthrough scoring"
```

---

### Task 10: `GatewayInbound` kind + envelope capture + routing

**Files:**
- Modify: `workers/providers/types.ts` (union types, ~line 29-70)
- Modify: `workers/providers/cf-routing.ts` (`normalizeInbound` signature ~line 116; `resolveCatchall` ~line 224)
- Modify: `workers/app.ts` (`email()` handler, ~line 163-186)
- Test: `tests/lib/cf-routing-gateway.test.ts` (create)

**Interfaces:**
- Consumes: `resolveRelayPolicy` (Task 3), `getDomainSettings`.
- Produces (Tasks 11, 12 consume):

```ts
// workers/providers/types.ts
export interface GatewayInbound {
	kind: "gateway";
	rawEmail: ArrayBuffer;
	parsedEmail: Email;
	/** Authoritative envelope recipient (RCPT TO). */
	recipient: string;
	domain: string;
	/** SMTP envelope sender (MAIL FROM); "" for bounces. */
	envelopeFrom: string;
}
// MailboxInbound gains: envelopeFrom?: string;
// normalizeInbound returns MailboxInbound | CatchallInbound | GatewayInbound | null
```

- [ ] **Step 1: Write the failing test**

```ts
// tests/lib/cf-routing-gateway.test.ts
import { beforeEach, describe, expect, it } from "vitest";
import { normalizeInbound } from "../../workers/providers/cf-routing";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import type { Env } from "../../workers/types";

const MSG = [
	"Received: from mx.origin.test by cf.example.net for <ghost@example.com>; Mon, 6 Jul 2026 10:00:00 +0000",
	"From: sender@origin.test",
	"To: ghost@example.com",
	"Subject: hi",
	"",
	"body",
	"",
].join("\r\n");

function event(to: string) {
	const bytes = new TextEncoder().encode(MSG);
	return {
		raw: new Response(bytes).body as ReadableStream,
		rawSize: bytes.length,
		to,
		from: "sender@origin.test",
	};
}

/** BUCKET fake: no registered mailboxes; example.com has relay enabled. */
function fakeEnv(domainSettings: Record<string, unknown>): Env {
	return {
		EMAIL_ADDRESSES: undefined,
		DOMAINS: "example.com",
		BUCKET: {
			head: async () => null, // no mailbox JSON anywhere
			get: async (key: string) =>
				key === "domains/example.com.json"
					? { etag: "e1", json: async () => domainSettings }
					: null,
		},
	} as unknown as Env;
}

describe("normalizeInbound gateway routing", () => {
	beforeEach(() => clearDomainSettingsCache());

	it("unregistered recipient on a relay-enabled domain → GatewayInbound", async () => {
		const env = fakeEnv({
			relay: { enabled: true, target: { host: "smtp-relay.gmail.com" } },
		});
		const normalized = await normalizeInbound(event("ghost@example.com"), env);
		expect(normalized?.kind).toBe("gateway");
		if (normalized?.kind === "gateway") {
			expect(normalized.recipient).toBe("ghost@example.com");
			expect(normalized.domain).toBe("example.com");
			expect(normalized.envelopeFrom).toBe("sender@origin.test");
		}
	});

	it("relay disabled → falls through to catch-all/drop as before", async () => {
		const env = fakeEnv({ relay: { enabled: false, target: { host: "h" } } });
		const normalized = await normalizeInbound(event("ghost@example.com"), env);
		expect(normalized).toBeNull(); // no catchall_intel configured either
	});

	it("gateway wins precedence over catch-all when both are enabled", async () => {
		const env = fakeEnv({
			relay: { enabled: true, target: { host: "smtp-relay.gmail.com" } },
			catchall_intel: { enabled: true },
		});
		const normalized = await normalizeInbound(event("ghost@example.com"), env);
		expect(normalized?.kind).toBe("gateway");
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/lib/cf-routing-gateway.test.ts`
Expected: FAIL — `kind` is `undefined`/`null` (no gateway resolution exists).

- [ ] **Step 3: Implement**

**`workers/providers/types.ts`:** add `envelopeFrom?: string;` to `MailboxInbound` (doc: "SMTP envelope sender (MAIL FROM) when the inbound provider exposes it; used by gateway relay"). Add the `GatewayInbound` interface from the Interfaces block above, after `CatchallInbound`, with a doc-comment noting it's the issue-#32 passthrough for unregistered recipients on relay-enabled domains.

**`workers/providers/cf-routing.ts`:**
1. Widen the event type and capture the envelope sender:

```ts
export async function normalizeInbound(
	event: { raw: ReadableStream; rawSize: number; to?: string; from?: string },
	env: Env,
): Promise<MailboxInbound | CatchallInbound | GatewayInbound | null> {
	// ...existing body...
	const envelopeFrom = event.from?.trim() ?? "";
```

2. `mkMailbox` passes it through: `({ kind: "mailbox", rawEmail: ..., parsedEmail, mailboxId, envelopeFrom })`.
3. Rename `resolveCatchall` to `resolveUnregistered` and give gateway precedence (all 4 call sites at lines ~167, ~183, ~195, ~204 gain the `envelopeFrom` argument):

```ts
/**
 * Resolve an unregistered recipient: inline-gateway passthrough first
 * (issue #32 — relay policy presence implies the operator fronts this
 * domain), then catch-all intel, then drop.
 */
async function resolveUnregistered(
	recipients: string[],
	rawEmail: Uint8Array,
	parsedEmail: Awaited<ReturnType<PostalMime["parse"]>>,
	env: Env,
	envelopeFrom: string,
): Promise<CatchallInbound | GatewayInbound | null> {
	for (const addr of recipients) {
		const at = addr.lastIndexOf("@");
		if (at < 0) continue;
		const domain = addr.slice(at + 1).toLowerCase();
		let settings: DomainSettings;
		try {
			settings = await getDomainSettings(env, domain);
		} catch {
			continue;
		}
		if (resolveRelayPolicy(settings)) {
			return {
				kind: "gateway",
				rawEmail: rawEmail.buffer as ArrayBuffer,
				parsedEmail,
				recipient: addr,
				domain,
				envelopeFrom,
			};
		}
	}
	return resolveCatchall(recipients, rawEmail, parsedEmail, env);
}
```

Keep the existing `resolveCatchall` as-is (called as the fallback above); add imports for `resolveRelayPolicy`, `GatewayInbound`, and `DomainSettings`.

**`workers/app.ts`:** widen the `email()` event type with `from?: string` (comment: envelope MAIL FROM — the runtime `ForwardableEmailMessage` carries it even though the previous signature omitted it) and add the dispatch branch:

```ts
			if (normalized.kind === "catchall") {
				await receiveCatchall(normalized, env, ctx);
			} else if (normalized.kind === "gateway") {
				await receiveGatewayPassthrough(normalized, env, ctx);
			} else {
				await receiveEmail(normalized, env, ctx);
			}
```

Import `receiveGatewayPassthrough` from `./lib/gateway-receive` (its own module — keeps it Node-pool-testable without pulling the whole Hono app in, unlike `workers/index.ts`). **Task 12 implements it — to keep this task compiling, create `workers/lib/gateway-receive.ts` with the stub now:**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import type { Env } from "../types";
import type { GatewayInbound } from "../providers/types";

export async function receiveGatewayPassthrough(
	normalized: GatewayInbound,
	_env: Env,
	_ctx: ExecutionContext,
): Promise<void> {
	// Implemented in the next commit (Task 12): stateless scan → tag-cap → relay.
	console.error("receiveGatewayPassthrough not yet implemented; dropping", normalized.recipient);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/lib/cf-routing-gateway.test.ts && npm run typecheck`
Expected: PASS + clean typecheck.

- [ ] **Step 5: Commit**

```bash
git add workers/providers/types.ts workers/providers/cf-routing.ts workers/app.ts workers/lib/gateway-receive.ts tests/lib/cf-routing-gateway.test.ts
git commit -m "feat(gateway): GatewayInbound kind, envelope capture, gateway-first unregistered routing"
```

---

### Task 11: Relay branch in `receiveEmail` + `relay_status` column

**Files:**
- Modify: `workers/index.ts` (`receiveEmail`, insert after the pipeline try/catch ~line 1732, before the "Foreground notification fanout" comment at ~1734)
- Modify: `workers/durableObject/migrations.ts` (append mailbox migration after `25_consumed_jti` ~line 536)
- Modify: `workers/db/schema.ts` (`emails` table, after `deep_scan_status` ~line 44)
- Modify: `workers/durableObject/index.ts` (new `setRelayStatus` method — mirror the method that updates `deep_scan_status`; find it with `grep -n "deep_scan_status" workers/durableObject/index.ts`)
- Test: extend an existing `receiveEmail` harness if one exists (`grep -rln "receiveEmail" test tests`); otherwise the branch's logic is fully covered by Task 8's unit tests and the DO method by `test/durableObject/`.

**Interfaces:**
- Consumes: `relayAfterVerdict` (Task 8), `resolveRelayPolicy` (Task 3), `domainFromMailboxId`/`getDomainSettings` (`workers/lib/domain-settings.ts:48,68`), `MailboxInbound.envelopeFrom` (Task 10).
- Produces: `emails.relay_status` (`"relayed" | "held" | "failed"` or NULL); `MailboxDO.setRelayStatus(emailId, status)`.

- [ ] **Step 1: Migration + schema + DO method**

Append to the mailbox migrations list in `workers/durableObject/migrations.ts`:

```ts
	{
		name: "26_relay_status",
		sql: `ALTER TABLE emails ADD COLUMN relay_status TEXT;`,
	},
```

Add to the `emails` table in `workers/db/schema.ts` after `deep_scan_status`:

```ts
	// Inline-gateway relay outcome (issue #32): "relayed" | "held" |
	// "failed"; NULL when the domain has no relay policy (or ingest
	// predates the gateway feature).
	relay_status: text("relay_status"),
```

Add to `MailboxDO` in `workers/durableObject/index.ts`, next to the `deep_scan_status` updater and in its exact style:

```ts
	async setRelayStatus(emailId: string, status: "relayed" | "held" | "failed"): Promise<void> {
		this.sql.exec(`UPDATE emails SET relay_status = ? WHERE id = ?`, status, emailId);
	}
```

(If the neighboring updater goes through drizzle instead of `this.sql.exec`, mirror that instead.)

- [ ] **Step 2: Write the relay branch**

In `receiveEmail`, after the pipeline try/catch closes (~line 1732) and before the notification-fanout comment (~line 1734):

```ts
	// Inline gateway relay (issue #32). When this mailbox's domain has an
	// enabled relay policy, the verdict decides whether the message ALSO
	// relays to the backend MX. Storage above is untouched — relay is
	// additive for registered mailboxes. Transient SMTP failures throw out
	// of receiveEmail so CF Email Routing defers and the origin retries
	// (may re-store a duplicate; accepted, see spec); permanent failures
	// keep the mirror copy, alert, and mark relay_status=failed.
	const relayDomain = domainFromMailboxId(mailboxId);
	const relayPolicy = relayDomain
		? resolveRelayPolicy(await getDomainSettings(env, relayDomain))
		: null;
	if (relayPolicy) {
		const outcome = await relayAfterVerdict({
			env,
			ctx,
			raw: new Uint8Array(normalized.rawEmail),
			verdict: securityVerdict,
			policy: relayPolicy,
			envelopeFrom: normalized.envelopeFrom ?? "",
			rcptTo: mailboxId,
		});
		const status =
			outcome === "relayed" ? "relayed" : outcome === "failed_permanent" ? "failed" : outcome === "held" ? "held" : null;
		if (status) {
			await stub
				.setRelayStatus(messageId, status)
				.catch((e) => console.error("setRelayStatus failed:", (e as Error).message));
		}
	}
```

Add imports at the top of `workers/index.ts`: `resolveRelayPolicy` from `./lib/relay-policy`, `relayAfterVerdict` from `./lib/gateway-relay`, and `domainFromMailboxId`/`getDomainSettings` from `./lib/domain-settings` (check which are already imported first — `getDomainSettings` likely is).

- [ ] **Step 3: Verify**

Run: `npm run typecheck && npm test`
Expected: clean typecheck; full suite passes (the branch is inert for domains without relay policy — every existing test).

- [ ] **Step 4: Commit**

```bash
git add workers/index.ts workers/durableObject/migrations.ts workers/db/schema.ts workers/durableObject/index.ts
git commit -m "feat(gateway): relay branch in receiveEmail + relay_status tracking"
```

---

### Task 12: `receiveGatewayPassthrough` — stateless scan → tag-cap → relay

**Files:**
- Modify: `workers/lib/gateway-receive.ts` (replace Task 10's stub with the real implementation)
- Test: `tests/lib/gateway-receive.test.ts` (create)

**Interfaces:**
- Consumes: `GatewayInbound` (Task 10), `runSecurityPipeline` + `stateless` (Task 9), `resolveRelayPolicy` (Task 3), `relayAfterVerdict` (Task 8), `Folders` (`shared/folders.ts`).
- Produces: `receiveGatewayPassthrough(normalized: GatewayInbound, env: Env, ctx: ExecutionContext): Promise<void>` — already wired into `workers/app.ts` by Task 10.

**Cap-vs-mapping interplay (do not "fix" this):** the tag-cap happens HERE, before the action mapping — quarantine/block verdicts become `tag` exactly like `learning_mode` does (`workers/security/index.ts:313`), so passthrough mail is never dropped on score alone under the default policy. `behaviorFor`'s `passthrough` option only degrades `hold` → `relay`; it is not a second cap.

- [ ] **Step 1: Write the failing test**

```ts
// tests/lib/gateway-receive.test.ts
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../workers/lib/gateway-relay", () => ({
	relayAfterVerdict: vi.fn(async () => "relayed"),
}));
vi.mock("../../workers/security", () => ({
	runSecurityPipeline: vi.fn(),
}));

import { relayAfterVerdict } from "../../workers/lib/gateway-relay";
import { runSecurityPipeline } from "../../workers/security";
import { receiveGatewayPassthrough } from "../../workers/lib/gateway-receive";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import type { GatewayInbound } from "../../workers/providers/types";
import type { Env } from "../../workers/types";

function fakeEnv(domainSettings: Record<string, unknown>): Env {
	return {
		BUCKET: {
			get: async (key: string) =>
				key === "domains/example.com.json"
					? { etag: "e1", json: async () => domainSettings }
					: null,
		},
	} as unknown as Env;
}

const inbound: GatewayInbound = {
	kind: "gateway",
	rawEmail: new TextEncoder().encode("Subject: t\r\n\r\nbody\r\n").buffer as ArrayBuffer,
	parsedEmail: { subject: "t", from: { address: "s@o.test" }, headers: [] } as never,
	recipient: "ghost@example.com",
	domain: "example.com",
	envelopeFrom: "s@o.test",
};

const ctx = { waitUntil: () => {} } as unknown as ExecutionContext;

const relayEnabled = { relay: { enabled: true, target: { host: "smtp-relay.gmail.com" } } };

function pipelineVerdict(action: string) {
	vi.mocked(runSecurityPipeline).mockResolvedValueOnce({
		verdict: { action, score: 70, confidence: 0.9, explanation: "", auth: { spf: "fail", dkim: "fail", dmarc: "fail", dkimObservations: [] }, classification: {}, signals: [] },
		skipped: false,
		stageTrace: [],
	} as never);
}

describe("receiveGatewayPassthrough", () => {
	beforeEach(() => {
		clearDomainSettingsCache();
		vi.mocked(relayAfterVerdict).mockClear();
		vi.mocked(runSecurityPipeline).mockReset();
	});

	it("runs the pipeline stateless and relays with passthrough=true", async () => {
		pipelineVerdict("allow");
		await receiveGatewayPassthrough(inbound, fakeEnv(relayEnabled), ctx);
		expect(runSecurityPipeline).toHaveBeenCalledWith(
			expect.objectContaining({ stateless: true, mailboxId: "ghost@example.com" }),
		);
		expect(relayAfterVerdict).toHaveBeenCalledWith(
			expect.objectContaining({
				passthrough: true,
				rcptTo: "ghost@example.com",
				envelopeFrom: "s@o.test",
				verdict: expect.objectContaining({ action: "allow" }),
			}),
		);
	});

	it("caps quarantine and block verdicts at tag before relaying", async () => {
		pipelineVerdict("quarantine");
		await receiveGatewayPassthrough(inbound, fakeEnv(relayEnabled), ctx);
		expect(relayAfterVerdict).toHaveBeenCalledWith(
			expect.objectContaining({ verdict: expect.objectContaining({ action: "tag" }) }),
		);
	});

	it("pipeline failure relays unscanned (verdict null) rather than eating mail", async () => {
		vi.mocked(runSecurityPipeline).mockRejectedValueOnce(new Error("boom"));
		await receiveGatewayPassthrough(inbound, fakeEnv(relayEnabled), ctx);
		expect(relayAfterVerdict).toHaveBeenCalledWith(expect.objectContaining({ verdict: null }));
	});

	it("drops silently when the relay policy has vanished", async () => {
		await receiveGatewayPassthrough(inbound, fakeEnv({}), ctx);
		expect(relayAfterVerdict).not.toHaveBeenCalled();
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/lib/gateway-receive.test.ts`
Expected: FAIL — the stub drops everything, `relayAfterVerdict` never called.

- [ ] **Step 3: Implement (replace the stub body in `workers/lib/gateway-receive.ts`)**

```ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Gateway passthrough for unregistered recipients (issue #32).
 *
 * A gateway fronting a whole domain receives mail for backend users with
 * no PhishSOC mailbox. Score with domain-tier settings (stateless — no
 * MailboxDO is created), cap quarantine/block at `tag` (nothing to hold
 * into; mirrors learning_mode's cap), and relay. Nothing is stored.
 *
 * Failure semantics differ from the registered path: there is no mirror
 * copy, so PERMANENT relay failures also throw — bouncing at the origin
 * is the only honest outcome (see relayAfterVerdict's passthrough flag).
 */

import type { Env } from "../types";
import type { GatewayInbound } from "../providers/types";
import type { FinalVerdict } from "../security/verdict";
import { runSecurityPipeline } from "../security";
import { getDomainSettings } from "./domain-settings";
import { resolveRelayPolicy } from "./relay-policy";
import { relayAfterVerdict } from "./gateway-relay";
import { Folders } from "../../shared/folders";

export async function receiveGatewayPassthrough(
	normalized: GatewayInbound,
	env: Env,
	ctx: ExecutionContext,
): Promise<void> {
	const { parsedEmail, recipient, domain, envelopeFrom } = normalized;
	const policy = resolveRelayPolicy(await getDomainSettings(env, domain));
	if (!policy) {
		// Policy changed between normalizeInbound and here — nothing to do.
		console.log("gateway passthrough: no relay policy for", domain, "- dropping");
		return;
	}

	let verdict: FinalVerdict | null = null;
	try {
		const result = await runSecurityPipeline({
			env,
			// Settings resolution only: an unregistered id falls through
			// mailbox(absent) → domain → org tiers. stateless=true means no
			// MailboxDO is created or written for this address.
			mailboxId: recipient,
			messageId: crypto.randomUUID(),
			targetFolder: Folders.INBOX,
			stateless: true,
			parsedEmail: {
				subject: parsedEmail.subject,
				from: parsedEmail.from,
				html: parsedEmail.html,
				text: parsedEmail.text,
				headers: parsedEmail.headers,
				attachments: parsedEmail.attachments?.map((a) => ({
					filename: a.filename ?? null,
					mimeType: a.mimeType ?? null,
				})),
			},
		});
		verdict = result.verdict;
	} catch (e) {
		// Fail open: a gateway must never eat mail because scanning broke.
		console.error("gateway passthrough: pipeline failed; relaying unscanned:", (e as Error).message);
	}

	// Tag-cap: no mailbox to quarantine into. Same cap learning_mode applies.
	if (verdict && (verdict.action === "quarantine" || verdict.action === "block")) {
		verdict = { ...verdict, action: "tag" };
	}

	await relayAfterVerdict({
		env,
		ctx,
		raw: new Uint8Array(normalized.rawEmail),
		verdict,
		policy,
		envelopeFrom,
		rcptTo: recipient,
		passthrough: true,
	});
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/lib/gateway-receive.test.ts && npm run typecheck`
Expected: PASS (4 tests) + clean typecheck.

- [ ] **Step 5: Commit**

```bash
git add workers/lib/gateway-receive.ts tests/lib/gateway-receive.test.ts
git commit -m "feat(gateway): tag-capped stateless passthrough for unregistered recipients"
```

---

### Task 13: Settings UI — relay card (domain) + ARC fields (org)

**Files:**
- Modify: `app/routes/domain-settings.tsx` (402 lines; state block ~line 69-79, `handleSave` ~line 131, cards in the JSX below)
- Modify: `app/routes/org-settings.tsx`
- Test: extend `tests/frontend/` ONLY if a domain-settings test already exists (`ls tests/frontend | grep -i domain`); otherwise verify by running the app.

**Interfaces:**
- Consumes: `RelaySettings` type (Task 1), org `gateway` block (Task 2). Both pages already GET/PUT the full settings object through endpoints that run `stripDefaultEqual` (`workers/index.ts:823-838` for domains) — no new endpoints.

**Read both route files first** and mirror their exact card/input/toggle components and save-merge style. The code below shows the state, load, save-merge, and card content to add; adapt component names to what the file actually uses (this file's conventions win over this plan's JSX).

- [ ] **Step 1: Domain relay card**

State (next to the existing `useState` block):

```tsx
const [relayEnabled, setRelayEnabled] = useState(false);
const [relayHost, setRelayHost] = useState("");
const [relayPort, setRelayPort] = useState("587");
const [relayImplicitTls, setRelayImplicitTls] = useState(false);
const [relayCredentialsSecret, setRelayCredentialsSecret] = useState("");
const [relayActionQuarantine, setRelayActionQuarantine] = useState<"relay" | "hold" | "drop">("hold");
```

Load (where the fetched settings populate state): map `settings.relay?.enabled ?? false`, `settings.relay?.target?.host ?? ""`, `String(settings.relay?.target?.port ?? 587)`, `settings.relay?.target?.implicitTls ?? false`, `settings.relay?.credentialsSecret ?? ""`, `settings.relay?.actions?.quarantine ?? "hold"`.

Save-merge (inside `handleSave`'s settings object):

```tsx
relay: relayEnabled
	? {
			enabled: true,
			target: {
				host: relayHost.trim(),
				port: Number.parseInt(relayPort, 10) || 587,
				implicitTls: relayImplicitTls,
			},
			...(relayCredentialsSecret.trim() ? { credentialsSecret: relayCredentialsSecret.trim() } : {}),
			...(relayActionQuarantine !== "hold" ? { actions: { quarantine: relayActionQuarantine } } : {}),
		}
	: { enabled: false },
```

(`stripDefaultEqual` drops the `{ enabled: false }` blob server-side — Task 1's strip case.)

Card content (adapt to the page's card component; copy an existing card's wrapper):
- Toggle: "Inline gateway relay" — description: "Relay scored inbound mail for this domain to a backend over SMTP submission (port 587/465 — port 25 is not possible from Workers)."
- Text input "Relay target host" (placeholder `smtp-relay.gmail.com`), text input "Port" (placeholder `587`), toggle "Implicit TLS (port 465)".
- Text input "Credentials secret name" (placeholder `RELAY_CREDS_EXAMPLE_COM`) with help text: `Worker Secret containing {"user":"...","pass":"..."} JSON — set with wrangler secret put.`
- Select "Quarantine verdict" with options `hold (default — keep in PhishSOC quarantine)` / `relay (deliver tagged; backend rules quarantine)` / `drop`. Only quarantine is surfaced in v1 UI; allow/tag/block mappings stay JSON-editable.

- [ ] **Step 2: Org ARC fields**

In `app/routes/org-settings.tsx`, mirror the page's existing field pattern: two text inputs, "ARC sealer domain" (`gateway.arcSealerDomain`, placeholder `gw.example.com`) and "ARC selector" (`gateway.arcSelector`, placeholder `arc1`), with help text: "Publish the matching public key at `<selector>._domainkey.<sealer domain>` and set the ARC_SEAL_PRIVATE_KEY secret — see docs/gateway-mode.md." Save-merge: `gateway: (arcSealerDomain.trim() || arcSelector.trim()) ? { ...(arcSealerDomain.trim() ? { arcSealerDomain: arcSealerDomain.trim() } : {}), ...(arcSelector.trim() ? { arcSelector: arcSelector.trim() } : {}) } : {}` (the empty object is stripped server-side per Task 2).

- [ ] **Step 3: Verify**

Run: `npm run typecheck && npm test` — expected clean (plus any extended frontend test).
Run: `npm run dev`, open the domain settings page, toggle the relay card on, save, reload — values persist; save with the toggle off — `domains/<domain>.json` in the local R2 sim carries no `relay` key.

- [ ] **Step 4: Commit**

```bash
git add app/routes/domain-settings.tsx app/routes/org-settings.tsx
git commit -m "feat(gateway): relay policy card on domain settings, ARC sealer fields on org settings"
```

---

### Task 14: Operator docs

**Files:**
- Create: `docs/gateway-mode.md`

- [ ] **Step 1: Write the doc**

Full content (trim nothing):

```markdown
# Inline Gateway Mode (v1 — inbound only)

Point a domain's MX at Cloudflare Email Routing; PhishSOC scores every
inbound message and relays it to your real mail backend (Google Workspace,
M365, or any SMTP-submission endpoint) with the verdict attached. Mail the
policy quarantines never reaches the backend.

**v1 scope:** inbound only, Cloudflare-only deployment (the issue #32
"Option A"). The external SMTP front-end (Option B), per-domain DKIM
signing, and outbound scanning are tracked in follow-up issues.

## How a message flows

1. Internet MX → Cloudflare Email Routing → the Worker's `email()` handler.
2. The security pipeline scores the message (same pipeline as standalone mode).
3. The verdict maps through the domain's relay policy:
   `allow → relay`, `tag → relay`, `quarantine → hold`, `block → drop` (defaults; all four configurable).
4. Relayed mail gains `X-PhishPilot-Verdict` / `X-PhishPilot-Score` headers
   and an ARC seal, then goes out over SMTP submission to your backend.
5. Held mail stays in the PhishSOC quarantine UI; registered mailboxes keep
   a full mirror copy of everything regardless.

Recipients with no registered PhishSOC mailbox are scored with domain-tier
settings, capped at `tag` (there is no mailbox to quarantine into), relayed,
and NOT stored.

## Limitations (read first)

- **Workers cannot use port 25.** The relay target must accept SMTP
  *submission*: port 587 (STARTTLS) or 465 (implicit TLS) with credentials.
  For Workspace use `smtp-relay.gmail.com:587`; for M365 use SMTP AUTH
  submission. A bare-MX backend needs the (follow-up) external front-end.
- **ARC sealing only when first in chain.** Messages already carrying ARC
  headers relay unsealed (their origin DKIM signature still validates —
  we only prepend headers, never modify existing ones).
- **Scan/seal failures fail open**: the gateway relays unscanned/unsealed
  and fires a security alert rather than eating mail.
- **Transient relay failures defer at the origin** (the Worker rethrows so
  the sending MTA retries). Permanent failures (bad credentials) keep the
  mirror copy, mark `relay_status=failed`, and alert.

## Setup

### 1. Generate the ARC sealing key (once per deployment)

    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out arc-private.pem
    openssl pkey -in arc-private.pem -pubout -outform DER | openssl base64 -A

Publish the public key as a DNS TXT record (pick a selector, e.g. `arc1`,
and a sealer domain you control, e.g. your PhishSOC host's domain):

    arc1._domainkey.gw.example.com  TXT  "v=DKIM1; k=rsa; p=<base64 from above>"

Store the private key and configure the sealer identity:

    wrangler secret put ARC_SEAL_PRIVATE_KEY < arc-private.pem

Then set **ARC sealer domain** and **ARC selector** on the org settings page.

### 2. Create backend relay credentials

**Google Workspace** (Admin console → Apps → Google Workspace → Gmail →
Routing → SMTP relay service): add a relay setting that accepts
authenticated submission, and create an app password (or use a dedicated
relay user). Also set **Inbound gateway** (Gmail → Spam, phishing, malware)
so Gmail trusts the gateway's Received chain and reads the ARC seal.

Store the credentials as a Worker Secret named per domain:

    wrangler secret put RELAY_CREDS_EXAMPLE_COM
    # paste: {"user":"relay@example.com","pass":"app-password"}

### 3. Configure the domain relay policy

Domain settings page → **Inline gateway relay**: enable, set target host
`smtp-relay.gmail.com`, port `587`, and the credentials secret name from
step 2. The quarantine mapping defaults to `hold` (mail stays in PhishSOC);
switch it to `relay` if you prefer backend-native quarantine routing — the
verdict header still travels with the message.

### 4. Cut over MX

Point the domain's MX records at Cloudflare Email Routing (per the standard
PhishSOC setup). Verify with a test message from an external mailbox:

- it arrives in the Workspace inbox,
- "Show original" in Gmail shows `arc=pass` and the `X-PhishPilot-*` headers,
- a message that scores quarantine appears in PhishSOC quarantine and never
  reaches Workspace,
- mail to an address with no PhishSOC mailbox still arrives (tagged when
  suspicious).

## Rollback

Disable the relay toggle (or delete the `relay` block from
`domains/<domain>.json`) — the domain instantly reverts to standalone
behavior. No code deploy involved.
```

- [ ] **Step 2: Commit**

```bash
git add docs/gateway-mode.md
git commit -m "docs(gateway): operator guide for inline gateway mode v1"
```

---

### Task 15: Full gates, follow-up issues, PR

- [ ] **Step 1: Run every gate**

```bash
npm test && npm run typecheck && npm run build
```

Expected: all suites pass (report exact counts), typecheck clean, build clean. Fix anything that fails before proceeding.

- [ ] **Step 2: File the follow-up issues** (spec "Out of scope" section; use the `/issue` skill conventions — task upfront, `path:line` pointers, acceptance criteria; check for duplicates first):

1. Option B: HTTP front-end endpoint (HMAC-authed, `workers/routes/yaramail-callback.ts:25` pattern) + Postfix/Haraka recipe docs.
2. Per-domain DKIM keys + outbound flow (backend → gateway → internet).
3. Quarantine release / recipient digest UX.
4. Catch-all-intel × gateway-passthrough interplay (`workers/providers/cf-routing.ts` `resolveUnregistered` — gateway currently wins; probe intel is lost for gateway domains).
5. ARC chain validation / sealing atop existing chains (i>1) (`workers/lib/arc-seal.ts` `hasExistingArcChain`).
6. Message-ID dedup on origin-retry re-delivery (`workers/index.ts` `receiveEmail` — duplicate storage when a transient relay failure triggers an origin retry).
7. M365 live validation of the relay path (config is already provider-agnostic).
8. Surface `relay_status` in the email-detail UI (column ships in this PR; only the API JSON carries it so far).

- [ ] **Step 3: Open the PR**

Note for the PR body: no `wrangler.jsonc` changes ship in this branch — the feature is inert until an operator sets a relay policy + secrets, so the auto-deploy on merge is a behavioral no-op. Do NOT enable auto-merge before every task above is pushed.

```bash
git push -u origin HEAD
gh pr create --title "feat(gateway): inline gateway mode v1 — per-domain relay, ARC seal, tag-capped passthrough" --body "$(cat <<'EOF'
Implements the v1 (Foundations + Option A) slice of #32 per
docs/superpowers/specs/2026-07-06-inline-gateway-design.md:

- `relay` policy block on the domain settings tier (R2 + stripDefaultEqual, not a new table)
- ARC sealing (RFC 8617, i=1) on `crypto.subtle`, cross-verified by mailauth in tests
- Minimal SMTP submission client over cloudflare:sockets (587 STARTTLS / 465; port 25 is platform-blocked)
- Verdict→action relay branch in receiveEmail (quarantine holds by default; transient failures defer at origin)
- Tag-capped stateless passthrough for unregistered recipients
- Relay card + ARC fields in settings UI; operator guide in docs/gateway-mode.md

Refs #32 (Option B, per-domain DKIM, and outbound are follow-up issues — see PR comments).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

After the PR is open: comment on #32 linking the PR and the filed follow-up issues, and ask whether to close #32 as decomposed (do not close it unilaterally).

- [ ] **Step 4: Manual acceptance (operator, post-deploy)** — from the spec, requires the Workspace tenant:

1. Test domain MX at Cloudflare; relay policy → `smtp-relay.gmail.com:587` + credentials secret; ARC key in DNS.
2. External inbound mail arrives in the Workspace inbox with `arc=pass` (Gmail "Show original") and `X-PhishPilot-*` headers.
3. A quarantine-scoring message stays in PhishSOC quarantine, never reaches Workspace.
4. Mail to an unregistered address relays tagged; nothing stored.
5. Disabling the relay policy reverts the domain with no code change.

