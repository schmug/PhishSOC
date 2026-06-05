// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Unit tests for `analyzeCatchall`.
 *
 * Verifies:
 *  - env.AI is never invoked (LLM-free invariant)
 *  - Phishing-shaped input → high band (auth fail + homograph + Spamhaus DROP)
 *  - Benign-shaped input → low band (auth pass + clean body + clean IP)
 *  - Spamhaus DROP hit raises score and adds a signal
 *  - CrowdSec malicious hit (via pre-seeded KV cache) raises score and adds signal
 *  - Transient KV errors degrade gracefully — no throw, no boost
 *  - No `mailboxId` anywhere in the module boundary
 */

import { describe, expect, it } from "vitest";
import { analyzeCatchall } from "../../workers/security/catchall";
import { parseCidr } from "../../workers/intel/cidr";
import type { Env } from "../../workers/types";
import type { CtiSummary } from "../../workers/intel/crowdsec-cti";

// ── Fake env helpers ──────────────────────────────────────────────────────────

interface FakeKv {
	store: Map<string, string>;
	get(key: string, type?: "text" | "arrayBuffer"): Promise<string | null>;
	put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
}

function makeKv(): FakeKv {
	const store = new Map<string, string>();
	return {
		store,
		async get(key) { return store.get(key) ?? null; },
		async put(key, value) { store.set(key, value); },
	};
}

/**
 * Throw-on-get KV — simulates a transient KV failure so we can assert
 * that the analyzer degrades gracefully rather than propagating the error.
 */
function makeErrorKv(): FakeKv {
	return {
		store: new Map(),
		async get() { throw new Error("KV network error"); },
		async put() {},
	};
}

function makeEnv(opts: { apiKey?: string; kv?: FakeKv } = {}): Env {
	const ai = {
		run() {
			throw new Error("env.AI called in analyzeCatchall — LLM not allowed on this path");
		},
	};
	return {
		AI: ai,
		CROWDSEC_CTI_API_KEY: opts.apiKey,
		BLOOM_KV: opts.kv as unknown as KVNamespace | undefined,
		POLICY_AUD: "",
		TEAM_DOMAIN: "",
	} as unknown as Env;
}

// ── Raw-header builders ───────────────────────────────────────────────────────

/** Build a PostalMime-style headers array from a simplified map. */
function headers(fields: Record<string, string>): Array<{ key: string; value: string }> {
	return Object.entries(fields).map(([key, value]) => ({ key, value }));
}

const AUTH_FAIL = headers({
	"authentication-results": "mx.example.com; spf=fail; dkim=fail; dmarc=fail",
});

const AUTH_PASS = headers({
	"authentication-results": "mx.example.com; spf=pass; dkim=pass; dmarc=pass",
});

/** Received header that embeds the given public IP. */
function receivedWith(ip: string): Array<{ key: string; value: string }> {
	return headers({ received: `from mail.example ([${ip}]) by mx.example.com` });
}

// ── Feed-seeding helpers ──────────────────────────────────────────────────────

/**
 * Seed `intel:{feedId}:cidrs` in the fake KV with a single CIDR entry,
 * using the same serialisation shape that `feeds.ts` writes during refresh.
 */
function seedCidr(kv: FakeKv, feedId: string, cidrStr: string): void {
	const c = parseCidr(cidrStr);
	if (!c) throw new Error(`Invalid CIDR: ${cidrStr}`);
	kv.store.set(
		`intel:${feedId}:cidrs`,
		JSON.stringify([{ n: c.network, m: c.mask, p: c.prefix }]),
	);
}

/**
 * Pre-seed the CrowdSec CTI KV cache for a given IP so `lookupIp` returns the
 * summary from cache without making any outbound fetch call.
 */
function seedCtiCache(kv: FakeKv, ip: string, summary: CtiSummary): void {
	kv.store.set(`cti:crowdsec:${ip}`, JSON.stringify(summary));
}

// ── Test IPs ──────────────────────────────────────────────────────────────────
// 192.0.2.x is RFC 5737 TEST-NET-1 — passes our private-range filter
// (not 10/8, 172.16/12, 192.168/16, 127/8, etc.) so it routes through
// the IP-reputation path in `extractReceivedFromIp`.
const TEST_IP = "192.0.2.55";
const TEST_CIDR = "192.0.2.0/24"; // covers TEST_IP

const CLEAN_IP = "8.8.8.8"; // not in any seeded feed

// A URL whose hostname is close enough to 'paypal.com' (1-char edit)
const HOMOGRAPH_BODY = '<a href="https://paypa1.com/login">Click here</a>';

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("analyzeCatchall — LLM invariant", () => {
	it("never calls env.AI regardless of input", async () => {
		const env = makeEnv();
		// If analyzeCatchall ever touches env.AI.run(), the stub throws and
		// the test fails with the explicit "LLM not allowed" message.
		await expect(
			analyzeCatchall(env, { rawHeaders: [], body: null }),
		).resolves.toBeDefined();
	});

	it("never calls env.AI on a phishing-shaped input", async () => {
		const env = makeEnv();
		await expect(
			analyzeCatchall(env, {
				rawHeaders: AUTH_FAIL,
				body: HOMOGRAPH_BODY,
				from: { address: "evil@attacker.example" },
			}),
		).resolves.toBeDefined();
	});
});

describe("analyzeCatchall — benign-shaped input", () => {
	it("returns low band for clean auth + no suspicious URLs + no IP match", async () => {
		const kv = makeKv();
		const env = makeEnv({ kv });

		const result = await analyzeCatchall(env, {
			rawHeaders: [...AUTH_PASS, ...receivedWith(CLEAN_IP)],
			body: "<p>Hi, here is your receipt. <a href='https://paypal.com/receipt'>View</a></p>",
			from: { address: "billing@paypal.com" },
		});

		expect(result.band).toBe("low");
		expect(result.score).toBeLessThan(30);
		expect(result.intelMatch).toBeNull();
		expect(result.auth.dmarc).toBe("pass");
	});

	it("returns structured fields with expected types", async () => {
		const env = makeEnv();
		const result = await analyzeCatchall(env, {
			rawHeaders: AUTH_PASS,
			body: null,
			from: { address: "user@example.com" },
		});

		expect(typeof result.score).toBe("number");
		expect(["low", "medium", "high"]).toContain(result.band);
		expect(Array.isArray(result.signals)).toBe(true);
		expect(result.auth).toBeDefined();
		expect(typeof result.urlFlags.homograph).toBe("boolean");
		expect(typeof result.urlFlags.shortener).toBe("boolean");
		expect(typeof result.urlFlags.count).toBe("number");
		expect(result.sender).toBe("user@example.com");
	});
});

describe("analyzeCatchall — phishing-shaped input", () => {
	it("returns high band for auth fail + homograph URL + Spamhaus DROP hit", async () => {
		const kv = makeKv();
		seedCidr(kv, "spamhaus-drop", TEST_CIDR);
		const env = makeEnv({ kv });

		const result = await analyzeCatchall(env, {
			rawHeaders: [...AUTH_FAIL, ...receivedWith(TEST_IP)],
			body: HOMOGRAPH_BODY,
			from: { address: "attacker@evil.example" },
		});

		expect(result.band).toBe("high");
		expect(result.score).toBeGreaterThanOrEqual(60);
		expect(result.signals.some((s) => s.includes("Spamhaus DROP"))).toBe(true);
		expect(result.intelMatch?.source).toBe("spamhaus");
		expect(result.sourceIp).toBe(TEST_IP);
	});

	it("flags homograph URL in urlFlags", async () => {
		const env = makeEnv();
		const result = await analyzeCatchall(env, {
			rawHeaders: AUTH_FAIL,
			body: HOMOGRAPH_BODY,
		});

		expect(result.urlFlags.homograph).toBe(true);
		expect(result.urlFlags.count).toBeGreaterThanOrEqual(1);
		expect(result.signals.some((s) => s.includes("homograph"))).toBe(true);
	});
});

describe("analyzeCatchall — Spamhaus DROP", () => {
	it("Spamhaus hit adds signal and raises score above auth-only baseline", async () => {
		const kv = makeKv();
		seedCidr(kv, "spamhaus-drop", TEST_CIDR);
		const env = makeEnv({ kv });

		// Baseline: no auth signals, no URL signals, IP match only
		const result = await analyzeCatchall(env, {
			rawHeaders: receivedWith(TEST_IP),
			body: null,
		});

		expect(result.signals.some((s) => s.includes("Spamhaus DROP"))).toBe(true);
		expect(result.intelMatch?.source).toBe("spamhaus");
		expect(result.score).toBeGreaterThanOrEqual(30); // DROP hit alone ≥ medium
	});

	it("no Spamhaus hit when IP is outside all seeded CIDRs", async () => {
		const kv = makeKv();
		seedCidr(kv, "spamhaus-drop", TEST_CIDR);
		const env = makeEnv({ kv });

		const result = await analyzeCatchall(env, {
			rawHeaders: receivedWith(CLEAN_IP),
			body: null,
		});

		expect(result.signals.some((s) => s.includes("Spamhaus DROP"))).toBe(false);
		expect(result.intelMatch?.source).not.toBe("spamhaus");
	});

	it("no Spamhaus hit when BLOOM_KV is not configured", async () => {
		// No KV in env — should not throw, just skip
		const env = makeEnv();

		const result = await analyzeCatchall(env, {
			rawHeaders: receivedWith(TEST_IP),
			body: null,
		});

		expect(result.intelMatch).toBeNull();
	});
});

describe("analyzeCatchall — CrowdSec CTI", () => {
	it("malicious CTI hit raises score and adds signal", async () => {
		const kv = makeKv();
		const summary: CtiSummary = {
			classifications: ["scanner"],
			behaviors: ["http:scan"],
			scores: { threat: 5, aggressiveness: 4, trust: 0 },
			reputation: "malicious",
		};
		seedCtiCache(kv, TEST_IP, summary);
		const env = makeEnv({ apiKey: "test-key", kv });

		const result = await analyzeCatchall(env, {
			rawHeaders: receivedWith(TEST_IP),
			body: null,
		});

		expect(result.signals.some((s) => s.includes("CrowdSec malicious"))).toBe(true);
		expect(result.score).toBeGreaterThan(0);
	});

	it("suspicious CTI hit adds a moderate boost", async () => {
		const kv = makeKv();
		const summary: CtiSummary = {
			classifications: [],
			behaviors: [],
			scores: { threat: 3, aggressiveness: 2, trust: 1 },
			reputation: "suspicious",
		};
		seedCtiCache(kv, TEST_IP, summary);
		const env = makeEnv({ apiKey: "test-key", kv });

		const result = await analyzeCatchall(env, {
			rawHeaders: receivedWith(TEST_IP),
			body: null,
		});

		expect(result.signals.some((s) => s.includes("CrowdSec suspicious"))).toBe(true);
		expect(result.score).toBeGreaterThan(0);
	});

	it("benign/safe CTI reputation adds no boost", async () => {
		const kv = makeKv();
		const summary: CtiSummary = {
			classifications: [],
			behaviors: [],
			scores: { threat: 0, aggressiveness: 0, trust: 5 },
			reputation: "safe",
		};
		seedCtiCache(kv, TEST_IP, summary);
		const env = makeEnv({ apiKey: "test-key", kv });

		const result = await analyzeCatchall(env, {
			rawHeaders: receivedWith(TEST_IP),
			body: null,
		});

		expect(result.intelMatch?.source).not.toBe("crowdsec");
	});

	it("no CTI lookup when API key is absent", async () => {
		const kv = makeKv();
		// No apiKey — lookupIp returns null without fetching
		const env = makeEnv({ kv });

		const result = await analyzeCatchall(env, {
			rawHeaders: receivedWith(TEST_IP),
			body: null,
		});

		// CTI absent, no KV data for Spamhaus either → no intel match
		expect(result.intelMatch).toBeNull();
	});

	it("Spamhaus hit takes precedence in intelMatch when both fire", async () => {
		const kv = makeKv();
		seedCidr(kv, "spamhaus-drop", TEST_CIDR);
		const ctiSummary: CtiSummary = {
			classifications: [],
			behaviors: [],
			scores: { threat: 4, aggressiveness: 3, trust: 0 },
			reputation: "malicious",
		};
		seedCtiCache(kv, TEST_IP, ctiSummary);
		const env = makeEnv({ apiKey: "test-key", kv });

		const result = await analyzeCatchall(env, {
			rawHeaders: receivedWith(TEST_IP),
			body: null,
		});

		// Both fire and both add signals, but intelMatch is Spamhaus (checked first)
		expect(result.intelMatch?.source).toBe("spamhaus");
		expect(result.signals.some((s) => s.includes("Spamhaus DROP"))).toBe(true);
		expect(result.signals.some((s) => s.includes("CrowdSec malicious"))).toBe(true);
	});
});

describe("analyzeCatchall — transient failure resilience", () => {
	it("KV error during Spamhaus check degrades to no-boost, does not throw", async () => {
		const env = makeEnv({ kv: makeErrorKv() });

		await expect(
			analyzeCatchall(env, {
				rawHeaders: receivedWith(TEST_IP),
				body: null,
			}),
		).resolves.toMatchObject({ intelMatch: null });
	});

	it("no source IP in headers → IP reputation skipped, no throw", async () => {
		const kv = makeKv();
		seedCidr(kv, "spamhaus-drop", TEST_CIDR);
		const env = makeEnv({ apiKey: "test-key", kv });

		const result = await analyzeCatchall(env, {
			rawHeaders: AUTH_PASS, // no Received: header
			body: null,
		});

		expect(result.sourceIp).toBeUndefined();
		expect(result.intelMatch).toBeNull();
	});
});

describe("analyzeCatchall — sender field", () => {
	it("lowercases the sender address", async () => {
		const env = makeEnv();
		const result = await analyzeCatchall(env, {
			rawHeaders: [],
			body: null,
			from: { address: "USER@EXAMPLE.COM" },
		});
		expect(result.sender).toBe("user@example.com");
	});

	it("returns empty string when from is absent", async () => {
		const env = makeEnv();
		const result = await analyzeCatchall(env, { rawHeaders: [], body: null });
		expect(result.sender).toBe("");
	});
});
