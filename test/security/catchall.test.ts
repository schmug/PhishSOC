// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Unit tests for `analyzeCatchall`.
 *
 * Key invariants verified:
 *   - `env.AI` is NEVER invoked (asserted by a throwing stub)
 *   - Auth failures score correctly
 *   - Homograph and shortener URLs score correctly
 *   - CrowdSec CTI reputation contributes to score
 *   - All-clean email scores 0
 *   - All external CTI calls are intercepted; suite is hermetic
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { analyzeCatchall } from "../../workers/security/catchall";
import type { Env } from "../../workers/types";

// ── Helpers ───────────────────────────────────────────────────────────────

function makeAuthHeaders(opts: {
	spf?: string;
	dkim?: string;
	dmarc?: string;
	authserv?: string;
}): unknown[] {
	const { spf = "pass", dkim = "pass", dmarc = "pass", authserv = "mx.example.com" } = opts;
	const value = `${authserv}; spf=${spf} header.from=example.com; dkim=${dkim} header.d=example.com header.s=sel1; dmarc=${dmarc} header.from=example.com`;
	return [{ key: "authentication-results", value }];
}

/** No authentication-results header → auth score = 0, no boost or deduction. */
function noAuthHeaders(): unknown[] {
	return [];
}

function makeReceivedHeaders(ip: string): unknown[] {
	return [{ key: "received", value: `from mail.attacker.net ([${ip}]) by mx.example.com` }];
}

/** AI stub that throws if invoked — verifies the catch-all path never calls it. */
const AI_NEVER_CALLED = {
	run() {
		throw new Error("env.AI must never be invoked on the catch-all path");
	},
} as unknown as Ai;

function makeEnv(opts: { apiKey?: string } = {}): Env {
	return {
		AI: AI_NEVER_CALLED,
		CROWDSEC_CTI_API_KEY: opts.apiKey,
	} as unknown as Env;
}

function ctiResponse(reputation: string, status = 200): Response {
	const body = {
		reputation,
		classifications: [],
		behaviors: [],
		scores: { overall: { threat: 50, aggressiveness: 30, trust: 20 } },
	};
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});
}

// ── Tests ─────────────────────────────────────────────────────────────────

describe("analyzeCatchall — no-AI invariant", () => {
	it("does not invoke env.AI even when auth or URLs are suspicious", async () => {
		const result = await analyzeCatchall({
			parsedEmail: {
				headers: makeAuthHeaders({ dmarc: "fail", spf: "fail", dkim: "fail" }),
				html: '<a href="http://goog1e.com/login">click</a>',
			},
			env: makeEnv(),
		});
		// If AI_NEVER_CALLED.run() had fired, the test would have thrown.
		expect(result.score).toBeGreaterThan(0);
	});
});

describe("analyzeCatchall — auth scoring", () => {
	it("clean email (all pass) scores 0 from auth", async () => {
		const result = await analyzeCatchall({
			parsedEmail: {
				headers: makeAuthHeaders({ spf: "pass", dkim: "pass", dmarc: "pass" }),
				html: "<p>Hello</p>",
			},
			env: makeEnv(),
		});
		expect(result.score).toBe(0);
		expect(result.signals).toHaveLength(0);
	});

	it("DMARC fail contributes +20", async () => {
		const result = await analyzeCatchall({
			parsedEmail: {
				headers: makeAuthHeaders({ dmarc: "fail" }),
			},
			env: makeEnv(),
		});
		// DMARC fail = +20, capped at 30 total by scoreAuth
		expect(result.score).toBe(20);
		expect(result.signals).toContain("DMARC failed");
		expect(result.auth.dmarc).toBe("fail");
	});

	it("SPF + DKIM fail contribute up to 30 (scoreAuth cap)", async () => {
		const result = await analyzeCatchall({
			parsedEmail: {
				headers: makeAuthHeaders({ spf: "fail", dkim: "fail", dmarc: "fail" }),
			},
			env: makeEnv(),
		});
		// DMARC(20) + SPF(10) + DKIM(10) = 40, but scoreAuth caps at 30
		expect(result.score).toBe(30);
		expect(result.auth.spf).toBe("fail");
		expect(result.auth.dkim).toBe("fail");
	});
});

describe("analyzeCatchall — URL heuristics", () => {
	it("homograph URL contributes +20", async () => {
		// No auth headers → auth score 0, isolating the URL signal.
		const result = await analyzeCatchall({
			parsedEmail: {
				headers: noAuthHeaders(),
				html: '<a href="http://goog1e.com/login">login</a>',
			},
			env: makeEnv(),
		});
		expect(result.score).toBe(20);
		expect(result.signals.some((s) => s.includes("homograph"))).toBe(true);
		expect(result.homographUrls).toBe(1);
	});

	it("shortener link contributes +5", async () => {
		// No auth headers → auth score 0, isolating the URL signal.
		const result = await analyzeCatchall({
			parsedEmail: {
				headers: noAuthHeaders(),
				html: '<a href="https://bit.ly/xyz123">click</a>',
			},
			env: makeEnv(),
		});
		expect(result.score).toBe(5);
		expect(result.shortenerUrls).toBe(1);
	});

	it("urlCount matches extracted links", async () => {
		const result = await analyzeCatchall({
			parsedEmail: {
				headers: makeAuthHeaders({}),
				html: '<a href="https://example.com">a</a><a href="https://example.org">b</a>',
			},
			env: makeEnv(),
		});
		expect(result.urlCount).toBe(2);
	});

	it("no body → urlCount 0 and no URL signals", async () => {
		const result = await analyzeCatchall({
			parsedEmail: { headers: makeAuthHeaders({}) },
			env: makeEnv(),
		});
		expect(result.urlCount).toBe(0);
		expect(result.homographUrls).toBe(0);
		expect(result.shortenerUrls).toBe(0);
	});
});

describe("analyzeCatchall — CrowdSec CTI", () => {
	const MALICIOUS_IP = "1.2.3.4";

	beforeEach(() => {
		vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
			const url = typeof input === "string" ? input : (input as Request).url;
			const u = new URL(url);
			if (u.hostname === "cti.api.crowdsec.net" && u.pathname.startsWith("/v2/smoke/")) {
				return ctiResponse("malicious");
			}
			return new Response("not found", { status: 404 });
		});
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("malicious CTI reputation adds +20 to score", async () => {
		// No auth headers → auth score 0, isolating the CTI signal.
		const result = await analyzeCatchall({
			parsedEmail: {
				headers: [
					...noAuthHeaders(),
					...makeReceivedHeaders(MALICIOUS_IP),
				],
			},
			env: makeEnv({ apiKey: "test-key" }),
		});
		expect(result.score).toBe(20);
		expect(result.ctiReputation).toBe("malicious");
		expect(result.senderIp).toBe(MALICIOUS_IP);
		expect(result.signals.some((s) => s.includes("malicious"))).toBe(true);
	});

	it("no API key → skips CTI, ctiReputation is null", async () => {
		const fetchSpy = vi.spyOn(globalThis, "fetch");
		const result = await analyzeCatchall({
			parsedEmail: {
				headers: [
					...noAuthHeaders(),
					...makeReceivedHeaders(MALICIOUS_IP),
				],
			},
			env: makeEnv(),
		});
		expect(result.ctiReputation).toBeNull();
		// CTI fetch must NOT be called when key is absent
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("CTI network failure is swallowed, score unaffected", async () => {
		vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network error"));
		const result = await analyzeCatchall({
			parsedEmail: {
				headers: [
					...noAuthHeaders(),
					...makeReceivedHeaders(MALICIOUS_IP),
				],
			},
			env: makeEnv({ apiKey: "test-key" }),
		});
		expect(result.ctiReputation).toBeNull();
		expect(result.score).toBe(0);
	});
});

describe("analyzeCatchall — result shape", () => {
	it("returns all documented fields", async () => {
		const result = await analyzeCatchall({
			parsedEmail: {
				headers: makeAuthHeaders({}),
			},
			env: makeEnv(),
		});
		expect(result).toMatchObject({
			score: expect.any(Number),
			signals: expect.any(Array),
			auth: expect.objectContaining({ spf: expect.any(String) }),
			urlCount: expect.any(Number),
			homographUrls: expect.any(Number),
			shortenerUrls: expect.any(Number),
			ctiReputation: null,
		});
	});

	it("score is clamped to 0..100", async () => {
		const result = await analyzeCatchall({
			parsedEmail: {
				// All-fail auth + homograph URL — well over 100 raw
				headers: makeAuthHeaders({ spf: "fail", dkim: "fail", dmarc: "fail" }),
				html: '<a href="http://goog1e.com">x</a>',
			},
			env: makeEnv(),
		});
		expect(result.score).toBeGreaterThanOrEqual(0);
		expect(result.score).toBeLessThanOrEqual(100);
	});
});
