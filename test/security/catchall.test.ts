// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for `analyzeCatchall` (issue #424).
 *
 * Covers:
 *   - phishing-shaped input raises score and returns high band
 *   - benign input stays low band
 *   - env.AI is never called (AI stub throws)
 *   - CrowdSec malicious hit boosts score and adds signal
 *   - Spamhaus DROP hit boosts score and adds signal
 *   - transient CTI failures degrade gracefully (no throw)
 */

import { describe, expect, it } from "vitest";
import { analyzeCatchall } from "../../workers/security/catchall";
import type { Env } from "../../workers/types";
import type { Email } from "postal-mime";

function makeEnv(overrides: Partial<Env> = {}): Env {
	return {
		AI: new Proxy({}, {
			get() {
				return () => { throw new Error("env.AI must not be called from catch-all analyzer"); };
			},
		}) as unknown as Env["AI"],
		BLOOM_KV: undefined,
		CROWDSEC_CTI_API_KEY: undefined,
		...overrides,
	} as unknown as Env;
}

function makeEmail(overrides: Partial<Email> = {}): Email {
	return {
		from: { address: "attacker@evil.example", name: "" },
		to: [{ address: "catchall@acme.example", name: "" }],
		subject: "You won a prize",
		text: "Click here http://xn--pypal-4ve.com/login",
		html: null,
		headers: [],
		attachments: [],
		...overrides,
	} as unknown as Email;
}

function makePhishingEmail(): Email {
	return makeEmail({
		headers: [
			{ key: "authentication-results", value: "mx.google.com; spf=fail smtp.mailfrom=evil.example; dkim=fail; dmarc=fail" },
			{ key: "received", value: "from [1.2.3.4] (1.2.3.4) by mx.google.com" },
		],
		html: '<a href="http://xn--pypal-4ve.com/login">Click here</a>',
	});
}

function makeBenignEmail(): Email {
	return makeEmail({
		from: { address: "no-reply@legit.example", name: "" },
		headers: [
			{ key: "authentication-results", value: "mx.google.com; spf=pass smtp.mailfrom=legit.example; dkim=pass; dmarc=pass" },
		],
		text: "Hello, this is a legitimate message.",
		html: null,
	});
}

describe("analyzeCatchall — phishing-shaped input", () => {
	it("scores above low band for failed auth + homograph URL", async () => {
		const env = makeEnv();
		const result = await analyzeCatchall(env, { parsedEmail: makePhishingEmail() });
		// Auth (dmarc+spf+dkim fail → 30 capped) + homograph URL (20) = 50 → medium
		expect(result.score).toBeGreaterThanOrEqual(30);
		expect(result.band).not.toBe("low");
		expect(result.signals.length).toBeGreaterThan(0);
	});

	it("sets urlFlags.homograph for a punycode homograph link", async () => {
		const env = makeEnv();
		const result = await analyzeCatchall(env, { parsedEmail: makePhishingEmail() });
		expect(result.urlFlags.homograph).toBe(true);
	});

	it("returns high band for failed auth + homograph + DROP hit", async () => {
		const cidrRow = { n: 0x01020300, m: 0xFFFFFF00, p: 24 };
		const kv = {
			store: new Map<string, string>([["intel:spamhaus-drop:cidrs", JSON.stringify([cidrRow])]]),
			async get(k: string) { return this.store.get(k) ?? null; },
		} as unknown as KVNamespace;
		const env = makeEnv({ BLOOM_KV: kv });
		const email = makePhishingEmail();
		(email.headers as unknown[]).push({ key: "received", value: "from [1.2.3.4] (1.2.3.4) by mx.google.com" });
		const result = await analyzeCatchall(env, { parsedEmail: email });
		expect(result.band).toBe("high");
		expect(result.score).toBeGreaterThanOrEqual(60);
	});
});

describe("analyzeCatchall — benign input", () => {
	it("returns low band for passing auth and no suspicious URLs", async () => {
		const env = makeEnv();
		const result = await analyzeCatchall(env, { parsedEmail: makeBenignEmail() });
		expect(result.band).toBe("low");
		expect(result.score).toBeLessThan(30);
	});
});

describe("analyzeCatchall — AI never called", () => {
	it("does not call env.AI even for suspicious input", async () => {
		// The AI proxy throws if any method is accessed.
		const env = makeEnv();
		await expect(analyzeCatchall(env, { parsedEmail: makePhishingEmail() })).resolves.toBeDefined();
	});
});

describe("analyzeCatchall — CrowdSec CTI signal", () => {
	it("boosts score and adds signal when CTI returns malicious", async () => {
		const kv = {
			store: new Map<string, string>(),
			async get(k: string) { return this.store.get(k) ?? null; },
			async put(k: string, v: string) { this.store.set(k, v); },
		} as unknown as KVNamespace;

		const maliciousCti = JSON.stringify({
			classifications: [],
			behaviors: [],
			scores: { threat: 95, aggressiveness: 90, trust: 0 },
			reputation: "malicious",
		});
		kv.store = new Map([["cti:crowdsec:1.2.3.4", maliciousCti]]);

		const env = makeEnv({
			BLOOM_KV: kv,
			CROWDSEC_CTI_API_KEY: "test-key",
		});
		const email = makeEmail({
			headers: [
				{ key: "received", value: "from [1.2.3.4] (1.2.3.4) by mx.google.com" },
			],
		});
		const result = await analyzeCatchall(env, { parsedEmail: email });
		expect(result.intelMatch.crowdsec).toBe(true);
		expect(result.signals.some((s) => s.includes("crowdsec-cti"))).toBe(true);
	});

	it("degrades gracefully when CTI throws (transient error)", async () => {
		const kv = {
			async get(_k: string) { throw new Error("KV unavailable"); },
		} as unknown as KVNamespace;
		const env = makeEnv({
			BLOOM_KV: kv,
			CROWDSEC_CTI_API_KEY: "test-key",
		});
		const email = makeEmail({
			headers: [
				{ key: "received", value: "from [1.2.3.4] (1.2.3.4) by mx.google.com" },
			],
		});
		await expect(analyzeCatchall(env, { parsedEmail: email })).resolves.toMatchObject({
			intelMatch: { crowdsec: false, drop: false },
		});
	});
});

describe("analyzeCatchall — Spamhaus DROP signal", () => {
	it("boosts score and adds signal when IP is in DROP CIDR", async () => {
		// Encode a CIDR row covering 1.2.3.0/24 (network=0x01020300, mask=0xFFFFFF00)
		const cidrRow = { n: 0x01020300, m: 0xFFFFFF00, p: 24 };
		const kv = {
			store: new Map<string, string>([["intel:spamhaus-drop:cidrs", JSON.stringify([cidrRow])]]),
			async get(k: string) { return this.store.get(k) ?? null; },
			async put(k: string, v: string) { this.store.set(k, v); },
		} as unknown as KVNamespace;

		const env = makeEnv({ BLOOM_KV: kv });
		const email = makeEmail({
			headers: [
				{ key: "received", value: "from [1.2.3.4] (1.2.3.4) by mx.google.com" },
			],
		});
		const result = await analyzeCatchall(env, { parsedEmail: email });
		expect(result.intelMatch.drop).toBe(true);
		expect(result.signals.some((s) => s.includes("spamhaus-drop"))).toBe(true);
	});
});

describe("analyzeCatchall — no mailboxId in signature", () => {
	it("result contains no mailboxId property", async () => {
		const env = makeEnv();
		const result = await analyzeCatchall(env, { parsedEmail: makeBenignEmail() });
		expect(result).not.toHaveProperty("mailboxId");
	});
});
