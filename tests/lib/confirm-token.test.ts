// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Unit tests for workers/lib/confirm-token.ts
 * Covers: sign produces valid HS256 JWT, verify succeeds on first use,
 * replay (second use) → null, wrong mailboxId → null, wrong payloadHash → null.
 */

import { describe, expect, it } from "vitest";
import {
	signConfirmationToken,
	verifyConfirmationToken,
	computePayloadHash,
	type ConfirmationTokenPayload,
} from "../../workers/lib/confirm-token";

const SECRET = "test-secret-at-least-32-chars-long-for-hs256!!";

function makeKv(initial: Record<string, string> = {}) {
	const store: Record<string, string> = { ...initial };
	return {
		async get(key: string) {
			return store[key] ?? null;
		},
		async put(key: string, value: string, _opts?: unknown) {
			store[key] = value;
		},
		async delete(key: string) {
			delete store[key];
		},
		_store: store,
	};
}

const BASE: ConfirmationTokenPayload = {
	tier: 1,
	mailboxId: "me@example.com",
	payloadHash: "a".repeat(64),
	jti: "test-jti-1234",
};

describe("signConfirmationToken", () => {
	it("produces a three-part JWT string", async () => {
		const token = await signConfirmationToken(BASE, SECRET);
		expect(token.split(".").length).toBe(3);
	});

	it("header alg is HS256", async () => {
		const token = await signConfirmationToken(BASE, SECRET);
		const header = JSON.parse(
			Buffer.from(token.split(".")[0], "base64url").toString(),
		);
		expect(header.alg).toBe("HS256");
	});

	it("payload contains tier, mailboxId, payloadHash, jti, exp", async () => {
		const before = Math.floor(Date.now() / 1000);
		const token = await signConfirmationToken(BASE, SECRET);
		const after = Math.floor(Date.now() / 1000);

		const payload = JSON.parse(
			Buffer.from(token.split(".")[1], "base64url").toString(),
		);

		expect(payload.tier).toBe(1);
		expect(payload.mailboxId).toBe("me@example.com");
		expect(payload.payloadHash).toBe("a".repeat(64));
		expect(payload.jti).toBe("test-jti-1234");
		expect(typeof payload.exp).toBe("number");
		// exp is iat + 60
		expect(payload.exp - payload.iat).toBe(60);
		expect(payload.exp).toBeGreaterThanOrEqual(before + 60);
		expect(payload.exp).toBeLessThanOrEqual(after + 61);
	});
});

describe("verifyConfirmationToken", () => {
	async function mintWithJti(jti: string, overrides: Partial<ConfirmationTokenPayload> = {}) {
		const payload = { ...BASE, jti, ...overrides };
		return signConfirmationToken(payload, SECRET);
	}

	/** Simulates the DO's atomic INSERT OR IGNORE using a plain Set. */
	function makeConsumeJti(consumed = new Set<string>()) {
		return (jti: string): Promise<boolean> => {
			if (consumed.has(jti)) return Promise.resolve(false);
			consumed.add(jti);
			return Promise.resolve(true);
		};
	}

	it("succeeds on first use and returns the payload", async () => {
		const kv = makeKv({ "confirm-jti:abc": "1" });
		const token = await mintWithJti("abc");

		const result = await verifyConfirmationToken(
			token,
			SECRET,
			BASE.mailboxId,
			BASE.payloadHash,
			kv as unknown as KVNamespace,
			makeConsumeJti(),
		);

		expect(result).not.toBeNull();
		expect(result!.tier).toBe(1);
		expect(result!.mailboxId).toBe(BASE.mailboxId);
		expect(result!.payloadHash).toBe(BASE.payloadHash);
		expect(result!.jti).toBe("abc");
	});

	it("calls consumeJti on success and not before the KV check (replay protection)", async () => {
		const kv = makeKv({ "confirm-jti:abc2": "1" });
		const token = await mintWithJti("abc2");
		const consumed = new Set<string>();

		const result = await verifyConfirmationToken(
			token,
			SECRET,
			BASE.mailboxId,
			BASE.payloadHash,
			kv as unknown as KVNamespace,
			makeConsumeJti(consumed),
		);

		expect(result).not.toBeNull();
		expect(consumed.has("abc2")).toBe(true);
	});

	it("returns null on second use of the same token (replay)", async () => {
		const kv = makeKv({ "confirm-jti:abc3": "1" });
		const token = await mintWithJti("abc3");
		const consumeJti = makeConsumeJti();

		const first = await verifyConfirmationToken(
			token,
			SECRET,
			BASE.mailboxId,
			BASE.payloadHash,
			kv as unknown as KVNamespace,
			consumeJti,
		);
		expect(first).not.toBeNull();

		const second = await verifyConfirmationToken(
			token,
			SECRET,
			BASE.mailboxId,
			BASE.payloadHash,
			kv as unknown as KVNamespace,
			consumeJti,
		);
		expect(second).toBeNull();
	});

	it("concurrent calls: exactly one succeeds (atomic jti consume)", async () => {
		const kv = makeKv({ "confirm-jti:race": "1" });
		const token = await mintWithJti("race");
		const consumeJti = makeConsumeJti();

		const [r1, r2] = await Promise.all([
			verifyConfirmationToken(token, SECRET, BASE.mailboxId, BASE.payloadHash, kv as unknown as KVNamespace, consumeJti),
			verifyConfirmationToken(token, SECRET, BASE.mailboxId, BASE.payloadHash, kv as unknown as KVNamespace, consumeJti),
		]);

		const successes = [r1, r2].filter(Boolean);
		expect(successes).toHaveLength(1);
	});

	it("returns null when jti is not in KV (never issued or already consumed)", async () => {
		const kv = makeKv(); // empty KV — jti not present
		const token = await mintWithJti("missing-jti");

		const result = await verifyConfirmationToken(
			token,
			SECRET,
			BASE.mailboxId,
			BASE.payloadHash,
			kv as unknown as KVNamespace,
			makeConsumeJti(),
		);
		expect(result).toBeNull();
	});

	it("returns null when mailboxId does not match", async () => {
		const kv = makeKv({ "confirm-jti:mismatch-mb": "1" });
		const token = await mintWithJti("mismatch-mb");

		const result = await verifyConfirmationToken(
			token,
			SECRET,
			"other@example.com", // wrong mailboxId
			BASE.payloadHash,
			kv as unknown as KVNamespace,
			makeConsumeJti(),
		);
		expect(result).toBeNull();
	});

	it("returns null when payloadHash does not match", async () => {
		const kv = makeKv({ "confirm-jti:mismatch-ph": "1" });
		const token = await mintWithJti("mismatch-ph");

		const result = await verifyConfirmationToken(
			token,
			SECRET,
			BASE.mailboxId,
			"b".repeat(64), // wrong hash
			kv as unknown as KVNamespace,
			makeConsumeJti(),
		);
		expect(result).toBeNull();
	});

	it("returns null when token is signed with wrong secret", async () => {
		const kv = makeKv({ "confirm-jti:wrong-sig": "1" });
		const token = await mintWithJti("wrong-sig");

		const result = await verifyConfirmationToken(
			token,
			"totally-different-secret-at-least-32chars",
			BASE.mailboxId,
			BASE.payloadHash,
			kv as unknown as KVNamespace,
			makeConsumeJti(),
		);
		expect(result).toBeNull();
	});
});

describe("computePayloadHash", () => {
	it("includes cc and bcc in the hash so undisclosed recipients cannot be added after confirm", async () => {
		const base = await computePayloadHash(
			"victim@acme.com",
			"Pay invoice",
			"wire transfer details",
			[],
		);
		const withBcc = await computePayloadHash(
			"victim@acme.com",
			"Pay invoice",
			"wire transfer details",
			[],
			undefined,
			"exfil@evil.com",
		);
		expect(withBcc).not.toBe(base);
	});

	it("normalizes recipient list order for to, cc, and bcc", async () => {
		const h1 = await computePayloadHash(
			["a@x.com", "b@x.com"],
			"s",
			"b",
			[],
			"c@x.com, d@x.com",
			"e@x.com",
		);
		const h2 = await computePayloadHash(
			["b@x.com", "a@x.com"],
			"s",
			"b",
			[],
			"d@x.com, c@x.com",
			"e@x.com",
		);
		expect(h1).toBe(h2);
	});
});

describe("computePayloadHash", () => {
	it("includes cc and bcc in the hash so undisclosed recipients cannot be added after confirm", async () => {
		const base = await computePayloadHash(
			"victim@acme.com",
			"Pay invoice",
			"wire transfer details",
			[],
		);
		const withBcc = await computePayloadHash(
			"victim@acme.com",
			"Pay invoice",
			"wire transfer details",
			[],
			undefined,
			"exfil@evil.com",
		);
		expect(withBcc).not.toBe(base);
	});

	it("normalizes recipient list order for to, cc, and bcc", async () => {
		const h1 = await computePayloadHash(
			["a@x.com", "b@x.com"],
			"s",
			"b",
			[],
			"c@x.com, d@x.com",
			"e@x.com",
		);
		const h2 = await computePayloadHash(
			["b@x.com", "a@x.com"],
			"s",
			"b",
			[],
			"d@x.com, c@x.com",
			"e@x.com",
		);
		expect(h1).toBe(h2);
	});
});
