// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it, vi, beforeEach } from "vitest";
import { enforceSendRiskConfirmation } from "../../workers/lib/send-risk-gate";
import {
	computePayloadHash,
	signConfirmationToken,
} from "../../workers/lib/confirm-token";

function makeKv(initial: Record<string, string> = {}) {
	const store = new Map(Object.entries(initial));
	return {
		get: vi.fn(async (key: string) => store.get(key) ?? null),
		put: vi.fn(async (key: string, value: string) => {
			store.set(key, value);
		}),
		delete: vi.fn(async (key: string) => {
			store.delete(key);
		}),
	} as unknown as KVNamespace;
}

describe("enforceSendRiskConfirmation — payload binding", () => {
	const SECRET = "test-secret-at-least-32-chars-long-for-hs256!!";

	it("rejects a token when BCC was added after step-up confirm", async () => {
		const kv = makeKv();
		const jti = "gate-bcc-jti";
		await kv.put(`confirm-jti:${jti}`, "1");

		const mailboxId = "soc@acme.com";
		const to = "ceo@acme.com";
		const subject = "wire transfer";
		const body = "Please send funds today";
		const payloadHash = await computePayloadHash(to, subject, body, []);
		const token = await signConfirmationToken(
			{ tier: 2, mailboxId, payloadHash, jti },
			SECRET,
		);

		const gate = await enforceSendRiskConfirmation(
			{ CONFIRMATION_TOKEN_SECRET: SECRET, BLOOM_KV: kv },
			token,
			{
				mailboxId,
				to,
				subject,
				body,
				bcc: "exfil@evil.com",
			},
		);

		expect(gate.ok).toBe(false);
		if (!gate.ok) {
			expect(gate.status).toBe(401);
		}
	});
});

describe("enforceSendRiskConfirmation — agent tier and tier downgrade", () => {
	const SECRET = "test-confirm-secret";
	const MAILBOX_ID = "operator@internal.example";
	let kv: KVNamespace;

	beforeEach(() => {
		kv = makeKv();
	});

	it("bumps agent-authored external sends to tier 2 without a token", async () => {
		const result = await enforceSendRiskConfirmation(
			{ CONFIRMATION_TOKEN_SECRET: SECRET, BLOOM_KV: kv },
			undefined,
			{
				mailboxId: MAILBOX_ID,
				to: "vendor@external.com",
				subject: "Hello",
				body: "Following up on the invoice.",
				createdBy: "agent",
			},
		);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.status).toBe(401);
		expect(result.body.error).toBe("confirmation_required");
		expect(result.body.risk?.tier).toBe(2);
	});

	it("rejects a tier-1 token when classification requires tier 2", async () => {
		const to = "vendor@external.com";
		const subject = "Please wire transfer $10,000";
		const body = "Urgent.";
		const payloadHash = await computePayloadHash(to, subject, body, []);
		const jti = crypto.randomUUID();
		await kv.put(`confirm-jti:${jti}`, "1", { expirationTtl: 120 });
		const token = await signConfirmationToken(
			{ tier: 1, mailboxId: MAILBOX_ID, payloadHash, jti },
			SECRET,
		);

		const result = await enforceSendRiskConfirmation(
			{ CONFIRMATION_TOKEN_SECRET: SECRET, BLOOM_KV: kv },
			token,
			{ mailboxId: MAILBOX_ID, to, subject, body },
		);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.body.error).toBe("confirmation_required");
		expect(result.body.risk?.tier).toBe(2);
	});
});

describe("enforceSendRiskConfirmation — fail closed on missing bindings", () => {
	const SECRET = "test-confirm-secret";
	const MAILBOX_ID = "operator@internal.example";
	type GateEnv = Parameters<typeof enforceSendRiskConfirmation>[0];

	// A high-risk send must NOT be accepted when the step-up verification
	// primitives are unavailable. Previously, a falsy BLOOM_KV (or secret)
	// skipped verification and returned ok:true, accepting any token.
	it("rejects a tier >= 1 send when BLOOM_KV is unconfigured", async () => {
		const result = await enforceSendRiskConfirmation(
			{ CONFIRMATION_TOKEN_SECRET: SECRET, BLOOM_KV: undefined } as unknown as GateEnv,
			"any-token-value",
			{
				mailboxId: MAILBOX_ID,
				to: "vendor@external.com",
				subject: "Please wire transfer $10,000",
				body: "Urgent.",
			},
		);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.status).toBe(401);
		expect(result.body.error).toBe("confirmation_unavailable");
	});

	it("rejects a tier >= 1 send when CONFIRMATION_TOKEN_SECRET is unconfigured", async () => {
		const result = await enforceSendRiskConfirmation(
			{ CONFIRMATION_TOKEN_SECRET: undefined, BLOOM_KV: makeKv() } as unknown as GateEnv,
			"any-token-value",
			{
				mailboxId: MAILBOX_ID,
				to: "vendor@external.com",
				subject: "Please wire transfer $10,000",
				body: "Urgent.",
			},
		);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.body.error).toBe("confirmation_unavailable");
	});
});
