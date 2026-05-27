// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it, vi, beforeEach } from "vitest";
import { enforceSendRiskConfirmation } from "../../workers/lib/send-risk-gate";
import {
	computePayloadHash,
	signConfirmationToken,
} from "../../workers/lib/confirm-token";

const SECRET = "test-confirm-secret";
const MAILBOX_ID = "operator@internal.example";

function makeKv() {
	const store = new Map<string, string>();
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

describe("enforceSendRiskConfirmation", () => {
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
