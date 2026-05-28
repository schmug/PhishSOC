// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import { enforceSendRiskConfirmation } from "../../workers/lib/send-risk-gate";
import {
	computePayloadHash,
	signConfirmationToken,
} from "../../workers/lib/confirm-token";

const SECRET = "test-secret-at-least-32-chars-long-for-hs256!!";

function makeKv(initial: Record<string, string> = {}) {
	const store: Record<string, string> = { ...initial };
	return {
		async get(key: string) {
			return store[key] ?? null;
		},
		async put(key: string, value: string) {
			store[key] = value;
		},
		async delete(key: string) {
			delete store[key];
		},
	};
}

describe("enforceSendRiskConfirmation — payload binding", () => {
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
			{ CONFIRMATION_TOKEN_SECRET: SECRET, BLOOM_KV: kv as unknown as KVNamespace },
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
