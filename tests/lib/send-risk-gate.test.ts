// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Regression: a Tier-1 step-up token must not authorize a Tier-2 send (e.g. macro
 * attachment added after confirm). Without a tier check, payloadHash binding
 * alone misses attachment-only escalations because attachmentIds stay [].
 */

import { describe, expect, it } from "vitest";
import { enforceSendRiskConfirmation } from "../../workers/lib/send-risk-gate";
import {
	computePayloadHash,
	signConfirmationToken,
} from "../../workers/lib/confirm-token";

const SECRET = "test-secret-at-least-32-chars-long-for-hs256!!";

function makeKv() {
	const store: Record<string, string> = {};
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

describe("enforceSendRiskConfirmation — tier escalation", () => {
	it("rejects a Tier-1 token when the send classifies as Tier 2 (macro attachment)", async () => {
		const mailboxId = "operator@internal.example";
		const to = "vendor@external.com";
		const subject = "Invoice";
		const body = "Please see attached.";
		const payloadHash = await computePayloadHash(to, subject, body, []);
		const jti = crypto.randomUUID();
		const bloomKv = makeKv();
		await bloomKv.put(`confirm-jti:${jti}`, "1");

		const token = await signConfirmationToken(
			{ tier: 1, mailboxId, payloadHash, jti },
			SECRET,
		);

		const result = await enforceSendRiskConfirmation(
			{ CONFIRMATION_TOKEN_SECRET: SECRET, BLOOM_KV: bloomKv as never },
			token,
			{
				mailboxId,
				to,
				subject,
				body,
				attachments: [{ filename: "invoice.pdf.exe" }],
			},
		);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.status).toBe(401);
			expect(result.body.error).toBe("confirmation_tier_insufficient");
			expect(result.body.risk?.tier).toBe(2);
		}
	});
});
