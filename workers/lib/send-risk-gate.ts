// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { classifySend, type SendRisk } from "../security/send-risk";
import { computePayloadHash, verifyConfirmationToken } from "./confirm-token";
import type { Env } from "../types";

export type SendRiskGateInput = {
	mailboxId: string;
	to: string | string[];
	cc?: string | string[] | null;
	bcc?: string | string[] | null;
	subject: string;
	body: string;
	attachments?: Array<{ filename?: string | null }>;
	/** Passed through to classifySend for the agent-authored tier bump (#266). */
	createdBy?: "agent" | "user";
};

type GateEnv = Pick<Env, "CONFIRMATION_TOKEN_SECRET" | "BLOOM_KV">;

export type SendRiskGateResult =
	| { ok: true; risk: SendRisk }
	| { ok: false; status: 401; body: { error: string; risk?: SendRisk } };

/**
 * Classify outbound send risk and enforce step-up confirmation for tier ≥ 1.
 * Shared by POST /emails, /reply, and /forward so none can bypass send-risk.
 */
export async function enforceSendRiskConfirmation(
	env: GateEnv,
	confirmationToken: string | undefined,
	input: SendRiskGateInput,
): Promise<SendRiskGateResult> {
	const risk = classifySend({
		to: input.to,
		cc: input.cc,
		bcc: input.bcc,
		subject: input.subject,
		body: input.body,
		attachments: input.attachments,
		mailboxId: input.mailboxId,
		createdBy: input.createdBy,
	});

	if (risk.tier < 1) {
		return { ok: true, risk };
	}

	if (!confirmationToken) {
		return { ok: false, status: 401, body: { error: "confirmation_required", risk } };
	}

	const { CONFIRMATION_TOKEN_SECRET, BLOOM_KV } = env;
	if (CONFIRMATION_TOKEN_SECRET && BLOOM_KV) {
		const payloadHash = await computePayloadHash(
			input.to,
			input.subject,
			input.body,
			[],
		);
		const verified = await verifyConfirmationToken(
			confirmationToken,
			CONFIRMATION_TOKEN_SECRET,
			input.mailboxId,
			payloadHash,
			BLOOM_KV,
		);
		if (!verified) {
			return { ok: false, status: 401, body: { error: "invalid or expired confirmation token" } };
		}
	}

	return { ok: true, risk };
}
