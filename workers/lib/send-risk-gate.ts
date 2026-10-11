// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import type { SendRisk, SendRiskRecord } from "../security/send-risk";
import { computePayloadHash, verifyConfirmationToken } from "./confirm-token";
import { assessSendRisk, type SendContextStub } from "./send-risk-assess";
import type { Env } from "../types";

export type SendRiskGateInput = {
	mailboxId: string;
	to: string | string[];
	cc?: string | string[] | null;
	bcc?: string | string[] | null;
	subject: string;
	body: string;
	attachments?: Array<{ filename?: string | null }>;
	/** From draft row `created_by` when sending an existing draft (#266). */
	createdBy?: "agent" | "user";
	/** Email row id or Message-ID of the message being replied to / forwarded. */
	originalRef?: string | null;
	/** "api" for UI/API routes, "mcp" for MCP tools — see `AssessSendRiskInput.channel`. */
	channel?: "api" | "mcp";
};

type GateEnv = Pick<Env, "CONFIRMATION_TOKEN_SECRET" | "BLOOM_KV"> & Partial<Env>;

export type SendRiskGateResult =
	| { ok: true; risk: SendRisk; confirmed: boolean }
	| { ok: false; status: 401; body: { error: string; risk?: SendRisk } };

/** Serialize a passed gate for `emails.send_risk` on the SENT row. */
export function sendRiskRecord(gate: { risk: SendRisk; confirmed: boolean }): string {
	const record: SendRiskRecord = {
		v: 1,
		tier: gate.risk.tier,
		reasons: gate.risk.reasons,
		confirmed: gate.confirmed,
	};
	return JSON.stringify(record);
}

/**
 * Classify outbound send risk and enforce step-up confirmation for tier ≥ 1.
 * Shared by POST /emails, /reply, /forward and the MCP send tools so none can
 * bypass send-risk.
 *
 * `consumeJti` must atomically mark the token's jti as consumed and return
 * true only on the first consume — use the per-mailbox DO's `consumeJti`
 * method (INSERT OR IGNORE with rowsWritten check) at every call site.
 *
 * `contextStub` (the mailbox DO) enables the stateful rules — recipient
 * history, flagged-thread, lookalike domain. Every production call site
 * passes it; without it only the stateless rules run.
 */
export async function enforceSendRiskConfirmation(
	env: GateEnv,
	confirmationToken: string | undefined,
	input: SendRiskGateInput,
	consumeJti: (jti: string) => Promise<boolean>,
	contextStub?: SendContextStub,
): Promise<SendRiskGateResult> {
	const risk = await assessSendRisk(env, contextStub, {
		to: input.to,
		cc: input.cc,
		bcc: input.bcc,
		subject: input.subject,
		body: input.body,
		attachments: input.attachments,
		mailboxId: input.mailboxId,
		createdBy: input.createdBy,
		originalRef: input.originalRef,
		channel: input.channel,
		phase: "gate",
	});

	if (risk.tier < 1) {
		return { ok: true, risk, confirmed: false };
	}

	if (!confirmationToken) {
		return { ok: false, status: 401, body: { error: "confirmation_required", risk } };
	}

	const { CONFIRMATION_TOKEN_SECRET, BLOOM_KV } = env;
	// Fail closed: a tier >= 1 send must never proceed when the step-up
	// verification primitives are unavailable. Skipping verification here (the
	// previous behaviour when either binding was missing) accepted any token —
	// including a forged or replayed one — for a high-risk send.
	if (!CONFIRMATION_TOKEN_SECRET || !BLOOM_KV) {
		return { ok: false, status: 401, body: { error: "confirmation_unavailable", risk } };
	}
	const attachmentIds = (input.attachments ?? [])
		.map((a) => a.filename?.trim() ?? "")
		.filter(Boolean);
	const payloadHash = await computePayloadHash(
		input.to,
		input.subject,
		input.body,
		attachmentIds,
		input.cc,
		input.bcc,
	);
	const verified = await verifyConfirmationToken(
		confirmationToken,
		CONFIRMATION_TOKEN_SECRET,
		input.mailboxId,
		payloadHash,
		BLOOM_KV,
		consumeJti,
	);
	if (!verified) {
		return { ok: false, status: 401, body: { error: "invalid or expired confirmation token" } };
	}
	if (verified.tier < risk.tier) {
		return {
			ok: false,
			status: 401,
			body: { error: "confirmation_required", risk },
		};
	}

	return { ok: true, risk, confirmed: true };
}
