// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Send-risk gate on MCP toolSendReply and toolSendEmail — regression for
 * bypass where MCP tool sends could proceed without step-up confirmation
 * even for tier ≥ 1 payloads (issue #313).
 */

import { describe, expect, it, vi, beforeEach } from "vitest";

// ── module mocks ─────────────────────────────────────────────────────────────

vi.mock("../../workers/email-sender", () => ({
	sendEmail: vi.fn().mockResolvedValue(undefined),
}));

// resolveMailboxSettings reads R2/DO — return minimal settings.
vi.mock("../../workers/lib/mailbox-settings", () => ({
	resolveMailboxSettings: vi.fn().mockResolvedValue({ draftVerifierModel: undefined }),
}));

// verifyDraft calls the AI binding — return the body unchanged.
vi.mock("../../workers/lib/ai", () => ({
	verifyDraft: vi.fn().mockImplementation((_ai: unknown, body: string) =>
		Promise.resolve(body),
	),
}));

// getMailboxStub returns a DO stub — return a fake one.
vi.mock("../../workers/lib/email-helpers", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/email-helpers")>();
	return {
		...original,
		getMailboxStub: vi.fn(() => fakeStub),
	};
});

import { toolSendReply, toolSendEmail } from "../../workers/lib/tools";
import {
	signConfirmationToken,
	computePayloadHash,
} from "../../workers/lib/confirm-token";
import type { Env } from "../../workers/types";

// ── shared constants ──────────────────────────────────────────────────────────

const MAILBOX_ID = "operator@internal.example";
const ORIGINAL_ID = "orig-email-1";
const SECRET = "test-secret-at-least-32-chars-long-for-hs256!!";

// ── fake DO stub ──────────────────────────────────────────────────────────────

const fakeStub = {
	async checkSendRateLimit() {
		return null;
	},
	async getEmail(id: string) {
		if (id !== ORIGINAL_ID) return null;
		return {
			id: ORIGINAL_ID,
			subject: "Question",
			sender: "asker@external.com",
			recipient: MAILBOX_ID,
			date: new Date().toISOString(),
			body: "Hello?",
			folder: "inbox",
			read: false,
			starred: false,
			thread_id: ORIGINAL_ID,
			message_id: "msg-orig",
			in_reply_to: null,
			email_references: null,
			cc: null,
			bcc: null,
			raw_headers: null,
		};
	},
	async createEmail() {
		return {};
	},
};

// ── fake KV ───────────────────────────────────────────────────────────────────

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
	} as unknown as KVNamespace;
}

// ── env factory ───────────────────────────────────────────────────────────────

function makeEnv(overrides: Partial<Record<string, unknown>> = {}): Env {
	return {
		BLOOM_KV: makeKv(),
		...overrides,
	} as unknown as Env;
}

// ── token helper ──────────────────────────────────────────────────────────────

async function makeValidToken(
	to: string,
	subject: string,
	body: string,
	kv: KVNamespace,
): Promise<string> {
	const payloadHash = await computePayloadHash(to, subject, body, []);
	const jti = crypto.randomUUID();
	// Pre-populate KV so verifyConfirmationToken finds the jti.
	await kv.put(`confirm-jti:${jti}`, "1");
	return signConfirmationToken(
		{ tier: 2, mailboxId: MAILBOX_ID, payloadHash, jti },
		SECRET,
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// toolSendReply
// ─────────────────────────────────────────────────────────────────────────────

beforeEach(() => {
	vi.clearAllMocks();
});

describe("toolSendReply — send-risk gate", () => {
	it("tier 0 (internal recipient) sends without a token", async () => {
		const env = makeEnv();
		const result = await toolSendReply(env, MAILBOX_ID, {
			originalEmailId: ORIGINAL_ID,
			to: "colleague@internal.example",
			subject: "Re: Question",
			bodyHtml: "<p>Sure!</p>",
		});
		expect("error" in result).toBe(false);
		expect((result as { status: string }).status).toBe("sent");
	});

	it("tier ≥ 1 (external recipient) without token returns confirmation_required", async () => {
		const env = makeEnv();
		const result = await toolSendReply(env, MAILBOX_ID, {
			originalEmailId: ORIGINAL_ID,
			to: "vendor@external.com",
			subject: "Re: Question",
			bodyHtml: "<p>Sure!</p>",
		});
		expect("error" in result).toBe(true);
		const err = result as { error: string; risk: { tier: number } };
		expect(err.error).toBe("confirmation_required");
		expect(err.risk.tier).toBeGreaterThanOrEqual(1);
	});

	it("tier ≥ 1 with an invalid token returns invalid or expired", async () => {
		const env = makeEnv({ CONFIRMATION_TOKEN_SECRET: SECRET });
		const result = await toolSendReply(env, MAILBOX_ID, {
			originalEmailId: ORIGINAL_ID,
			to: "vendor@external.com",
			subject: "Re: Question",
			bodyHtml: "<p>Sure!</p>",
			confirmationToken: "not.a.valid.jwt",
		});
		expect("error" in result).toBe(true);
		expect((result as { error: string }).error).toBe(
			"invalid or expired confirmation token",
		);
	});

	it("tier ≥ 1 with a valid token sends successfully", async () => {
		const kv = makeKv();
		const env = makeEnv({ CONFIRMATION_TOKEN_SECRET: SECRET, BLOOM_KV: kv });
		const to = "vendor@external.com";
		const subject = "Re: Question";
		const bodyHtml = "<p>Sure!</p>";
		const token = await makeValidToken(to, subject, bodyHtml, kv);

		const result = await toolSendReply(env, MAILBOX_ID, {
			originalEmailId: ORIGINAL_ID,
			to,
			subject,
			bodyHtml,
			confirmationToken: token,
		});
		expect("error" in result).toBe(false);
		expect((result as { status: string }).status).toBe("sent");
	});

	it("does not write to SENT or call sendEmail when gate rejects", async () => {
		const { sendEmail } = await import("../../workers/email-sender");
		const env = makeEnv();
		await toolSendReply(env, MAILBOX_ID, {
			originalEmailId: ORIGINAL_ID,
			to: "vendor@external.com",
			subject: "Re: Question",
			bodyHtml: "<p>Wire me funds</p>",
		});
		expect(sendEmail).not.toHaveBeenCalled();
		// fakeStub.createEmail would be called on a SENT write; verify it was not.
		const createCalls: unknown[] = [];
		const origCreate = fakeStub.createEmail;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(fakeStub as any).createEmail = async (...args: unknown[]) => {
			createCalls.push(args);
			return origCreate.apply(fakeStub);
		};
		expect(createCalls).toHaveLength(0);
	});
});

// ─────────────────────────────────────────────────────────────────────────────
// toolSendEmail
// ─────────────────────────────────────────────────────────────────────────────

describe("toolSendEmail — send-risk gate", () => {
	it("tier 0 (internal recipient) sends without a token", async () => {
		const env = makeEnv();
		const result = await toolSendEmail(env, MAILBOX_ID, {
			to: "colleague@internal.example",
			subject: "Hello",
			bodyHtml: "<p>How are you?</p>",
		});
		expect("error" in result).toBe(false);
		expect((result as { status: string }).status).toBe("sent");
	});

	it("tier ≥ 1 (external recipient) without token returns confirmation_required", async () => {
		const env = makeEnv();
		const result = await toolSendEmail(env, MAILBOX_ID, {
			to: "vendor@external.com",
			subject: "Hello",
			bodyHtml: "<p>How are you?</p>",
		});
		expect("error" in result).toBe(true);
		const err = result as { error: string; risk: { tier: number } };
		expect(err.error).toBe("confirmation_required");
		expect(err.risk.tier).toBeGreaterThanOrEqual(1);
	});

	it("tier ≥ 1 with an invalid token returns invalid or expired", async () => {
		const env = makeEnv({ CONFIRMATION_TOKEN_SECRET: SECRET });
		const result = await toolSendEmail(env, MAILBOX_ID, {
			to: "vendor@external.com",
			subject: "Hello",
			bodyHtml: "<p>How are you?</p>",
			confirmationToken: "not.a.valid.jwt",
		});
		expect("error" in result).toBe(true);
		expect((result as { error: string }).error).toBe(
			"invalid or expired confirmation token",
		);
	});

	it("tier ≥ 1 with a valid token sends successfully", async () => {
		const kv = makeKv();
		const env = makeEnv({ CONFIRMATION_TOKEN_SECRET: SECRET, BLOOM_KV: kv });
		const to = "vendor@external.com";
		const subject = "Hello";
		const bodyHtml = "<p>How are you?</p>";
		const token = await makeValidToken(to, subject, bodyHtml, kv);

		const result = await toolSendEmail(env, MAILBOX_ID, {
			to,
			subject,
			bodyHtml,
			confirmationToken: token,
		});
		expect("error" in result).toBe(false);
		expect((result as { status: string }).status).toBe("sent");
	});

	it("does not call sendEmail when gate rejects", async () => {
		const { sendEmail } = await import("../../workers/email-sender");
		const env = makeEnv();
		await toolSendEmail(env, MAILBOX_ID, {
			to: "vendor@external.com",
			subject: "Hello",
			bodyHtml: "<p>How are you?</p>",
		});
		expect(sendEmail).not.toHaveBeenCalled();
	});
});
