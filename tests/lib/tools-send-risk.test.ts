// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Send-risk gate on toolSendReply and toolSendEmail (issue #313).
 *
 * Acceptance criteria tested:
 *   1. Tier 0 send (internal recipient) proceeds without a token.
 *   2. Tier ≥ 1 send (external recipient) without token → confirmation_required error,
 *      no env.EMAIL send, no SENT write.
 *   3. Tier ≥ 1 send with invalid/expired token → rejected, no send.
 *   4. Tier ≥ 1 send with valid token → send proceeds.
 */

import { describe, expect, it, vi, beforeEach } from "vitest";

// ── Mock sendEmail so no real delivery happens ───────────────────────────────
vi.mock("../../workers/email-sender", () => ({
	sendEmail: vi.fn().mockResolvedValue(undefined),
}));

// ── Mock the AI verifyDraft to return the body unchanged ──────────────────────
vi.mock("../../workers/lib/ai", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/ai")>();
	return {
		...original,
		verifyDraft: vi.fn().mockImplementation((_ai: unknown, body: string) =>
			Promise.resolve(body),
		),
	};
});

// ── Mock mailbox-settings (resolveMailboxSettings) to return defaults ─────────
vi.mock("../../workers/lib/mailbox-settings", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/mailbox-settings")>();
	return {
		...original,
		resolveMailboxSettings: vi.fn().mockResolvedValue({ draftVerifierModel: undefined }),
	};
});

import { toolSendReply, toolSendEmail } from "../../workers/lib/tools";
import { sendEmail } from "../../workers/email-sender";
import {
	signConfirmationToken,
	computePayloadHash,
} from "../../workers/lib/confirm-token";
import type { Env } from "../../workers/types";
import type { EmailFull } from "../../workers/lib/schemas";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const MAILBOX_ID = "operator@internal.example";
const ORIGINAL_ID = "orig-email-1";
const SECRET = "test-secret-at-least-32-chars-long-for-hs256!!";

const originalEmail: EmailFull = {
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

// ── KV stub for token replay-protection ──────────────────────────────────────

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
	} as unknown as KVNamespace;
}

// ── DO stub factory ───────────────────────────────────────────────────────────

function makeStub(opts: { sendRateLimitError?: string | null } = {}) {
	const sentEmails: unknown[] = [];
	const consumedJtis = new Set<string>();
	return {
		async checkSendRateLimit() {
			return opts.sendRateLimitError ?? null;
		},
		async getEmail(id: string) {
			return id === ORIGINAL_ID ? originalEmail : null;
		},
		async createEmail(_folder: unknown, email: unknown) {
			sentEmails.push(email);
			return {};
		},
		async consumeJti(jti: string): Promise<boolean> {
			if (consumedJtis.has(jti)) return false;
			consumedJtis.add(jti);
			return true;
		},
		_sentEmails: sentEmails,
	};
}

// ── Env factory ───────────────────────────────────────────────────────────────

function makeEnv(
	stub: ReturnType<typeof makeStub>,
	kv?: KVNamespace,
): Env {
	return {
		CONFIRMATION_TOKEN_SECRET: SECRET,
		BLOOM_KV: kv ?? makeKv(),
		// The DO binding — getMailboxStub calls env.MAILBOX.idFromName()
		// and .get(). We intercept by providing a minimal stub that always
		// returns our pre-built stub.
		MAILBOX: {
			idFromName: () => "id",
			get: () => stub,
		},
		// Minimal stubs for other bindings that tools.ts may touch.
		BUCKET: { get: vi.fn(), put: vi.fn(), delete: vi.fn(), list: vi.fn() } as unknown as R2Bucket,
		AI: {} as unknown as Ai,
		EMAIL: {} as unknown as SendEmail,
	} as unknown as Env;
}

// ── Helper: mint a valid confirmation token ───────────────────────────────────

async function mintValidToken(
	to: string,
	subject: string,
	body: string,
	mailboxId: string,
	kv: KVNamespace,
): Promise<string> {
	const jti = crypto.randomUUID();
	const payloadHash = await computePayloadHash(to, subject, body, []);
	const token = await signConfirmationToken(
		{ tier: 1, mailboxId, payloadHash, jti },
		SECRET,
	);
	// Pre-seed KV so the verify step finds the jti.
	await kv.put(`confirm-jti:${jti}`, "1");
	return token;
}

// ─────────────────────────────────────────────────────────────────────────────
// toolSendReply tests
// ─────────────────────────────────────────────────────────────────────────────

describe("toolSendReply — send-risk gate", () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it("tier 0 (internal recipient): sends without a confirmation token", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		const result = await toolSendReply(env, MAILBOX_ID, {
			originalEmailId: ORIGINAL_ID,
			to: "colleague@internal.example", // same domain → tier 0
			subject: "Re: Question",
			bodyHtml: "<p>Sure!</p>",
		});
		expect(result).toMatchObject({ status: "sent" });
		expect(sendEmail).toHaveBeenCalledOnce();
		expect(stub._sentEmails).toHaveLength(1); // SENT row written
	});

	it("tier ≥ 1 (external recipient) without token: returns confirmation_required, no send", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		const result = await toolSendReply(env, MAILBOX_ID, {
			originalEmailId: ORIGINAL_ID,
			to: "vendor@external.com", // different domain → tier 1
			subject: "Re: Question",
			bodyHtml: "<p>Sure!</p>",
		});
		expect(result).toMatchObject({
			error: "confirmation_required",
			confirmation_required: true,
		});
		expect((result as { risk?: { tier: number } }).risk?.tier).toBeGreaterThanOrEqual(1);
		expect(sendEmail).not.toHaveBeenCalled();
		expect(stub._sentEmails).toHaveLength(0); // no SENT write
	});

	it("tier ≥ 1 with invalid/expired token: rejected, no send", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		const result = await toolSendReply(env, MAILBOX_ID, {
			originalEmailId: ORIGINAL_ID,
			to: "vendor@external.com",
			subject: "Re: Question",
			bodyHtml: "<p>Sure!</p>",
			confirmationToken: "this.is.not.a.valid.jwt",
		});
		expect("error" in result).toBe(true);
		expect((result as { error: string }).error).toMatch(/invalid|expired|confirmation/i);
		expect(sendEmail).not.toHaveBeenCalled();
		expect(stub._sentEmails).toHaveLength(0);
	});

	it("tier ≥ 1 with valid token: send proceeds", async () => {
		const kv = makeKv();
		const stub = makeStub();
		const env = makeEnv(stub, kv);

		const to = "vendor@external.com";
		const subject = "Re: Question";
		const body = "<p>Sure!</p>";
		const token = await mintValidToken(to, subject, body, MAILBOX_ID, kv);

		const result = await toolSendReply(env, MAILBOX_ID, {
			originalEmailId: ORIGINAL_ID,
			to,
			subject,
			bodyHtml: body,
			confirmationToken: token,
		});
		expect(result).toMatchObject({ status: "sent" });
		expect(sendEmail).toHaveBeenCalledOnce();
		expect(stub._sentEmails).toHaveLength(1);
	});
});

// ─────────────────────────────────────────────────────────────────────────────
// toolSendEmail tests
// ─────────────────────────────────────────────────────────────────────────────

describe("toolSendEmail — send-risk gate", () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it("tier 0 (internal recipient): sends without a confirmation token", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		const result = await toolSendEmail(env, MAILBOX_ID, {
			to: "colleague@internal.example", // same domain → tier 0
			subject: "Hello",
			bodyHtml: "<p>Hi there</p>",
		});
		expect(result).toMatchObject({ status: "sent" });
		expect(sendEmail).toHaveBeenCalledOnce();
		expect(stub._sentEmails).toHaveLength(1);
	});

	it("tier ≥ 1 (external recipient) without token: returns confirmation_required, no send", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		const result = await toolSendEmail(env, MAILBOX_ID, {
			to: "vendor@external.com",
			subject: "Hello",
			bodyHtml: "<p>Hi there</p>",
		});
		expect(result).toMatchObject({
			error: "confirmation_required",
			confirmation_required: true,
		});
		expect((result as { risk?: { tier: number } }).risk?.tier).toBeGreaterThanOrEqual(1);
		expect(sendEmail).not.toHaveBeenCalled();
		expect(stub._sentEmails).toHaveLength(0);
	});

	it("tier ≥ 1 with invalid/expired token: rejected, no send", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		const result = await toolSendEmail(env, MAILBOX_ID, {
			to: "vendor@external.com",
			subject: "Hello",
			bodyHtml: "<p>Hi there</p>",
			confirmationToken: "bad.token.value",
		});
		expect("error" in result).toBe(true);
		expect((result as { error: string }).error).toMatch(/invalid|expired|confirmation/i);
		expect(sendEmail).not.toHaveBeenCalled();
		expect(stub._sentEmails).toHaveLength(0);
	});

	it("tier ≥ 1 with valid token: send proceeds", async () => {
		const kv = makeKv();
		const stub = makeStub();
		const env = makeEnv(stub, kv);

		const to = "vendor@external.com";
		const subject = "Hello";
		const body = "<p>Hi there</p>";
		const token = await mintValidToken(to, subject, body, MAILBOX_ID, kv);

		const result = await toolSendEmail(env, MAILBOX_ID, {
			to,
			subject,
			bodyHtml: body,
			confirmationToken: token,
		});
		expect(result).toMatchObject({ status: "sent" });
		expect(sendEmail).toHaveBeenCalledOnce();
		expect(stub._sentEmails).toHaveLength(1);
	});

	it("BEC keyword (tier 2) without token: returns confirmation_required", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		const result = await toolSendEmail(env, MAILBOX_ID, {
			to: "colleague@internal.example",
			subject: "Urgent",
			bodyHtml: "<p>Please wire transfer $10,000 immediately</p>",
		});
		expect(result).toMatchObject({
			error: "confirmation_required",
			confirmation_required: true,
		});
		expect((result as { risk?: { tier: number } }).risk?.tier).toBe(2);
		expect(sendEmail).not.toHaveBeenCalled();
	});
});
