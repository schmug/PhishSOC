// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Send-risk gate on reply/forward routes — regression for bypass where only
 * POST /emails enforced step-up confirmation (#273 / #285).
 */

import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { describe, expect, it, vi, beforeEach } from "vitest";

vi.mock("../../workers/lib/mailbox", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/mailbox")>();
	return {
		...original,
		requireMailbox: createMiddleware(async (_c, next) => {
			await next();
		}),
	};
});

vi.mock("../../workers/email-sender", () => ({
	sendEmail: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../workers/lib/attachments", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/attachments")>();
	return { ...original, storeAttachments: vi.fn().mockResolvedValue([]) };
});

import { handleReplyEmail, handleForwardEmail } from "../../workers/routes/reply-forward";
import type { MailboxContext } from "../../workers/lib/mailbox";
import type { EmailFull } from "../../workers/lib/schemas";

const MAILBOX_ID = "operator@internal.example";
const ORIGINAL_ID = "orig-email-1";

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

function makeStub() {
	return {
		async checkSendRateLimit() {
			return null;
		},
		async getEmail(id: string) {
			return id === ORIGINAL_ID ? originalEmail : null;
		},
		async createEmail() {
			return {};
		},
		async markThreadRead() {
			return {};
		},
	};
}

let currentStub = makeStub();

beforeEach(() => {
	currentStub = makeStub();
	vi.clearAllMocks();
});

const fakeCtx = {
	waitUntil: (_p: Promise<unknown>) => {},
	passThroughOnException: () => {},
} as unknown as ExecutionContext;

function makeApp(handler: typeof handleReplyEmail) {
	const app = new Hono<MailboxContext>();
	app.use("*", async (c, next) => {
		c.set("mailboxStub", currentStub as unknown as Parameters<typeof c.set>[1]);
		await next();
	});
	app.post("/api/v1/mailboxes/:mailboxId/emails/:id/reply", handler);
	return {
		fetch(path: string, opts?: RequestInit) {
			return app.request(path, opts, {} as never, fakeCtx);
		},
	};
}

function sendBody(overrides: Record<string, unknown> = {}) {
	return {
		to: "colleague@internal.example",
		from: MAILBOX_ID,
		subject: "Re: Question",
		text: "Reply body",
		...overrides,
	};
}

describe("POST /emails/:id/reply — send-risk gate", () => {
	it("returns 401 confirmation_required for external recipient without token", async () => {
		const { fetch } = makeApp(handleReplyEmail);
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails/${ORIGINAL_ID}/reply`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(sendBody({ to: "vendor@external.com" })),
			},
		);
		expect(res.status).toBe(401);
		const json = (await res.json()) as { error: string; risk: { tier: number } };
		expect(json.error).toBe("confirmation_required");
		expect(json.risk.tier).toBe(1);
	});

	it("returns 401 confirmation_required for BEC keyword without token", async () => {
		const { fetch } = makeApp(handleReplyEmail);
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails/${ORIGINAL_ID}/reply`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(
					sendBody({ text: "Please wire transfer $10,000 immediately" }),
				),
			},
		);
		expect(res.status).toBe(401);
		const json = (await res.json()) as { error: string; risk: { tier: number } };
		expect(json.error).toBe("confirmation_required");
		expect(json.risk.tier).toBe(2);
	});
});

describe("POST /emails/:id/forward — send-risk gate", () => {
	it("returns 401 confirmation_required for external recipient without token", async () => {
		const app = new Hono<MailboxContext>();
		app.use("*", async (c, next) => {
			c.set("mailboxStub", currentStub as unknown as Parameters<typeof c.set>[1]);
			await next();
		});
		app.post("/api/v1/mailboxes/:mailboxId/emails/:id/forward", handleForwardEmail);
		const res = await app.request(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails/${ORIGINAL_ID}/forward`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(sendBody({ to: "vendor@external.com" })),
			},
			{} as never,
			fakeCtx,
		);
		expect(res.status).toBe(401);
		const json = (await res.json()) as { error: string; risk: { tier: number } };
		expect(json.error).toBe("confirmation_required");
		expect(json.risk.tier).toBe(1);
	});
});
