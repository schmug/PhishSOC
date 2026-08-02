// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Route-level tests for workers/routes/send-email.ts (issue #262 — slice 3 of #15).
 *
 * Acceptance criteria tested here:
 *   1. Tier 0 send (internal recipient) proceeds normally → 202.
 *   2. Tier 1 send (external recipient) without x-confirmation-token → 401
 *      with { error: "confirmation_required", risk }.
 *   3. Tier 2 send (BEC keyword) without x-confirmation-token → 401.
 *   4. POST /emails/preflight returns { tier, reasons } without storing anything.
 */

import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { describe, expect, it, vi, beforeEach } from "vitest";

// requireMailbox makes real R2/DO calls — replace with a stub injector.
vi.mock("../../workers/lib/mailbox", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/mailbox")>();
	return {
		...original,
		requireMailbox: createMiddleware(async (_c, next) => {
			await next();
		}),
	};
});

// sendEmail fires an outbound delivery — no-op for unit tests.
vi.mock("../../workers/email-sender", () => ({
	sendEmail: vi.fn().mockResolvedValue(undefined),
}));

// storeAttachments writes to R2 — return empty array.
vi.mock("../../workers/lib/attachments", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/attachments")>();
	return { ...original, storeAttachments: vi.fn().mockResolvedValue([]) };
});

import { sendEmailRoutes } from "../../workers/routes/send-email";
import type { MailboxContext } from "../../workers/lib/mailbox";

// ── fake stub ────────────────────────────────────────────────────────────────

function makeStub(overrides: Record<string, unknown> = {}) {
	return {
		async checkSendRateLimit() { return null; },
		async createEmail() { return {}; },
		async getEmail() { return null; },
		...overrides,
	};
}

let currentStub = makeStub();

beforeEach(() => {
	currentStub = makeStub();
	vi.clearAllMocks();
});

// ── app factory ───────────────────────────────────────────────────────────────

const fakeCtx = {
	waitUntil: (_p: Promise<unknown>) => {},
	passThroughOnException: () => {},
} as unknown as ExecutionContext;

function makeApp(env: Record<string, unknown> = {}) {
	const app = new Hono<MailboxContext>();
	app.use("*", async (c, next) => {
		c.set("mailboxStub", currentStub as unknown as Parameters<typeof c.set>[1]);
		await next();
	});
	app.route("/api/v1/mailboxes/:mailboxId", sendEmailRoutes);
	return {
		fetch(path: string, opts?: RequestInit) {
			return app.request(path, opts, env as never, fakeCtx);
		},
	};
}

// ── base send body ────────────────────────────────────────────────────────────

const MAILBOX_ID = "operator@internal.example";

function sendBody(overrides: Record<string, unknown> = {}) {
	return {
		to: "colleague@internal.example",
		from: MAILBOX_ID,
		subject: "Hello",
		text: "How are you?",
		...overrides,
	};
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe("POST /emails — Tier 0 (internal recipient)", () => {
	it("proceeds to 202 with no confirmation token required", async () => {
		const { fetch } = makeApp();
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(sendBody()),
			},
		);
		expect(res.status).toBe(202);
		const json = await res.json() as { status: string };
		expect(json.status).toBe("sent");
	});
});

describe("POST /emails — Tier 1 (external recipient) without token", () => {
	it("returns 401 with confirmation_required error and risk", async () => {
		const { fetch } = makeApp();
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(sendBody({ to: "vendor@external.com" })),
			},
		);
		expect(res.status).toBe(401);
		const json = await res.json() as { error: string; risk: { tier: number; reasons: string[] } };
		expect(json.error).toBe("confirmation_required");
		expect(json.risk.tier).toBe(1);
		expect(json.risk.reasons.some((r) => r.includes("External"))).toBe(true);
	});
});

describe("POST /emails — Tier 2 (BEC keyword) without token", () => {
	it("returns 401 with confirmation_required error and risk", async () => {
		const { fetch } = makeApp();
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(
					sendBody({ to: "colleague@internal.example", text: "Please wire transfer $10,000" }),
				),
			},
		);
		expect(res.status).toBe(401);
		const json = await res.json() as { error: string; risk: { tier: number } };
		expect(json.error).toBe("confirmation_required");
		expect(json.risk.tier).toBe(2);
	});

	it("classifies tier 2 when BEC keyword is only in text/plain with benign html", async () => {
		const { fetch } = makeApp();
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(
					sendBody({
						to: "colleague@internal.example",
						html: "<p>Please review the attached.</p>",
						text: "wire transfer $50,000 to account 12345 immediately",
					}),
				),
			},
		);
		expect(res.status).toBe(401);
		const json = await res.json() as { error: string; risk: { tier: number } };
		expect(json.error).toBe("confirmation_required");
		expect(json.risk.tier).toBe(2);
	});
});

describe("POST /emails/preflight", () => {
	it("returns tier and reasons without creating or sending anything", async () => {
		const createEmailCalls: unknown[] = [];
		currentStub = {
			checkSendRateLimit: async () => null,
			createEmail: async (...args: unknown[]) => { createEmailCalls.push(args); return {}; },
		};

		const { fetch } = makeApp();
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails/preflight`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(sendBody({ to: "vendor@external.com" })),
			},
		);
		expect(res.status).toBe(200);
		const json = await res.json() as { tier: number; reasons: string[] };
		expect(json.tier).toBe(1);
		expect(Array.isArray(json.reasons)).toBe(true);
		// No email stored, no email sent.
		expect(createEmailCalls).toHaveLength(0);
	});

	it("returns tier 0 for internal-only send", async () => {
		const { fetch } = makeApp();
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails/preflight`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(sendBody()),
			},
		);
		expect(res.status).toBe(200);
		const json = await res.json() as { tier: number };
		expect(json.tier).toBe(0);
	});

	it("returns tier 2 for BEC keyword body", async () => {
		const { fetch } = makeApp();
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails/preflight`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(
					sendBody({ text: "I need gift card codes urgently" }),
				),
			},
		);
		expect(res.status).toBe(200);
		const json = await res.json() as { tier: number };
		expect(json.tier).toBe(2);
	});

	it("returns tier 2 for agent-authored external draft via draft_id (#266)", async () => {
		currentStub = makeStub({
			async getEmail(id: string) {
				if (id === "draft-agent-1") return { created_by: "agent" };
				return null;
			},
		});
		const { fetch } = makeApp();
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails/preflight`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(
					sendBody({ to: "vendor@external.com", draft_id: "draft-agent-1" }),
				),
			},
		);
		expect(res.status).toBe(200);
		const json = await res.json() as { tier: number };
		expect(json.tier).toBe(2);
	});
});

// ── Validation errors return 400, never 500 (issue: CC/BCC-only 500) ────────────

describe("invalid recipient input → 400 (never 500)", () => {
	it("POST /emails with a malformed bcc returns 400 with a clear message", async () => {
		const createEmailCalls: unknown[] = [];
		currentStub = makeStub({
			createEmail: async (...args: unknown[]) => { createEmailCalls.push(args); return {}; },
		});
		const { fetch } = makeApp();
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(sendBody({ bcc: "not-an-email" })),
			},
		);
		expect(res.status).toBe(400);
		const json = await res.json() as { error: string };
		expect(json.error).toMatch(/bcc/i);
		// Nothing was stored for an invalid send.
		expect(createEmailCalls).toHaveLength(0);
	});

	it("POST /emails with no To: returns 400 asking for a To: recipient", async () => {
		const { fetch } = makeApp();
		const body = sendBody();
		delete (body as Record<string, unknown>).to;
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
			},
		);
		expect(res.status).toBe(400);
		const json = await res.json() as { error: string };
		expect(json.error).toMatch(/to:/i);
	});

	it("POST /emails/preflight with a malformed bcc returns 400, not 500", async () => {
		const { fetch } = makeApp();
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails/preflight`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(sendBody({ bcc: "not-an-email" })),
			},
		);
		expect(res.status).toBe(400);
		const json = await res.json() as { error: string };
		expect(json.error).toMatch(/bcc/i);
	});

	it("POST /emails with a valid array bcc still succeeds (202)", async () => {
		const { fetch } = makeApp();
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(
					sendBody({ bcc: ["one@internal.example", "two@internal.example"] }),
				),
			},
		);
		expect(res.status).toBe(202);
	});

	it("POST /emails with malformed JSON returns 400, not 500", async () => {
		const { fetch } = makeApp();
		const res = await fetch(
			`/api/v1/mailboxes/${encodeURIComponent(MAILBOX_ID)}/emails`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: "{ not json",
			},
		);
		expect(res.status).toBe(400);
	});
});
