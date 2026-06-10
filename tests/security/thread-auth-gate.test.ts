// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * receiveEmail-level regression for subject-match thread-splicing fix (issue #463).
 *
 * Verifies that:
 *   - Unauthenticated sender (all auth headers fail/none) → findThreadBySubject NOT called
 *   - Authenticated sender (dmarc=pass) → findThreadBySubject IS called; thread adopted
 *   - Authenticated sender (spf=pass) → findThreadBySubject IS called; thread adopted
 *   - Authenticated sender (dkim=pass) → findThreadBySubject IS called; thread adopted
 *   - Quarantined + subject-matched → detachEmailFromThread IS called
 *   - Blocked + subject-matched → detachEmailFromThread IS called
 *   - Quarantined without subject-match → detachEmailFromThread NOT called
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Email } from "postal-mime";
import type { MailboxInbound } from "../../workers/providers/types";
import type { Env } from "../../workers/types";

vi.mock("../../workers/lib/mailbox-settings", () => ({
	resolveMailboxSettings: vi.fn(),
	stripDefaultEqual: <T>(x: T) => x,
	YaraMailScannerSettings: { parse: (x: unknown) => x },
}));

vi.mock("../../workers/security", () => ({
	runSecurityPipeline: vi.fn(),
}));

vi.mock("../../workers/dmarc/ingest", () => ({
	isDmarcReport: vi.fn().mockReturnValue(false),
	ingestDmarcReport: vi.fn(),
	isDmarcRuf: vi.fn().mockReturnValue(false),
	ingestDmarcRuf: vi.fn(),
}));

vi.mock("../../workers/tlsrpt/ingest", () => ({
	isTlsRptReport: vi.fn().mockReturnValue(false),
	ingestTlsRptReport: vi.fn(),
}));

vi.mock("../../workers/intel/deep-scan", () => ({
	runDeepScan: vi.fn().mockResolvedValue({ added_score: 0, final_action: "allow", reasons: [] }),
}));

vi.mock("../../workers/security/yaramail-signal", () => ({
	fireYaraScan: vi.fn().mockResolvedValue(undefined),
}));

import { receiveEmail } from "../../workers/index";
import { resolveMailboxSettings } from "../../workers/lib/mailbox-settings";
import { runSecurityPipeline } from "../../workers/security";

const mockedResolve = vi.mocked(resolveMailboxSettings);
const mockedPipeline = vi.mocked(runSecurityPipeline);

const MAILBOX_ID = "inbox@example.com";
const EXISTING_THREAD_ID = "existing-thread-uuid";

function makeAuthHeader(spf: string, dkim: string, dmarc: string) {
	return { key: "Authentication-Results", value: `authserv.example; spf=${spf}; dkim=${dkim}; dmarc=${dmarc}` };
}

function makeEmail(authHeader?: { key: string; value: string }): Email {
	return {
		subject: "Re: Important discussion",
		from: { address: "alice@example.com", name: "Alice" },
		to: [{ address: MAILBOX_ID, name: "" }],
		headers: authHeader ? [authHeader] : [],
		attachments: [],
	} as unknown as Email;
}

function makeNormalized(email: Email): MailboxInbound {
	return { kind: "mailbox", rawEmail: new ArrayBuffer(0), parsedEmail: email, mailboxId: MAILBOX_ID };
}

function makeMailboxStub(threadId: string | null = null) {
	return {
		createEmail: vi.fn().mockResolvedValue(undefined),
		moveEmail: vi.fn().mockResolvedValue(undefined),
		detachEmailFromThread: vi.fn().mockResolvedValue(undefined),
		findThreadBySubject: vi.fn().mockResolvedValue(threadId),
		recordPipelineRunStart: vi.fn().mockResolvedValue(undefined),
		recordPipelineRunComplete: vi.fn().mockResolvedValue(undefined),
		notifyNewEmail: vi.fn().mockResolvedValue(undefined),
	};
}

function makeEnv(stub: ReturnType<typeof makeMailboxStub>): Env {
	return {
		BUCKET: { head: vi.fn().mockResolvedValue({ key: `mailboxes/${MAILBOX_ID}.json` }), put: vi.fn() },
		MAILBOX: { idFromName: vi.fn().mockReturnValue("do-id"), get: vi.fn().mockReturnValue(stub) },
		EMAIL_AGENT: { idFromName: vi.fn().mockReturnValue("agent-id"), get: vi.fn().mockReturnValue({ fetch: vi.fn().mockResolvedValue(new Response("ok")) }) },
	} as unknown as Env;
}

function makeCtx(): ExecutionContext {
	return { waitUntil: vi.fn() } as unknown as ExecutionContext;
}

const BASE_SETTINGS = {
	security: { enabled: true, ruf_ingestion: { enabled: false }, thresholds: {} },
	autoDraft: { enabled: false },
	raw: undefined,
} as unknown as Awaited<ReturnType<typeof resolveMailboxSettings>>;

describe("receiveEmail — subject-match thread-auth gate (issue #463)", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		mockedResolve.mockResolvedValue(BASE_SETTINGS);
		mockedPipeline.mockResolvedValue({ verdict: null, skipped: true } as never);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("unauthenticated sender: findThreadBySubject NOT called", async () => {
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("fail", "fail", "fail"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.findThreadBySubject).not.toHaveBeenCalled();
		const [, emailArgs] = stub.createEmail.mock.calls[0] as [unknown, { thread_id: string }];
		expect(emailArgs.thread_id).not.toBe(EXISTING_THREAD_ID);
	});

	it("no auth headers: findThreadBySubject NOT called", async () => {
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(); // no Authentication-Results header
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.findThreadBySubject).not.toHaveBeenCalled();
	});

	it("authenticated (dmarc=pass): findThreadBySubject IS called; thread adopted", async () => {
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("fail", "none", "pass"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.findThreadBySubject).toHaveBeenCalledOnce();
		const [, emailArgs] = stub.createEmail.mock.calls[0] as [unknown, { thread_id: string }];
		expect(emailArgs.thread_id).toBe(EXISTING_THREAD_ID);
	});

	it("authenticated (spf=pass): findThreadBySubject IS called; thread adopted", async () => {
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("pass", "none", "none"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.findThreadBySubject).toHaveBeenCalledOnce();
		const [, emailArgs] = stub.createEmail.mock.calls[0] as [unknown, { thread_id: string }];
		expect(emailArgs.thread_id).toBe(EXISTING_THREAD_ID);
	});

	it("authenticated (dkim=pass): findThreadBySubject IS called; thread adopted", async () => {
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("none", "pass", "none"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.findThreadBySubject).toHaveBeenCalledOnce();
		const [, emailArgs] = stub.createEmail.mock.calls[0] as [unknown, { thread_id: string }];
		expect(emailArgs.thread_id).toBe(EXISTING_THREAD_ID);
	});

	it("quarantined + subject-matched: detachEmailFromThread IS called", async () => {
		mockedPipeline.mockResolvedValue({ verdict: { action: "quarantine", score: 80, signals: [], explanation: "" }, skipped: false } as never);
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("pass", "none", "none"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.moveEmail).toHaveBeenCalledWith(expect.any(String), "quarantine");
		expect(stub.detachEmailFromThread).toHaveBeenCalledOnce();
	});

	it("blocked + subject-matched: detachEmailFromThread IS called", async () => {
		mockedPipeline.mockResolvedValue({ verdict: { action: "block", score: 95, signals: [], explanation: "" }, skipped: false } as never);
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("pass", "none", "none"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.moveEmail).toHaveBeenCalledWith(expect.any(String), "quarantine");
		expect(stub.detachEmailFromThread).toHaveBeenCalledOnce();
	});

	it("quarantined without subject-match: detachEmailFromThread NOT called", async () => {
		mockedPipeline.mockResolvedValue({ verdict: { action: "quarantine", score: 80, signals: [], explanation: "" }, skipped: false } as never);
		// findThreadBySubject returns null — no subject match
		const stub = makeMailboxStub(null);
		const email = makeEmail(makeAuthHeader("pass", "none", "none"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.moveEmail).toHaveBeenCalledWith(expect.any(String), "quarantine");
		expect(stub.detachEmailFromThread).not.toHaveBeenCalled();
	});
});
