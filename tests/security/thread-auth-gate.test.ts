// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * receiveEmail-level regression for subject-match thread-splicing fix
 * (issue #463, hardened for GHSA-m9f6-j7mm-wc4m).
 *
 * The subject-merge gate must require From:-aligned, trustworthy
 * authentication before splicing a referenceless message into an existing
 * thread:
 *
 *   - SPF authenticates the envelope MAIL-FROM and DKIM the signing d=
 *     domain — neither is aligned to the From: header an attacker spoofs,
 *     so spf=pass / dkim=pass alone must NOT unlock the merge.
 *   - Only dmarc=pass implies From: alignment, and it only counts when
 *     reported by an operator-trusted authserv-id (`authVerdict.trusted`),
 *     mirroring `evaluateHardAllow` in workers/security/triage.ts —
 *     otherwise a forged Authentication-Results header claiming dmarc=pass
 *     is honored on default deployments (empty trusted_authserv_ids).
 *
 * Verifies that:
 *   - dmarc=fail + spf=pass + dkim=pass (forged splice) → NOT merged; own thread_id
 *   - spf=pass only → NOT merged
 *   - dkim=pass only → NOT merged
 *   - dmarc=pass from a trusted authserv-id → merged (happy path intact)
 *   - dmarc=pass with empty trusted_authserv_ids (default deploy, forged
 *     Authentication-Results) → NOT merged
 *   - dmarc=pass from an UNtrusted authserv-id on a configured deploy → NOT merged
 *   - Unauthenticated sender (all fail / no headers) → NOT merged
 *   - Quarantined/blocked + subject-matched → detachEmailFromThread IS called
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
const TRUSTED_AUTHSERV = "authserv.example";

function makeAuthHeader(spf: string, dkim: string, dmarc: string, authservId: string = TRUSTED_AUTHSERV) {
	return { key: "Authentication-Results", value: `${authservId}; spf=${spf}; dkim=${dkim}; dmarc=${dmarc}` };
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

function makeSettings(trustedAuthservIds: string[]) {
	return {
		security: {
			enabled: true,
			ruf_ingestion: { enabled: false },
			thresholds: {},
			trusted_authserv_ids: trustedAuthservIds,
		},
		autoDraft: { enabled: false },
		raw: undefined,
	} as unknown as Awaited<ReturnType<typeof resolveMailboxSettings>>;
}

/** Default deploy for these tests: operator HAS configured a trusted authserv-id. */
const BASE_SETTINGS = makeSettings([TRUSTED_AUTHSERV]);

describe("receiveEmail — subject-match thread-auth gate (issue #463 / GHSA-m9f6-j7mm-wc4m)", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		mockedResolve.mockResolvedValue(BASE_SETTINGS);
		mockedPipeline.mockResolvedValue({ verdict: null, skipped: true } as never);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("forged splice (dmarc=fail, spf=pass, dkim=pass): NOT merged; gets its own thread_id", async () => {
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("pass", "pass", "fail"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.findThreadBySubject).not.toHaveBeenCalled();
		const [, emailArgs] = stub.createEmail.mock.calls[0] as [unknown, { id: string; thread_id: string }];
		expect(emailArgs.thread_id).not.toBe(EXISTING_THREAD_ID);
		// Own thread: a referenceless unauthenticated message threads to itself.
		expect(emailArgs.thread_id).toBe(emailArgs.id);
	});

	it("spf=pass alone: findThreadBySubject NOT called (SPF is not From-aligned)", async () => {
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("pass", "none", "none"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.findThreadBySubject).not.toHaveBeenCalled();
		const [, emailArgs] = stub.createEmail.mock.calls[0] as [unknown, { id: string; thread_id: string }];
		expect(emailArgs.thread_id).toBe(emailArgs.id);
	});

	it("dkim=pass alone: findThreadBySubject NOT called (DKIM d= is not From-aligned)", async () => {
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("none", "pass", "none"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.findThreadBySubject).not.toHaveBeenCalled();
		const [, emailArgs] = stub.createEmail.mock.calls[0] as [unknown, { id: string; thread_id: string }];
		expect(emailArgs.thread_id).toBe(emailArgs.id);
	});

	it("dmarc=pass from trusted authserv-id: findThreadBySubject IS called; thread adopted", async () => {
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("fail", "none", "pass"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.findThreadBySubject).toHaveBeenCalledOnce();
		const [, emailArgs] = stub.createEmail.mock.calls[0] as [unknown, { thread_id: string }];
		expect(emailArgs.thread_id).toBe(EXISTING_THREAD_ID);
	});

	it("dmarc=pass with empty trusted_authserv_ids (default deploy): forged Authentication-Results NOT honored", async () => {
		mockedResolve.mockResolvedValue(makeSettings([]));
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("pass", "pass", "pass"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.findThreadBySubject).not.toHaveBeenCalled();
		const [, emailArgs] = stub.createEmail.mock.calls[0] as [unknown, { id: string; thread_id: string }];
		expect(emailArgs.thread_id).toBe(emailArgs.id);
	});

	it("dmarc=pass from an UNtrusted authserv-id on a configured deploy: NOT merged", async () => {
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("pass", "pass", "pass", "attacker.example"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.findThreadBySubject).not.toHaveBeenCalled();
		const [, emailArgs] = stub.createEmail.mock.calls[0] as [unknown, { id: string; thread_id: string }];
		expect(emailArgs.thread_id).toBe(emailArgs.id);
	});

	it("unauthenticated sender (all fail): findThreadBySubject NOT called", async () => {
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

	it("quarantined + subject-matched: detachEmailFromThread IS called", async () => {
		mockedPipeline.mockResolvedValue({ verdict: { action: "quarantine", score: 80, signals: [], explanation: "" }, skipped: false } as never);
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("pass", "pass", "pass"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.moveEmail).toHaveBeenCalledWith(expect.any(String), "quarantine");
		expect(stub.detachEmailFromThread).toHaveBeenCalledOnce();
	});

	it("blocked + subject-matched: detachEmailFromThread IS called", async () => {
		mockedPipeline.mockResolvedValue({ verdict: { action: "block", score: 95, signals: [], explanation: "" }, skipped: false } as never);
		const stub = makeMailboxStub(EXISTING_THREAD_ID);
		const email = makeEmail(makeAuthHeader("pass", "pass", "pass"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.moveEmail).toHaveBeenCalledWith(expect.any(String), "quarantine");
		expect(stub.detachEmailFromThread).toHaveBeenCalledOnce();
	});

	it("quarantined without subject-match: detachEmailFromThread NOT called", async () => {
		mockedPipeline.mockResolvedValue({ verdict: { action: "quarantine", score: 80, signals: [], explanation: "" }, skipped: false } as never);
		// findThreadBySubject returns null — no subject match
		const stub = makeMailboxStub(null);
		const email = makeEmail(makeAuthHeader("pass", "pass", "pass"));
		await receiveEmail(makeNormalized(email), makeEnv(stub), makeCtx());

		expect(stub.moveEmail).toHaveBeenCalledWith(expect.any(String), "quarantine");
		expect(stub.detachEmailFromThread).not.toHaveBeenCalled();
	});
});
