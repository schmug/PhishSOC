// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * receiveEmail-level regression for RUF (DMARC forensic report) fall-through
 * to the security pipeline (issue #409).
 *
 * PR #406 fixed a bypass in the RUF divert block of `receiveEmail`: the early
 * `return` is now conditional on *successful* ingest. This suite pins that
 * control-flow so a future refactor cannot reintroduce an unconditional return:
 *
 *   - disabled ingest → security pipeline runs (email classified)
 *   - enabled but ingestDmarcRuf returns { ingested: false } → pipeline runs
 *   - enabled but ingestDmarcRuf throws → pipeline runs
 *   - successful ingest (ingested: true) → archived; pipeline does NOT run
 *
 * The real `isDmarcRuf()` heuristic runs on a genuine `message/feedback-report`
 * fixture so the test validates both halves of the fix together.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Attachment, Email } from "postal-mime";
import type { NormalizedInbound } from "../../workers/providers/types";
import type { Env } from "../../workers/types";

// ── Module mocks (hoisted before any module graph is evaluated) ───────────────

vi.mock("../../workers/lib/mailbox-settings", () => ({
	resolveMailboxSettings: vi.fn(),
	stripDefaultEqual: <T>(x: T) => x,
	YaraMailScannerSettings: { parse: (x: unknown) => x },
}));

vi.mock("../../workers/security", () => ({
	runSecurityPipeline: vi.fn(),
}));

// Preserve real isDmarcRuf / isDmarcReport / isTlsRptReport — they run on the
// genuine fixture to validate the heuristic half of the fix too.
vi.mock("../../workers/dmarc/ingest", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../../workers/dmarc/ingest")>();
	return { ...actual, ingestDmarcRuf: vi.fn() };
});

vi.mock("../../workers/intel/deep-scan", () => ({
	runDeepScan: vi.fn().mockResolvedValue({ added_score: 0, final_action: "allow", reasons: [] }),
}));

vi.mock("../../workers/security/yaramail-signal", () => ({
	fireYaraScan: vi.fn().mockResolvedValue(undefined),
}));

// ── Imports resolved after mocks are in place ─────────────────────────────────

import { receiveEmail } from "../../workers/index";
import { resolveMailboxSettings } from "../../workers/lib/mailbox-settings";
import { runSecurityPipeline } from "../../workers/security";
import { ingestDmarcRuf } from "../../workers/dmarc/ingest";
import { Folders } from "../../shared/folders";

const mockedResolve = vi.mocked(resolveMailboxSettings);
const mockedPipeline = vi.mocked(runSecurityPipeline);
const mockedIngest = vi.mocked(ingestDmarcRuf);

// ── Helpers ───────────────────────────────────────────────────────────────────

const MAILBOX_ID = "security@example.com";

function enc(text: string): ArrayBuffer {
	return new TextEncoder().encode(text).buffer as ArrayBuffer;
}

const ARF_BODY = [
	"Feedback-Type: auth-failure",
	"User-Agent: TestReporter/1.0",
	"Version: 1",
	"Original-Mail-From: attacker@evil.example",
	"Source-IP: 198.51.100.7",
	"Reported-Domain: example.com",
].join("\r\n");

/** Genuine RUF email: subject doesn't match aggregate-report heuristics and
 *  the `message/feedback-report` attachment satisfies `isDmarcRuf()`. */
function makeRufEmail(): Email {
	return {
		subject: "DMARC Failure Report",
		from: { address: "noreply@reporter.example", name: "Reporter" },
		to: [{ address: MAILBOX_ID, name: "" }],
		attachments: [
			{
				mimeType: "message/feedback-report",
				content: enc(ARF_BODY),
				filename: "report.eml",
				disposition: "attachment",
				headers: [],
			} as unknown as Attachment,
		],
		headers: [],
	} as unknown as Email;
}

function makeNormalized(): NormalizedInbound {
	return {
		rawEmail: new ArrayBuffer(0),
		parsedEmail: makeRufEmail(),
		mailboxId: MAILBOX_ID,
	};
}

function makeMailboxStub() {
	return {
		createEmail: vi.fn().mockResolvedValue(undefined),
		moveEmail: vi.fn().mockResolvedValue(undefined),
		findThreadBySubject: vi.fn().mockResolvedValue(null),
		recordPipelineRunStart: vi.fn().mockResolvedValue(undefined),
		recordPipelineRunComplete: vi.fn().mockResolvedValue(undefined),
		notifyNewEmail: vi.fn().mockResolvedValue(undefined),
	};
}

function makeEnv(stub: ReturnType<typeof makeMailboxStub>): Env {
	return {
		BUCKET: {
			head: vi.fn().mockResolvedValue({ key: `mailboxes/${MAILBOX_ID}.json` }),
			put: vi.fn().mockResolvedValue(undefined),
		},
		MAILBOX: {
			idFromName: vi.fn().mockReturnValue("do-id"),
			get: vi.fn().mockReturnValue(stub),
		},
		EMAIL_AGENT: {
			idFromName: vi.fn().mockReturnValue("agent-id"),
			get: vi.fn().mockReturnValue({
				fetch: vi.fn().mockResolvedValue(new Response("ok")),
			}),
		},
	} as unknown as Env;
}

function makeCtx(): ExecutionContext {
	return { waitUntil: vi.fn() } as unknown as ExecutionContext;
}

/** Build the settings object returned by the mocked resolveMailboxSettings. */
function makeSettings(rufEnabled: boolean) {
	return {
		security: {
			enabled: true,
			ruf_ingestion: { enabled: rufEnabled, retain_raw: false },
			thresholds: {},
		},
		autoDraft: { enabled: false },
		raw: undefined,
	} as unknown as Awaited<ReturnType<typeof resolveMailboxSettings>>;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("receiveEmail — RUF fall-through to security pipeline (issue #409)", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		// Default pipeline mock: null verdict so no quarantine move fires.
		mockedPipeline.mockResolvedValue({ verdict: null, skipped: true } as never);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("disabled ingest: runSecurityPipeline IS invoked when ruf_ingestion.enabled is false", async () => {
		mockedResolve.mockResolvedValue(makeSettings(false));

		const stub = makeMailboxStub();
		await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());

		expect(mockedPipeline).toHaveBeenCalledOnce();
		expect(stub.moveEmail).not.toHaveBeenCalledWith(expect.any(String), Folders.ARCHIVE);
	});

	it("failed ingest (ingested: false): runSecurityPipeline IS invoked", async () => {
		mockedResolve.mockResolvedValue(makeSettings(true));
		mockedIngest.mockResolvedValue({ ingested: false, reason: "rate-limited" });

		const stub = makeMailboxStub();
		await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());

		expect(mockedPipeline).toHaveBeenCalledOnce();
		expect(stub.moveEmail).not.toHaveBeenCalledWith(expect.any(String), Folders.ARCHIVE);
	});

	it("failed ingest (throws): runSecurityPipeline IS invoked", async () => {
		mockedResolve.mockResolvedValue(makeSettings(true));
		mockedIngest.mockRejectedValue(new Error("ingest DB error"));

		const stub = makeMailboxStub();
		await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());

		expect(mockedPipeline).toHaveBeenCalledOnce();
		expect(stub.moveEmail).not.toHaveBeenCalledWith(expect.any(String), Folders.ARCHIVE);
	});

	it("successful ingest: email is archived and runSecurityPipeline is NOT invoked", async () => {
		mockedResolve.mockResolvedValue(makeSettings(true));
		mockedIngest.mockResolvedValue({ ingested: true });

		const stub = makeMailboxStub();
		await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());

		expect(stub.moveEmail).toHaveBeenCalledWith(expect.any(String), Folders.ARCHIVE);
		expect(mockedPipeline).not.toHaveBeenCalled();
	});
});
