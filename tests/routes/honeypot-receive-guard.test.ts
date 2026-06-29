// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Regression: self-assigned `honeypot.enabled` (without operator provisioning
 * via POST /api/v1/honeypots) must NOT skip the inbound security pipeline (#24).
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Email } from "postal-mime";
import type { NormalizedInbound } from "../../workers/providers/types";
import type { Env } from "../../workers/types";

vi.mock("../../workers/lib/mailbox-settings", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../../workers/lib/mailbox-settings")>();
	return {
		...actual,
		resolveMailboxSettings: vi.fn(),
	};
});

vi.mock("../../workers/security", () => ({
	runSecurityPipeline: vi.fn(),
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

const MAILBOX_ID = "alice@acme.example.com";

function makeNormalized(): NormalizedInbound {
	return {
		kind: "mailbox",
		mailboxId: MAILBOX_ID,
		rawEmail: new ArrayBuffer(0),
		parsedEmail: {
			subject: "test",
			from: { address: "attacker@evil.example" },
			to: [{ address: MAILBOX_ID }],
			headers: [],
		} as unknown as Email,
	};
}

function makeStub() {
	return {
		createEmail: vi.fn().mockResolvedValue(undefined),
		countEmails: vi.fn().mockResolvedValue(0),
		findThreadBySubject: vi.fn().mockResolvedValue(null),
		moveEmail: vi.fn().mockResolvedValue(undefined),
		detachEmailFromThread: vi.fn().mockResolvedValue(undefined),
		recordPipelineRunStart: vi.fn().mockResolvedValue(undefined),
		recordPipelineRunComplete: vi.fn().mockResolvedValue(undefined),
		notifyNewEmail: vi.fn().mockResolvedValue(undefined),
	};
}

function makeEnv(stub: ReturnType<typeof makeStub>): Env {
	return {
		BUCKET: { head: vi.fn().mockResolvedValue({ key: `mailboxes/${MAILBOX_ID}.json` }), put: vi.fn() },
		MAILBOX: { idFromName: vi.fn().mockReturnValue("do-id"), get: vi.fn().mockReturnValue(stub) },
		EMAIL_AGENT: {
			idFromName: vi.fn().mockReturnValue("agent-id"),
			get: vi.fn().mockReturnValue({ fetch: vi.fn().mockResolvedValue(new Response("ok")) }),
		},
	} as unknown as Env;
}

function makeCtx(): ExecutionContext {
	return { waitUntil: vi.fn() } as unknown as ExecutionContext;
}

describe("receiveEmail — honeypot guard", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		mockedPipeline.mockResolvedValue({ verdict: null, skipped: true } as never);
	});

	it("does not skip the security pipeline for a self-assigned honeypot flag (no expires_at)", async () => {
		mockedResolve.mockResolvedValue({
			security: { enabled: true, ruf_ingestion: { enabled: false }, thresholds: {} },
			autoDraft: { enabled: false },
			raw: { honeypot: { enabled: true } },
		} as Awaited<ReturnType<typeof resolveMailboxSettings>>);
		const stub = makeStub();

		await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());

		expect(mockedPipeline).toHaveBeenCalled();
	});

	it("skips the security pipeline for an operator-provisioned honeypot", async () => {
		mockedResolve.mockResolvedValue({
			security: { enabled: true, ruf_ingestion: { enabled: false }, thresholds: {} },
			autoDraft: { enabled: false },
			raw: { honeypot: { enabled: true, expires_at: "2099-01-01T00:00:00Z" } },
		} as Awaited<ReturnType<typeof resolveMailboxSettings>>);
		const stub = makeStub();

		await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());

		expect(mockedPipeline).not.toHaveBeenCalled();
	});
});
