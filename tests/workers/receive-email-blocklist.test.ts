// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sender blocklist enforcement in `receiveEmail`
 * (spec docs/superpowers/specs/2026-09-27-sender-blocklist-design.md):
 * drop/reject stop before storage, spam files to Spam and still runs the
 * pipeline, and any settings failure fails open. Harness copied from
 * receive-email-result.test.ts.
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
		appendBlockedLog: vi.fn().mockResolvedValue(undefined),
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

/**
 * Matches the shape `resolveMailboxSettings` resolves to (see
 * tests/routes/honeypot-receive-guard.test.ts), extended with `raw` /
 * `autoDraft` overrides for the sidecar / auto-draft assertions below.
 */
function makeResolvedSettings(overrides: {
	raw?: Record<string, unknown>;
	autoDraft?: { enabled: boolean };
	domain?: Record<string, unknown>;
	org?: Record<string, unknown>;
}): Awaited<ReturnType<typeof resolveMailboxSettings>> {
	return {
		security: { enabled: true, ruf_ingestion: { enabled: false }, thresholds: {} },
		autoDraft: overrides.autoDraft ?? { enabled: false },
		raw: overrides.raw ?? {},
		domain: overrides.domain,
		org: overrides.org,
	} as Awaited<ReturnType<typeof resolveMailboxSettings>>;
}
const DROP = { id: "r-drop", match: "evil.example", action: "drop", created_at: "t" };
const REJECT = { id: "r-rej", match: "evil.example", action: "reject", reason: "Go away", created_at: "t" };
const SPAM = { id: "r-spam", match: "attacker@evil.example", action: "spam", created_at: "t" };

describe("receiveEmail sender blocklist", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		mockedPipeline.mockResolvedValue({ verdict: null, skipped: true, stageTrace: [] } as never);
	});

	it("drop: stores nothing, writes one audit row", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		mockedResolve.mockResolvedValue(makeResolvedSettings({ raw: { blocklist: [DROP] } }));
		const res = await receiveEmail(makeNormalized(), env, makeCtx());
		expect(res?.blocked).toMatchObject({ action: "drop", ruleId: "r-drop", tier: "mailbox" });
		expect(stub.createEmail).not.toHaveBeenCalled();
		expect(env.BUCKET.put).not.toHaveBeenCalled();
		expect(mockedPipeline).not.toHaveBeenCalled();
		expect(stub.appendBlockedLog).toHaveBeenCalledOnce();
	});

	it("reject: returns the reason for setReject", async () => {
		const stub = makeStub();
		mockedResolve.mockResolvedValue(makeResolvedSettings({ raw: { blocklist: [REJECT] } }));
		const res = await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());
		expect(res?.blocked).toEqual({ action: "reject", ruleId: "r-rej", tier: "mailbox", reason: "Go away" });
		expect(stub.createEmail).not.toHaveBeenCalled();
	});

	it("reject on a sidecar mailbox downgrades to drop", async () => {
		const stub = makeStub();
		mockedResolve.mockResolvedValue(makeResolvedSettings({ raw: { blocklist: [REJECT] } }));
		const res = await receiveEmail({ ...makeNormalized(), providerMessageId: "g-1" }, makeEnv(stub), makeCtx());
		expect(res?.blocked?.action).toBe("drop");
		expect(res?.blocked?.reason).toBeUndefined();
	});

	it("an audit write failure still drops", async () => {
		const stub = makeStub();
		stub.appendBlockedLog.mockRejectedValue(new Error("do down"));
		mockedResolve.mockResolvedValue(makeResolvedSettings({ raw: { blocklist: [DROP] } }));
		const res = await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());
		expect(res?.blocked?.action).toBe("drop");
		expect(stub.createEmail).not.toHaveBeenCalled();
	});

	it("spam: stores in Spam with the rule, runs the pipeline with targetFolder spam, no auto-draft", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		mockedResolve.mockResolvedValue(makeResolvedSettings({ raw: { blocklist: [SPAM] }, autoDraft: { enabled: true } }));
		const res = await receiveEmail(makeNormalized(), env, makeCtx());
		expect(res?.blocked).toBeUndefined();
		expect(stub.createEmail).toHaveBeenCalledWith(
			"spam",
			expect.objectContaining({ blocked_by_rule: JSON.stringify({ id: "r-spam", match: "attacker@evil.example", tier: "mailbox" }) }),
			expect.anything(),
		);
		expect(mockedPipeline).toHaveBeenCalledWith(expect.objectContaining({ targetFolder: "spam" }));
		expect(stub.notifyNewEmail).toHaveBeenCalledWith(expect.any(String), "spam");
		expect(env.EMAIL_AGENT.get).not.toHaveBeenCalled();
	});

	it("spam + pipeline quarantine escalates to Quarantine", async () => {
		const stub = makeStub();
		mockedResolve.mockResolvedValue(makeResolvedSettings({ raw: { blocklist: [SPAM] } }));
		mockedPipeline.mockResolvedValue({
			verdict: { action: "quarantine", score: 80, explanation: "x", signals: [], confidence: 0.9 },
			skipped: false, stageTrace: [],
		} as never);
		await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());
		expect(stub.moveEmail).toHaveBeenCalledWith(expect.any(String), "quarantine");
	});

	it("fails open when resolved settings lack domain/org and a settings read throws", async () => {
		const stub = makeStub();
		mockedResolve.mockRejectedValueOnce(new Error("r2 down")).mockResolvedValue(makeResolvedSettings({}));
		const res = await receiveEmail(makeNormalized(), makeEnv(stub), makeCtx());
		expect(res?.blocked).toBeUndefined();
		expect(stub.createEmail).toHaveBeenCalledWith("inbox", expect.anything(), expect.anything());
	});
});
