// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * `receiveEmail` returns { messageId, verdict } instead of void (issue #31),
 * and sidecar mailboxes (Task 1's `settings.sidecar` block) skip auto-draft
 * dispatch — replies happen in the tenant's own inbox, not PhishSOC.
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

/**
 * Matches the shape `resolveMailboxSettings` resolves to (see
 * tests/routes/honeypot-receive-guard.test.ts), extended with `raw` /
 * `autoDraft` overrides for the sidecar / auto-draft assertions below.
 */
function makeResolvedSettings(overrides: {
	raw?: Record<string, unknown>;
	autoDraft?: { enabled: boolean };
}): Awaited<ReturnType<typeof resolveMailboxSettings>> {
	return {
		security: { enabled: true, ruf_ingestion: { enabled: false }, thresholds: {} },
		autoDraft: overrides.autoDraft ?? { enabled: false },
		raw: overrides.raw ?? {},
	} as Awaited<ReturnType<typeof resolveMailboxSettings>>;
}

describe("receiveEmail result value (issue #31)", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		mockedResolve.mockResolvedValue(makeResolvedSettings({}));
		mockedPipeline.mockResolvedValue({ verdict: null, skipped: true, stageTrace: [] } as never);
	});

	it("returns { messageId, verdict } when the pipeline runs", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		mockedResolve.mockResolvedValue(makeResolvedSettings({}));
		mockedPipeline.mockResolvedValue({
			verdict: { action: "quarantine", score: 80, explanation: "x", signals: [], confidence: 0.9 },
			skipped: false,
			stageTrace: [],
		} as never);

		const result = await receiveEmail(makeNormalized(), env, makeCtx());

		expect(result).not.toBeNull();
		expect(result!.verdict?.action).toBe("quarantine");
		expect(typeof result!.messageId).toBe("string");
	});

	it("returns null for an unknown mailbox (no settings blob)", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		(env.BUCKET.head as ReturnType<typeof vi.fn>).mockResolvedValue(null);

		const result = await receiveEmail(makeNormalized(), env, makeCtx());

		expect(result).toBeNull();
	});

	it("persists the provider-native message id on the email row (#593 dedupe fallback)", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);

		await receiveEmail({ ...makeNormalized(), providerMessageId: "gmail-123" }, env, makeCtx());

		expect(stub.createEmail).toHaveBeenCalledWith(
			expect.anything(),
			expect.objectContaining({ provider_message_id: "gmail-123" }),
			expect.anything(),
		);
	});

	it("leaves provider_message_id null for providers without a native id (CF Email Routing)", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);

		await receiveEmail(makeNormalized(), env, makeCtx());

		expect(stub.createEmail).toHaveBeenCalledWith(
			expect.anything(),
			expect.objectContaining({ provider_message_id: null }),
			expect.anything(),
		);
	});

	it("skips auto-draft dispatch when the mailbox has a sidecar block", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		mockedResolve.mockResolvedValue(
			makeResolvedSettings({
				raw: { sidecar: { provider: "workspace", credentials_secret_name: "SIDECAR_SECRET_x" } },
				autoDraft: { enabled: true },
			}),
		);
		mockedPipeline.mockResolvedValue({ verdict: null, skipped: true, stageTrace: [] } as never);

		await receiveEmail(makeNormalized(), env, makeCtx());

		// EMAIL_AGENT.get must never be called for a sidecar mailbox.
		expect(env.EMAIL_AGENT.get).not.toHaveBeenCalled();
	});
});
