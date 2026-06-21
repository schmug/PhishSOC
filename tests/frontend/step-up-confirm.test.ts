// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// M5 (#376): the client step-up relay now runs an in-page WebAuthn assertion
// (no popup, no postMessage, no second Access app). requestStepUpConfirmation
// keeps the same signature/return type so its composer callers are unchanged.

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@simplewebauthn/browser", () => ({ startAuthentication: vi.fn() }));
vi.mock("~/services/api", () => ({
	default: {
		webauthnAuthenticateOptions: vi.fn(),
		webauthnAuthenticateVerify: vi.fn(),
	},
}));

import { startAuthentication } from "@simplewebauthn/browser";
import api from "~/services/api";
import {
	requestStepUpConfirmation,
	StepUpNoPasskeyError,
} from "~/lib/step-up-confirm";

const startAuth = startAuthentication as unknown as ReturnType<typeof vi.fn>;
const optionsMock = api.webauthnAuthenticateOptions as unknown as ReturnType<typeof vi.fn>;
const verifyMock = api.webauthnAuthenticateVerify as unknown as ReturnType<typeof vi.fn>;

const PAYLOAD = {
	tier: 2 as const,
	mailboxId: "m1",
	to: "vendor@external.com",
	subject: "Wire change",
	body: "<p>Please wire funds</p>",
	attachmentIds: [] as string[],
};

afterEach(() => {
	vi.clearAllMocks();
});

describe("requestStepUpConfirmation (WebAuthn)", () => {
	it("runs options → startAuthentication → verify and returns the token", async () => {
		optionsMock.mockResolvedValue({ challenge: "chal", allowCredentials: [{ id: "c1" }] });
		const assertion = { id: "c1", response: {} };
		startAuth.mockResolvedValue(assertion);
		verifyMock.mockResolvedValue({ token: "tok-123" });

		const token = await requestStepUpConfirmation(PAYLOAD);
		expect(token).toBe("tok-123");

		// Bound to the exact send fields (server payloadHash binding).
		expect(optionsMock).toHaveBeenCalledWith({
			mailboxId: "m1",
			tier: 2,
			payload: {
				to: "vendor@external.com",
				cc: undefined,
				bcc: undefined,
				subject: "Wire change",
				body: "<p>Please wire funds</p>",
				attachmentIds: [],
			},
		});
		expect(startAuth).toHaveBeenCalledWith({
			optionsJSON: { challenge: "chal", allowCredentials: [{ id: "c1" }] },
		});
		expect(verifyMock).toHaveBeenCalledWith(
			expect.objectContaining({ mailboxId: "m1", tier: 2, assertion }),
		);
	});

	it("throws StepUpNoPasskeyError when no credential is enrolled (and never prompts)", async () => {
		optionsMock.mockResolvedValue({ challenge: "chal", allowCredentials: [] });
		await expect(requestStepUpConfirmation(PAYLOAD)).rejects.toBeInstanceOf(StepUpNoPasskeyError);
		expect(startAuth).not.toHaveBeenCalled();
		expect(verifyMock).not.toHaveBeenCalled();
	});

	it("surfaces a user-friendly error when the assertion is cancelled, and does not verify", async () => {
		optionsMock.mockResolvedValue({ challenge: "chal", allowCredentials: [{ id: "c1" }] });
		startAuth.mockRejectedValue(
			Object.assign(new Error("The operation either timed out or was not allowed."), {
				name: "NotAllowedError",
			}),
		);
		await expect(requestStepUpConfirmation(PAYLOAD)).rejects.toThrow();
		expect(verifyMock).not.toHaveBeenCalled();
	});
});
