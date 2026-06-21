// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// M6 (#376): passkey enrollment. First key is a single create ceremony; adding
// a 2nd+ key first requires an existing-key assertion (the register/options
// requiresStepUp handshake).

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@simplewebauthn/browser", () => ({
	startAuthentication: vi.fn(),
	startRegistration: vi.fn(),
}));
vi.mock("~/services/api", () => ({
	default: {
		webauthnRegisterOptions: vi.fn(),
		webauthnRegisterVerify: vi.fn(),
	},
}));

import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import api from "~/services/api";
import { enrollPasskey } from "~/lib/webauthn-enroll";

const regOptions = api.webauthnRegisterOptions as unknown as ReturnType<typeof vi.fn>;
const regVerify = api.webauthnRegisterVerify as unknown as ReturnType<typeof vi.fn>;
const startReg = startRegistration as unknown as ReturnType<typeof vi.fn>;
const startAuth = startAuthentication as unknown as ReturnType<typeof vi.fn>;

afterEach(() => vi.clearAllMocks());

describe("enrollPasskey", () => {
	it("enrolls the first key with a single create ceremony", async () => {
		regOptions.mockResolvedValue({ registration: { challenge: "r" } });
		const attestation = { id: "new", response: {} };
		startReg.mockResolvedValue(attestation);
		regVerify.mockResolvedValue({ verified: true, credentialId: "new", firstKey: true });

		const result = await enrollPasskey();
		expect(result.firstKey).toBe(true);
		expect(startReg).toHaveBeenCalledWith({ optionsJSON: { challenge: "r" } });
		expect(regVerify).toHaveBeenCalledWith(attestation);
		expect(startAuth).not.toHaveBeenCalled();
	});

	it("completes the existing-key step-up before enrolling a 2nd key", async () => {
		const assertion = { id: "old", response: {} };
		const attestation = { id: "new2", response: {} };
		regOptions
			.mockResolvedValueOnce({ requiresStepUp: true, authentication: { challenge: "a" } })
			.mockResolvedValueOnce({ registration: { challenge: "r2" } });
		startAuth.mockResolvedValue(assertion);
		startReg.mockResolvedValue(attestation);
		regVerify.mockResolvedValue({ verified: true, credentialId: "new2", firstKey: false });

		const result = await enrollPasskey();
		expect(result.firstKey).toBe(false);
		expect(startAuth).toHaveBeenCalledWith({ optionsJSON: { challenge: "a" } });
		// 2nd register/options call carries the existing-key assertion.
		expect(regOptions).toHaveBeenNthCalledWith(2, { stepUpAssertion: assertion });
		expect(startReg).toHaveBeenCalledWith({ optionsJSON: { challenge: "r2" } });
	});

	it("surfaces a friendly error when the create ceremony is cancelled", async () => {
		regOptions.mockResolvedValue({ registration: { challenge: "r" } });
		startReg.mockRejectedValue(
			Object.assign(new Error("not allowed"), { name: "NotAllowedError" }),
		);
		await expect(enrollPasskey()).rejects.toThrow(/cancelled|timed out/i);
		expect(regVerify).not.toHaveBeenCalled();
	});
});
