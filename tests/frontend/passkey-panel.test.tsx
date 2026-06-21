// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// M6 (#376): the settings passkey-enrollment surface.
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderWithProviders } from "./test-utils";

const feedbackSuccess = vi.fn();
const feedbackError = vi.fn();
vi.mock("~/lib/feedback", () => ({
	useFeedback: () => ({ success: feedbackSuccess, error: feedbackError, info: vi.fn() }),
}));

const enrollMock = vi.fn();
vi.mock("~/lib/webauthn-enroll", () => ({
	enrollPasskey: (...args: unknown[]) => enrollMock(...args),
}));

import { PasskeyPanel } from "~/components/PasskeyPanel";

beforeEach(() => {
	feedbackSuccess.mockReset();
	feedbackError.mockReset();
	enrollMock.mockReset();
});
afterEach(() => vi.clearAllMocks());

describe("PasskeyPanel", () => {
	it("renders an enroll affordance", () => {
		renderWithProviders(<PasskeyPanel />);
		expect(screen.getByTestId("enroll-passkey-button")).toHaveTextContent(/add a passkey/i);
	});

	it("enrolls and shows a first-key success message", async () => {
		enrollMock.mockResolvedValue({ firstKey: true });
		const user = userEvent.setup();
		renderWithProviders(<PasskeyPanel />);
		await user.click(screen.getByTestId("enroll-passkey-button"));
		await waitFor(() => expect(enrollMock).toHaveBeenCalled());
		await waitFor(() =>
			expect(feedbackSuccess).toHaveBeenCalledWith(expect.stringMatching(/passkey enrolled/i)),
		);
	});

	it("surfaces an enrollment error", async () => {
		enrollMock.mockRejectedValue(new Error("This authenticator is already registered for your account."));
		const user = userEvent.setup();
		renderWithProviders(<PasskeyPanel />);
		await user.click(screen.getByTestId("enroll-passkey-button"));
		await waitFor(() =>
			expect(feedbackError).toHaveBeenCalledWith(expect.stringMatching(/already registered/i)),
		);
	});
});
