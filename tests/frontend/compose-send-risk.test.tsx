// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Acceptance tests for issue #263 (composer send-risk UI) and the composer
 * step-up confirm flow (#285, reworked for #376).
 *
 * #263: Tier 0/1/2 button labels, data-testid attributes, preflight
 *       network-failure fallback, and Tier-2 phrase confirmation.
 * step-up: the composer calls requestStepUpConfirmation (now an in-page
 *       WebAuthn assertion — its internals are unit-tested in
 *       step-up-confirm.test.ts) and threads the returned one-shot token into
 *       the send as x-confirmation-token. These tests mock the relay to assert
 *       the composer's contract: correct payload in, token threaded out,
 *       graceful failure, phrase gate first.
 */

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import { renderWithProviders } from "./test-utils";

// ── hoisted mocks ─────────────────────────────────────────────────────────────

const feedbackInfo = vi.fn();
const feedbackError = vi.fn();
const feedbackSuccess = vi.fn();

vi.mock("~/lib/feedback", () => ({
	useFeedback: () => ({
		info: feedbackInfo,
		error: feedbackError,
		success: feedbackSuccess,
	}),
}));

vi.mock("~/services/api", async () => {
	const actual = await vi.importActual<typeof import("~/services/api")>(
		"~/services/api",
	);
	return {
		...actual,
		default: { ...actual.default, preflightEmail: vi.fn() },
	};
});

// The step-up relay (WebAuthn assertion) is mocked here; its real internals are
// covered by step-up-confirm.test.ts. The composer only owns calling it with
// the exact send payload and threading the token (or failing gracefully).
const stepUpMock = vi.fn();
vi.mock("~/lib/step-up-confirm", () => ({
	requestStepUpConfirmation: (...args: unknown[]) => stepUpMock(...args),
	StepUpNoPasskeyError: class StepUpNoPasskeyError extends Error {},
}));

// Stable spies so we can assert the x-confirmation-token is threaded through.
const sendEmailMutate = vi.fn().mockResolvedValue(undefined);
const replyMutate = vi.fn().mockResolvedValue(undefined);
const forwardMutate = vi.fn().mockResolvedValue(undefined);
const deleteEmailMutate = vi.fn();

vi.mock("~/queries/emails", () => ({
	useSendEmail: () => ({ mutateAsync: sendEmailMutate }),
	useSaveDraft: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useReplyToEmail: () => ({ mutateAsync: replyMutate }),
	useForwardEmail: () => ({ mutateAsync: forwardMutate }),
	useDeleteEmail: () => ({ mutate: deleteEmailMutate }),
}));

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({
		data: {
			id: "m1",
			email: "operator@internal.test",
			name: "Operator",
			settings: {},
		},
	}),
}));

// Tiptap/ProseMirror doesn't run in jsdom — replace with a no-op.
vi.mock("~/components/RichTextEditor", () => ({
	default: () => null,
}));

// ── deferred imports (after mocks are registered) ────────────────────────────

import ComposePanel from "~/components/ComposePanel";
import ComposeEmail from "~/components/ComposeEmail";
import api from "~/services/api";
import { useUIStore } from "~/hooks/useUIStore";

const preflightMock = api.preflightEmail as unknown as ReturnType<typeof vi.fn>;

// ── helpers ───────────────────────────────────────────────────────────────────

function renderPanel() {
	return renderWithProviders(
		<Routes>
			<Route path="/mailbox/:mailboxId" element={<ComposePanel />} />
		</Routes>,
		{ initialEntries: ["/mailbox/m1"] },
	);
}

function renderModal() {
	useUIStore.getState().openComposeModal();
	return renderWithProviders(
		<Routes>
			<Route path="/mailbox/:mailboxId" element={<ComposeEmail />} />
		</Routes>,
		{ initialEntries: ["/mailbox/m1"] },
	);
}

/** Type into the "To" field and wait for the debounce to settle (≤2 s). */
async function typeToAndWaitForPreflight(
	user: ReturnType<typeof userEvent.setup>,
	address: string,
	expectedTestId: string,
) {
	await user.type(screen.getByPlaceholderText(/recipient@example.com/i), address);
	await waitFor(
		() => expect(screen.getByTestId(expectedTestId)).toBeInTheDocument(),
		{ timeout: 2000 },
	);
}

// ── test suite ────────────────────────────────────────────────────────────────

describe("Composer send-risk UI (#263)", () => {
	beforeEach(() => {
		preflightMock.mockReset();
		feedbackInfo.mockReset();
		feedbackError.mockReset();
		feedbackSuccess.mockReset();
		stepUpMock.mockReset();
		sendEmailMutate.mockReset().mockResolvedValue(undefined);
		replyMutate.mockReset().mockResolvedValue(undefined);
		forwardMutate.mockReset().mockResolvedValue(undefined);
		deleteEmailMutate.mockReset();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
		useUIStore.getState().closeComposeModal();
	});

	// ── Acceptance: button labels per tier ───────────────────────────────────

	describe("Send button label by tier", () => {
		it("shows 'Send' with data-testid tier0 before preflight fires", () => {
			preflightMock.mockResolvedValue({ tier: 0, reasons: [] });
			renderPanel();
			const btn = screen.getByTestId("send-button-tier0");
			expect(btn).toBeInTheDocument();
			expect(btn).toHaveTextContent("Send");
		});

		it("shows 'Send (re-auth)' with data-testid tier1 when preflight returns tier 1", async () => {
			preflightMock.mockResolvedValue({
				tier: 1,
				reasons: ["External recipient"],
			});
			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier1");
			expect(screen.getByTestId("send-button-tier1")).toHaveTextContent("Send (re-auth)");
		});

		it("shows 'Send (verify)' with data-testid tier2 when preflight returns tier 2", async () => {
			preflightMock.mockResolvedValue({
				tier: 2,
				reasons: ["BEC/credential keyword"],
			});
			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier2");
			expect(screen.getByTestId("send-button-tier2")).toHaveTextContent("Send (verify)");
		});
	});

	// ── Regression: preflight normalises multi-address Cc/Bcc to arrays ───────
	// A comma-joined Bcc string fails per-address email validation server-side
	// (ZodError → 500); the live preview must send the same array the send does.

	describe("Preflight recipient normalisation", () => {
		it("sends a multi-address Bcc as an array, not a comma-joined string", async () => {
			preflightMock.mockResolvedValue({ tier: 0, reasons: [] });
			const user = userEvent.setup();
			renderPanel();

			await user.type(
				screen.getByPlaceholderText(/recipient@example.com/i),
				"primary@example.com",
			);
			await user.click(screen.getByRole("button", { name: /cc \/ bcc/i }));
			await user.type(
				screen.getByLabelText(/^BCC$/i),
				"one@example.com, two@example.com",
			);

			await waitFor(() => expect(preflightMock).toHaveBeenCalled(), { timeout: 2000 });

			const lastCall = preflightMock.mock.calls.at(-1);
			const payload = lastCall?.[1] as { to: unknown; bcc: unknown };
			expect(payload.to).toBe("primary@example.com");
			expect(payload.bcc).toEqual(["one@example.com", "two@example.com"]);
		});
	});

	// ── Acceptance: preflight network failure does not block send ────────────

	describe("Preflight network failure fallback", () => {
		it("stays on tier0 button when preflight throws a network error", async () => {
			preflightMock.mockRejectedValue(new Error("network error"));
			const user = userEvent.setup();
			renderPanel();
			await user.type(
				screen.getByPlaceholderText(/recipient@example.com/i),
				"vendor@external.com",
			);
			await waitFor(
				() => expect(preflightMock).toHaveBeenCalled(),
				{ timeout: 2000 },
			);
			expect(screen.getByTestId("send-button-tier0")).toBeInTheDocument();
			expect(screen.queryByTestId("send-button-tier1")).not.toBeInTheDocument();
		});
	});

	// ── Acceptance: Tier-2 confirmation phrase ───────────────────────────────

	describe("Tier-2 confirmation phrase", () => {
		it("renders the phrase input when tier is 2", async () => {
			preflightMock.mockResolvedValue({ tier: 2, reasons: ["BEC keyword"] });
			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier2");
			expect(screen.getByTestId("confirm-phrase-input")).toBeInTheDocument();
		});

		it("does not render the phrase input when tier is 1", async () => {
			preflightMock.mockResolvedValue({ tier: 1, reasons: ["External recipient"] });
			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier1");
			expect(screen.queryByTestId("confirm-phrase-input")).not.toBeInTheDocument();
		});

		it("shows an error when the form is submitted with the wrong phrase", async () => {
			preflightMock.mockResolvedValue({ tier: 2, reasons: ["BEC keyword"] });
			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier2");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Hello");
			await user.type(screen.getByTestId("confirm-phrase-input"), "wrong@addr.com");
			await user.click(screen.getByTestId("send-button-tier2"));
			expect(
				screen.getByText(/type.*vendor@external\.com.*to confirm.*before sending/i),
			).toBeInTheDocument();
			// Phrase gate must block before the step-up ever runs.
			expect(stepUpMock).not.toHaveBeenCalled();
			expect(sendEmailMutate).not.toHaveBeenCalled();
		});
	});

	// ── Tier-1 step-up: WebAuthn relay threads the token ──────────────────────

	describe("Tier-1 step-up (WebAuthn)", () => {
		it("runs the step-up with the exact send payload and sends with x-confirmation-token", async () => {
			preflightMock.mockResolvedValue({ tier: 1, reasons: ["External recipient"] });
			stepUpMock.mockResolvedValue("tok-tier1");

			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier1");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Hello");
			await user.click(screen.getByTestId("send-button-tier1"));

			await waitFor(() => expect(sendEmailMutate).toHaveBeenCalled());
			expect(sendEmailMutate).toHaveBeenCalledWith(
				expect.objectContaining({ mailboxId: "m1", confirmationToken: "tok-tier1" }),
			);

			// The step-up payload must carry the exact send fields so the server
			// payloadHash binding holds.
			expect(stepUpMock).toHaveBeenCalledWith(
				expect.objectContaining({
					tier: 1,
					mailboxId: "m1",
					to: "vendor@external.com",
					subject: "Hello",
				}),
			);
			const sent = sendEmailMutate.mock.calls[0][0] as {
				email: { to: unknown; subject: string; html: string };
			};
			const stepUpArg = stepUpMock.mock.calls[0][0] as {
				to: unknown;
				subject: string;
				body: string;
			};
			expect(stepUpArg.to).toEqual(sent.email.to);
			expect(stepUpArg.subject).toBe(sent.email.subject);
			expect(stepUpArg.body).toBe(sent.email.html);
			expect(feedbackSuccess).toHaveBeenCalledWith("Email sent!");
		});
	});

	// ── Tier-2 step-up: phrase gate first, then WebAuthn relay ────────────────

	describe("Tier-2 step-up (WebAuthn)", () => {
		it("enforces the phrase, then runs the step-up and sends", async () => {
			preflightMock.mockResolvedValue({ tier: 2, reasons: ["BEC keyword"] });
			stepUpMock.mockResolvedValue("tok-tier2");

			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier2");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Wire change");
			await user.type(
				screen.getByTestId("confirm-phrase-input"),
				"vendor@external.com",
			);
			await user.click(screen.getByTestId("send-button-tier2"));

			await waitFor(() => expect(stepUpMock).toHaveBeenCalled());
			await waitFor(() => expect(sendEmailMutate).toHaveBeenCalled());
			expect(sendEmailMutate).toHaveBeenCalledWith(
				expect.objectContaining({ confirmationToken: "tok-tier2" }),
			);
		});
	});

	// ── step-up failure handling ──────────────────────────────────────────────

	describe("Step-up failure handling", () => {
		it("surfaces a step-up error, does not send, and re-enables the button", async () => {
			preflightMock.mockResolvedValue({ tier: 1, reasons: ["External recipient"] });
			stepUpMock.mockRejectedValue(new Error("invalid or expired confirmation token"));

			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier1");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Hello");
			await user.click(screen.getByTestId("send-button-tier1"));

			await waitFor(() =>
				expect(feedbackError).toHaveBeenCalledWith(
					expect.stringMatching(/invalid or expired confirmation token/i),
				),
			);
			expect(sendEmailMutate).not.toHaveBeenCalled();
			await waitFor(() =>
				expect(screen.getByTestId("send-button-tier1")).not.toBeDisabled(),
			);
		});
	});

	// ── second render path (modal) ────────────────────────────────────────────

	describe("ComposeEmail modal render path", () => {
		it("runs the same step-up relay from the modal surface", async () => {
			preflightMock.mockResolvedValue({ tier: 1, reasons: ["External recipient"] });
			stepUpMock.mockResolvedValue("tok-modal");

			const user = userEvent.setup();
			renderModal();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier1");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Hello");
			await user.click(screen.getByTestId("send-button-tier1"));

			await waitFor(() => expect(sendEmailMutate).toHaveBeenCalled());
			expect(sendEmailMutate).toHaveBeenCalledWith(
				expect.objectContaining({ confirmationToken: "tok-modal" }),
			);
		});
	});
});
