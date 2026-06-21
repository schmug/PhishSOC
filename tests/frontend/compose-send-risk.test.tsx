// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Acceptance tests for issue #263 (composer send-risk UI) and issue #285
 * (composer step-up confirm flow).
 *
 * #263: Tier 0/1/2 button labels, data-testid attributes, preflight
 *       network-failure fallback, and Tier-2 phrase confirmation.
 * #285: Tier 1 / Tier 2 popup + postMessage step-up relay, replay/expiry
 *       errors, popup-blocked / popup-closed graceful failure, and the
 *       x-confirmation-token resend on both composer surfaces.
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

// ── popup harness ─────────────────────────────────────────────────────────────

type FakePopup = {
	closed: boolean;
	close: ReturnType<typeof vi.fn>;
	postMessage: ReturnType<typeof vi.fn<(message: unknown, targetOrigin: string) => void>>;
	focus: ReturnType<typeof vi.fn>;
};

function makeFakePopup(): FakePopup {
	const popup: FakePopup = {
		closed: false,
		close: vi.fn(() => {
			popup.closed = true;
		}),
		postMessage: vi.fn<(message: unknown, targetOrigin: string) => void>(),
		focus: vi.fn(),
	};
	return popup;
}

const ORIGIN = window.location.origin;

/** Dispatch a message as if it came from the relay popup. */
function postFromRelay(data: unknown) {
	window.dispatchEvent(
		new MessageEvent("message", { data, origin: ORIGIN }),
	);
}

/**
 * Drive the relay popup to a successful token handshake. Returns the nonce
 * the opener generated (read off the payload it posted into the popup).
 */
async function completeRelayHandshake(popup: FakePopup, token: string) {
	// Opener registers its listener and waits for "ready".
	postFromRelay({ source: "phishsoc-confirm", type: "ready" });
	await waitFor(() => expect(popup.postMessage).toHaveBeenCalled());
	const payloadMsg = popup.postMessage.mock.calls[0][0] as {
		nonce: string;
		payload: unknown;
	};
	postFromRelay({
		source: "phishsoc-confirm",
		type: "token",
		nonce: payloadMsg.nonce,
		token,
	});
	return payloadMsg;
}

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
			// Phrase gate must block before the popup ever opens.
			expect(sendEmailMutate).not.toHaveBeenCalled();
		});
	});

	// ── #285: Tier-1 step-up relay ────────────────────────────────────────────

	describe("Tier-1 step-up confirm relay (#285)", () => {
		it("opens the confirm popup, relays the token, and sends with x-confirmation-token", async () => {
			preflightMock.mockResolvedValue({ tier: 1, reasons: ["External recipient"] });
			const popup = makeFakePopup();
			const openSpy = vi.fn(() => popup as unknown as Window);
			vi.stubGlobal("open", openSpy);

			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier1");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Hello");
			await user.click(screen.getByTestId("send-button-tier1"));

			await waitFor(() => expect(openSpy).toHaveBeenCalled());
			expect(openSpy).toHaveBeenCalledWith(
				"/api/v1/confirm",
				expect.any(String),
				expect.any(String),
			);

			const payloadMsg = await completeRelayHandshake(popup, "tok-tier1");

			await waitFor(() => expect(sendEmailMutate).toHaveBeenCalled());
			expect(sendEmailMutate).toHaveBeenCalledWith(
				expect.objectContaining({
					mailboxId: "m1",
					confirmationToken: "tok-tier1",
				}),
			);
			// Payload posted into the popup must carry the exact send fields
			// so the server payloadHash binding holds.
			const sent = sendEmailMutate.mock.calls[0][0] as {
				email: { to: unknown; subject: string; html: string };
			};
			const relayed = (payloadMsg.payload as {
				to: unknown;
				subject: string;
				body: string;
				attachmentIds: string[];
			});
			expect(relayed.to).toEqual(sent.email.to);
			expect(relayed.subject).toBe(sent.email.subject);
			expect(relayed.body).toBe(sent.email.html);
			expect(relayed.attachmentIds).toEqual([]);
			expect(feedbackSuccess).toHaveBeenCalledWith("Email sent!");
		});
	});

	// ── #285: Tier-2 step-up relay (phrase gate first) ───────────────────────

	describe("Tier-2 step-up confirm relay (#285)", () => {
		it("enforces the phrase, then runs the popup flow and sends", async () => {
			preflightMock.mockResolvedValue({ tier: 2, reasons: ["BEC keyword"] });
			const popup = makeFakePopup();
			const openSpy = vi.fn(() => popup as unknown as Window);
			vi.stubGlobal("open", openSpy);

			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier2");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Wire change");
			await user.type(
				screen.getByTestId("confirm-phrase-input"),
				"vendor@external.com",
			);
			await user.click(screen.getByTestId("send-button-tier2"));

			await waitFor(() => expect(openSpy).toHaveBeenCalled());
			await completeRelayHandshake(popup, "tok-tier2");

			await waitFor(() => expect(sendEmailMutate).toHaveBeenCalled());
			expect(sendEmailMutate).toHaveBeenCalledWith(
				expect.objectContaining({ confirmationToken: "tok-tier2" }),
			);
		});
	});

	// ── #285: error + edge handling ──────────────────────────────────────────

	describe("Step-up relay error handling (#285)", () => {
		it("surfaces a replayed/expired token error and does not send", async () => {
			preflightMock.mockResolvedValue({ tier: 1, reasons: ["External recipient"] });
			const popup = makeFakePopup();
			vi.stubGlobal("open", vi.fn(() => popup as unknown as Window));

			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier1");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Hello");
			await user.click(screen.getByTestId("send-button-tier1"));

			postFromRelay({ source: "phishsoc-confirm", type: "ready" });
			await waitFor(() => expect(popup.postMessage).toHaveBeenCalled());
			const nonce = (popup.postMessage.mock.calls[0][0] as { nonce: string }).nonce;
			postFromRelay({
				source: "phishsoc-confirm",
				type: "error",
				nonce,
				error: "invalid or expired confirmation token",
			});

			await waitFor(() =>
				expect(feedbackError).toHaveBeenCalledWith(
					expect.stringMatching(/invalid or expired confirmation token/i),
				),
			);
			expect(sendEmailMutate).not.toHaveBeenCalled();
			// isSending must not stick — the send button is interactive again.
			await waitFor(() =>
				expect(screen.getByTestId("send-button-tier1")).not.toBeDisabled(),
			);
		});

		it("fails gracefully when the popup is blocked (window.open returns null)", async () => {
			preflightMock.mockResolvedValue({ tier: 1, reasons: ["External recipient"] });
			vi.stubGlobal("open", vi.fn(() => null));

			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier1");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Hello");
			await user.click(screen.getByTestId("send-button-tier1"));

			await waitFor(() =>
				expect(feedbackError).toHaveBeenCalledWith(
					expect.stringMatching(/popup|blocked/i),
				),
			);
			expect(sendEmailMutate).not.toHaveBeenCalled();
			await waitFor(() =>
				expect(screen.getByTestId("send-button-tier1")).not.toBeDisabled(),
			);
		});

		it("fails gracefully when the popup is closed before completing auth", async () => {
			preflightMock.mockResolvedValue({ tier: 1, reasons: ["External recipient"] });
			const popup = makeFakePopup();
			popup.closed = true; // closed/blocked-as-window immediately
			vi.stubGlobal("open", vi.fn(() => popup as unknown as Window));

			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier1");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Hello");
			await user.click(screen.getByTestId("send-button-tier1"));

			await waitFor(
				() =>
					expect(feedbackError).toHaveBeenCalledWith(
						expect.stringMatching(/closed/i),
					),
				{ timeout: 3000 },
			);
			expect(sendEmailMutate).not.toHaveBeenCalled();
			await waitFor(() =>
				expect(screen.getByTestId("send-button-tier1")).not.toBeDisabled(),
			);
		});
	});

	// ── #285: second render path (modal) ─────────────────────────────────────

	describe("ComposeEmail modal render path (#285)", () => {
		it("runs the same step-up relay from the modal surface", async () => {
			preflightMock.mockResolvedValue({ tier: 1, reasons: ["External recipient"] });
			const popup = makeFakePopup();
			vi.stubGlobal("open", vi.fn(() => popup as unknown as Window));

			const user = userEvent.setup();
			renderModal();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier1");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Hello");
			await user.click(screen.getByTestId("send-button-tier1"));

			await completeRelayHandshake(popup, "tok-modal");
			await waitFor(() => expect(sendEmailMutate).toHaveBeenCalled());
			expect(sendEmailMutate).toHaveBeenCalledWith(
				expect.objectContaining({ confirmationToken: "tok-modal" }),
			);
		});
	});
});
