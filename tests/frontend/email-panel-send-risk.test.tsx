// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Acceptance tests for issue #314 (EmailPanel draft-send step-up wiring),
 * reworked for #376 (WebAuthn step-up).
 *
 * Covers tier-0 (no prompt) and tier ≥ 1 (step-up → token relay) paths through
 * `handleSendDraft`. The step-up relay (now an in-page WebAuthn assertion) is
 * mocked here; its internals live in step-up-confirm.test.ts.
 */

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import { renderWithProviders } from "./test-utils";
import type { Email } from "~/types";

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
		default: {
			...actual.default,
			preflightEmail: vi.fn(),
			getEmail: vi.fn(),
		},
	};
});

const stepUpMock = vi.fn();
vi.mock("~/lib/step-up-confirm", () => ({
	requestStepUpConfirmation: (...args: unknown[]) => stepUpMock(...args),
	StepUpNoPasskeyError: class StepUpNoPasskeyError extends Error {},
}));

// Stable spies so we can assert confirmationToken is threaded through.
const sendEmailMutate = vi.fn().mockResolvedValue(undefined);
const replyMutate = vi.fn().mockResolvedValue(undefined);
const deleteEmailMutate = vi.fn().mockResolvedValue(undefined);

vi.mock("~/queries/emails", () => ({
	useSendEmail: () => ({ mutateAsync: sendEmailMutate }),
	useReplyToEmail: () => ({ mutateAsync: replyMutate }),
	useDeleteEmail: () => ({ mutate: vi.fn(), mutateAsync: deleteEmailMutate }),
	useUpdateEmail: () => ({ mutate: vi.fn() }),
	useMoveEmail: () => ({ mutate: vi.fn() }),
	useEmail: () => ({ data: DRAFT_EMAIL }),
	useThreadReplies: () => ({ data: [] }),
}));

vi.mock("~/queries/folders", () => ({
	useFolders: () => ({ data: [] }),
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

const closePanelMock = vi.fn();
vi.mock("~/hooks/useUIStore", () => ({
	useUIStore: () => ({
		closePanel: closePanelMock,
		startCompose: vi.fn(),
	}),
}));

// Stub out the display sub-components so they don't pull in EmailIframe/DOMPurify.
vi.mock("~/components/email-panel/SingleMessageView", () => ({
	default: () => null,
}));
vi.mock("~/components/email-panel/ThreadMessage", () => ({
	default: () => null,
}));

// ── deferred imports (after mocks are registered) ────────────────────────────

import EmailPanel from "~/components/EmailPanel";
import api from "~/services/api";

const preflightMock = api.preflightEmail as unknown as ReturnType<typeof vi.fn>;

// ── fixtures ──────────────────────────────────────────────────────────────────

const DRAFT_EMAIL: Email = {
	id: "e1",
	folder_id: "draft",
	recipient: "vendor@external.com",
	subject: "Test subject",
	body: "<p>Hello</p>",
	sender: "operator@internal.test",
	date: "2026-05-01T12:00:00Z",
	read: false,
	starred: false,
};

// ── render helper ─────────────────────────────────────────────────────────────

function renderDraftPanel() {
	return renderWithProviders(
		<Routes>
			<Route path="/mailbox/:mailboxId/:folder" element={<EmailPanel emailId="e1" />} />
		</Routes>,
		{ initialEntries: ["/mailbox/m1/draft"] },
	);
}

// ── test suite ────────────────────────────────────────────────────────────────

describe("EmailPanel draft send-risk (#314)", () => {
	beforeEach(() => {
		preflightMock.mockReset();
		feedbackInfo.mockReset();
		feedbackError.mockReset();
		feedbackSuccess.mockReset();
		stepUpMock.mockReset();
		sendEmailMutate.mockReset().mockResolvedValue(undefined);
		replyMutate.mockReset().mockResolvedValue(undefined);
		deleteEmailMutate.mockReset().mockResolvedValue(undefined);
		closePanelMock.mockReset();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	// ── Tier 0: no step-up prompt ────────────────────────────────────────────

	describe("Tier 0 send", () => {
		it("sends without a confirmation prompt and calls sendEmailMutate without confirmationToken", async () => {
			preflightMock.mockResolvedValue({ tier: 0, reasons: [] });
			const user = userEvent.setup();
			renderDraftPanel();

			const sendBtn = screen.getByRole("button", { name: /^send$/i });
			await user.click(sendBtn);

			await waitFor(() => expect(sendEmailMutate).toHaveBeenCalled());
			expect(sendEmailMutate).toHaveBeenCalledWith(
				expect.objectContaining({
					mailboxId: "m1",
					confirmationToken: undefined,
				}),
			);
			expect(stepUpMock).not.toHaveBeenCalled();
			expect(feedbackSuccess).toHaveBeenCalledWith("Email sent!");
			// closePanel must be called since we're in the draft folder.
			expect(closePanelMock).toHaveBeenCalled();
		});

		it("proceeds as Tier 0 when preflight throws a network error", async () => {
			preflightMock.mockRejectedValue(new Error("network error"));
			const user = userEvent.setup();
			renderDraftPanel();

			await user.click(screen.getByRole("button", { name: /^send$/i }));

			await waitFor(() => expect(sendEmailMutate).toHaveBeenCalled());
			expect(sendEmailMutate).toHaveBeenCalledWith(
				expect.objectContaining({ confirmationToken: undefined }),
			);
		});
	});

	// ── Tier ≥ 1: step-up (WebAuthn) → token relay ───────────────────────────

	describe("Tier 1 send", () => {
		it("runs the step-up with the exact payload and sends with confirmationToken", async () => {
			preflightMock.mockResolvedValue({ tier: 1, reasons: ["External recipient"] });
			stepUpMock.mockResolvedValue("tok-draft-tier1");

			const user = userEvent.setup();
			renderDraftPanel();

			await user.click(screen.getByRole("button", { name: /^send$/i }));

			await waitFor(() => expect(sendEmailMutate).toHaveBeenCalled());
			expect(sendEmailMutate).toHaveBeenCalledWith(
				expect.objectContaining({
					mailboxId: "m1",
					confirmationToken: "tok-draft-tier1",
				}),
			);

			// The step-up payload must match the exact wire values so the server
			// payloadHash binding holds.
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

		it("surfaces a step-up error and does not send", async () => {
			preflightMock.mockResolvedValue({ tier: 1, reasons: ["External recipient"] });
			stepUpMock.mockRejectedValue(new Error("invalid or expired confirmation token"));

			const user = userEvent.setup();
			renderDraftPanel();

			await user.click(screen.getByRole("button", { name: /^send$/i }));

			await waitFor(() =>
				expect(feedbackError).toHaveBeenCalledWith(
					expect.stringMatching(/invalid or expired confirmation token/i),
				),
			);
			expect(sendEmailMutate).not.toHaveBeenCalled();
		});
	});
});
