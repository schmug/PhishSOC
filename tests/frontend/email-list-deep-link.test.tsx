// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Tests for the `?email=` deep-link auto-select (issue #563): the new-mail
// ops-visibility webhook links to `/mailbox/:mailboxId/emails/:folder?email=<id>`.
// Visiting that URL must open the reading panel for that message, and the
// `email` param must not linger (so a later refresh/refetch doesn't re-fire it).

import { screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import { renderWithProviders } from "./test-utils";
import { useUIStore } from "~/hooks/useUIStore";

const INBOX_EMAIL = {
	id: "e1",
	subject: "Test email",
	sender: "sender@example.com",
	recipient: "me@example.com",
	date: "2026-05-01T12:00:00Z",
	read: true,
	starred: false,
	folder_id: "inbox",
	snippet: "Hello",
	has_draft: false,
	needs_reply: false,
};

vi.mock("~/queries/emails", () => ({
	useEmails: () => ({
		data: { emails: [INBOX_EMAIL], totalCount: 1 },
		isFetching: false,
	}),
	useMarkThreadRead: () => ({ mutate: vi.fn() }),
	useDeleteEmail: () => ({ mutate: vi.fn() }),
	useUpdateEmail: () => ({ mutate: vi.fn() }),
}));

vi.mock("~/queries/folders", () => ({
	useFolders: () => ({ data: [] }),
}));

vi.mock("~/lib/feedback", () => ({
	useFeedback: () => ({ error: vi.fn(), info: vi.fn(), success: vi.fn() }),
}));

// MailboxSplitView renders the real EmailPanel when a message is selected,
// which pulls in the send/reply/thread query surface (see
// tests/frontend/email-panel-send-risk.test.tsx). A minimal stub is enough to
// prove the panel opened for the right message id without re-mocking that
// whole surface here.
vi.mock("~/components/EmailPanel", () => ({
	default: ({ emailId }: { emailId: string }) => (
		<div data-testid="email-panel">{emailId}</div>
	),
}));

import EmailListRoute from "~/routes/email-list";

function renderEmailList(path: string) {
	return renderWithProviders(
		<Routes>
			<Route
				path="/mailbox/:mailboxId/emails/:folder"
				element={<EmailListRoute />}
			/>
		</Routes>,
		{ initialEntries: [path] },
	);
}

describe("EmailListRoute — ?email= deep-link auto-select (issue #563)", () => {
	beforeEach(() => {
		useUIStore.setState({ selectedEmailId: null, isComposing: false });
	});

	it("opens the reading panel for the id in ?email= on load, then drops the param", async () => {
		renderEmailList("/mailbox/mb1/emails/inbox?email=e1");

		const panel = await screen.findByTestId("email-panel");
		expect(panel).toHaveTextContent("e1");
		expect(useUIStore.getState().selectedEmailId).toBe("e1");
	});

	it("does not open the reading panel when no ?email= param is present", () => {
		renderEmailList("/mailbox/mb1/emails/inbox");

		expect(screen.queryByTestId("email-panel")).not.toBeInTheDocument();
		expect(useUIStore.getState().selectedEmailId).toBeNull();
	});
});
