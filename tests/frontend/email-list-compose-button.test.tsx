// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Tests for the persistent Compose button in the email-list header (#348).
// Covers: button renders when folder has messages (G1), clicking calls
// startCompose (G2), button suppressed in non-compose folders (G3).

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import { renderWithProviders } from "./test-utils";

const startCompose = vi.fn();

// Mock the full UIStore shape consumed by both EmailListRoute and the
// MailboxSplitView it renders.
vi.mock("~/hooks/useUIStore", () => ({
	useUIStore: () => ({
		selectedEmailId: null,
		isComposing: false,
		selectEmail: vi.fn(),
		closePanel: vi.fn(),
		closeCompose: vi.fn(),
		startCompose,
	}),
}));

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

import EmailListRoute from "~/routes/email-list";

function renderEmailList(folder: string) {
	return renderWithProviders(
		<Routes>
			<Route
				path="/mailbox/:mailboxId/emails/:folder"
				element={<EmailListRoute />}
			/>
		</Routes>,
		{ initialEntries: [`/mailbox/mb1/emails/${folder}`] },
	);
}

describe("EmailListRoute — persistent Compose button", () => {
	beforeEach(() => {
		startCompose.mockReset();
	});

	it("renders Compose button in Inbox when emails are present", () => {
		renderEmailList("inbox");
		expect(screen.getByRole("button", { name: "Compose" })).toBeInTheDocument();
	});

	it("calls startCompose when the Compose button is clicked", async () => {
		const user = userEvent.setup();
		renderEmailList("inbox");
		await user.click(screen.getByRole("button", { name: "Compose" }));
		expect(startCompose).toHaveBeenCalledOnce();
	});

	it("does not render Compose button in Trash", () => {
		renderEmailList("trash");
		expect(
			screen.queryByRole("button", { name: "Compose" }),
		).not.toBeInTheDocument();
	});

	it("does not render Compose button in Archive", () => {
		renderEmailList("archive");
		expect(
			screen.queryByRole("button", { name: "Compose" }),
		).not.toBeInTheDocument();
	});

	it("does not render Compose button in Quarantine", () => {
		renderEmailList("quarantine");
		expect(
			screen.queryByRole("button", { name: "Compose" }),
		).not.toBeInTheDocument();
	});
});
