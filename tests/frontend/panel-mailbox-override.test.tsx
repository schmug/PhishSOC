// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// /inbox has no :mailboxId route param, so EmailPanel/ComposePanel accept an
// explicit mailboxId that overrides the URL (spec 2026-09-26 unified inbox).

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import { renderWithProviders } from "./test-utils";
import type { Email } from "~/types";

vi.mock("~/lib/feedback", () => ({
	useFeedback: () => ({ info: vi.fn(), error: vi.fn(), success: vi.fn() }),
}));

vi.mock("~/services/api", async () => {
	const actual = await vi.importActual<typeof import("~/services/api")>("~/services/api");
	return {
		...actual,
		default: {
			...actual.default,
			preflightEmail: vi.fn().mockResolvedValue({ tier: 0, reasons: [] }),
			getEmail: vi.fn(),
		},
	};
});

vi.mock("~/lib/step-up-confirm", () => ({
	requestStepUpConfirmation: vi.fn(),
	StepUpNoPasskeyError: class StepUpNoPasskeyError extends Error {},
}));

const INBOX_EMAIL: Email = {
	id: "e1",
	folder_id: "inbox",
	recipient: "ops@b.test",
	subject: "Hello",
	body: "<p>Hi</p>",
	sender: "someone@ext.test",
	date: "2026-09-01T12:00:00.000Z",
	read: true,
	starred: false,
};

const useEmailSpy = vi.fn();
const useFoldersSpy = vi.fn();
const replyMutate = vi.fn().mockResolvedValue(undefined);

vi.mock("~/queries/emails", () => ({
	useSendEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useSaveDraft: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useReplyToEmail: () => ({ mutateAsync: replyMutate }),
	useForwardEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useDeleteEmail: () => ({ mutate: vi.fn(), mutateAsync: vi.fn() }),
	useUpdateEmail: () => ({ mutate: vi.fn() }),
	useMoveEmail: () => ({ mutate: vi.fn() }),
	useEmail: (mailboxId: string | undefined, emailId: string | undefined) => {
		useEmailSpy(mailboxId, emailId);
		return { data: INBOX_EMAIL };
	},
	useThreadReplies: () => ({ data: [] }),
}));

vi.mock("~/queries/folders", () => ({
	useFolders: (mailboxId: string | undefined) => {
		useFoldersSpy(mailboxId);
		return { data: [] };
	},
}));

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: (id: string | undefined) => ({
		data: id ? { id, email: id, name: id, settings: {} } : undefined,
	}),
}));

vi.mock("~/components/email-panel/SingleMessageView", () => ({ default: () => null }));
vi.mock("~/components/email-panel/ThreadMessage", () => ({ default: () => null }));
vi.mock("~/components/RichTextEditor", () => ({ default: () => null }));

import ComposePanel from "~/components/ComposePanel";
import EmailPanel from "~/components/EmailPanel";
import { useUIStore } from "~/hooks/useUIStore";

describe("mailboxId override", () => {
	beforeEach(() => {
		useEmailSpy.mockReset();
		useFoldersSpy.mockReset();
		replyMutate.mockReset().mockResolvedValue(undefined);
	});

	it("EmailPanel uses the prop when there is no route param", () => {
		renderWithProviders(
			<Routes>
				<Route path="/inbox" element={<EmailPanel emailId="e1" mailboxId="ops@b.test" folder="inbox" />} />
			</Routes>,
			{ initialEntries: ["/inbox"] },
		);
		expect(useEmailSpy).toHaveBeenCalledWith("ops@b.test", "e1");
		expect(useFoldersSpy).toHaveBeenCalledWith("ops@b.test");
	});

	it("EmailPanel still reads the route param when no prop is given", () => {
		renderWithProviders(
			<Routes>
				<Route path="/mailbox/:mailboxId/emails/:folder" element={<EmailPanel emailId="e1" />} />
			</Routes>,
			{ initialEntries: ["/mailbox/m1/emails/inbox"] },
		);
		expect(useEmailSpy).toHaveBeenCalledWith("m1", "e1");
	});

	it("ComposePanel replies from the prop mailbox", async () => {
		useUIStore.setState({
			isComposing: true,
			composeOptions: { mode: "reply", originalEmail: INBOX_EMAIL },
		});
		const user = userEvent.setup();
		renderWithProviders(
			<Routes>
				<Route path="/inbox" element={<ComposePanel mailboxId="ops@b.test" folder="inbox" />} />
			</Routes>,
			{ initialEntries: ["/inbox"] },
		);
		await user.click(await screen.findByTestId("send-button-tier0"));
		await waitFor(() => expect(replyMutate).toHaveBeenCalledTimes(1));
		expect(replyMutate.mock.calls[0][0]).toMatchObject({ mailboxId: "ops@b.test", emailId: "e1" });
	});
});
