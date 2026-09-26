// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import { renderWithProviders } from "./test-utils";

vi.mock("~/lib/feedback", () => ({
	useFeedback: () => ({ info: vi.fn(), error: vi.fn(), success: vi.fn() }),
}));
vi.mock("~/services/api", async () => {
	const actual = await vi.importActual<typeof import("~/services/api")>("~/services/api");
	return { ...actual, default: { ...actual.default, preflightEmail: vi.fn().mockResolvedValue({ tier: 0, reasons: [] }) } };
});
vi.mock("~/lib/step-up-confirm", () => ({
	requestStepUpConfirmation: vi.fn(),
	StepUpNoPasskeyError: class StepUpNoPasskeyError extends Error {},
}));

const sendMutate = vi.fn().mockResolvedValue(undefined);
vi.mock("~/queries/emails", () => ({
	useSendEmail: () => ({ mutateAsync: sendMutate }),
	useSaveDraft: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useReplyToEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useForwardEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useDeleteEmail: () => ({ mutate: vi.fn() }),
}));
vi.mock("~/queries/mailboxes", () => ({
	useMailbox: (id: string | undefined) => ({
		data: id ? { id, email: id, name: id, settings: { signature: { enabled: true, text: `SIG-${id}` } } } : undefined,
	}),
}));
vi.mock("~/components/RichTextEditor", () => ({ default: () => null }));

import ComposePanel from "~/components/ComposePanel";
import { useUIStore } from "~/hooks/useUIStore";
import { LAST_FROM_STORAGE_KEY } from "~/lib/compose-from";

const OPTIONS = [
	{ id: "ops@a.test", email: "ops@a.test" },
	{ id: "sales@b.test", email: "sales@b.test" },
];

function renderPicker(defaultId: string | null, mode: "new" | "reply" = "new") {
	useUIStore.setState({
		isComposing: true,
		composeOptions:
			mode === "new"
				? { mode: "new", originalEmail: null }
				: {
						mode: "reply",
						originalEmail: {
							id: "e1", subject: "Hi", sender: "x@ext.test", recipient: "ops@a.test",
							date: "2026-09-01T12:00:00.000Z", read: true, starred: false,
						},
					},
	});
	return renderWithProviders(
		<Routes>
			<Route path="/inbox" element={<ComposePanel mailboxId="ops@a.test" folder="inbox" fromPicker={{ options: OPTIONS, defaultId }} />} />
		</Routes>,
		{ initialEntries: ["/inbox"] },
	);
}

describe("Compose From picker", () => {
	beforeEach(() => {
		sendMutate.mockReset().mockResolvedValue(undefined);
		localStorage.clear();
	});

	it("disables Send until a mailbox is picked, then sends from it and remembers it", async () => {
		const user = userEvent.setup();
		renderPicker(null);
		const send = await screen.findByTestId("send-button-tier0");
		expect(send).toBeDisabled();
		await user.selectOptions(screen.getByLabelText("From"), "sales@b.test");
		await user.type(screen.getByPlaceholderText(/recipient@example.com/i), "dest@ext.test");
		await user.type(screen.getByPlaceholderText(/email subject/i), "Quote");
		expect(send).toBeEnabled();
		await user.click(send);
		await waitFor(() => expect(sendMutate).toHaveBeenCalledTimes(1));
		expect(sendMutate.mock.calls[0][0].mailboxId).toBe("sales@b.test");
		expect(localStorage.getItem(LAST_FROM_STORAGE_KEY)).toBe("sales@b.test");
	});

	it("pre-selects defaultId", async () => {
		renderPicker("ops@a.test");
		expect(await screen.findByLabelText("From")).toHaveValue("ops@a.test");
	});

	it("keeps typed To and Subject when From changes", async () => {
		const user = userEvent.setup();
		renderPicker("ops@a.test");
		await user.type(await screen.findByPlaceholderText(/recipient@example.com/i), "dest@ext.test");
		await user.type(screen.getByPlaceholderText(/email subject/i), "Quote");
		await user.selectOptions(screen.getByLabelText("From"), "sales@b.test");
		expect(screen.getByPlaceholderText(/recipient@example.com/i)).toHaveValue("dest@ext.test");
		expect(screen.getByPlaceholderText(/email subject/i)).toHaveValue("Quote");
	});

	it("swaps the signature when From changes before the body is edited", async () => {
		const user = userEvent.setup();
		renderPicker("ops@a.test");
		await user.selectOptions(await screen.findByLabelText("From"), "sales@b.test");
		await user.type(screen.getByPlaceholderText(/recipient@example.com/i), "dest@ext.test");
		await user.type(screen.getByPlaceholderText(/email subject/i), "Quote");
		await user.click(screen.getByTestId("send-button-tier0"));
		await waitFor(() => expect(sendMutate).toHaveBeenCalledTimes(1));
		const html = sendMutate.mock.calls[0][0].email.html as string;
		expect(html).toContain("SIG-sales@b.test");
		expect(html).not.toContain("SIG-ops@a.test");
	});

	it("adds the picked mailbox's signature when compose opened with no default", async () => {
		const user = userEvent.setup();
		renderPicker(null);
		await user.selectOptions(await screen.findByLabelText("From"), "sales@b.test");
		await user.type(screen.getByPlaceholderText(/recipient@example.com/i), "dest@ext.test");
		await user.type(screen.getByPlaceholderText(/email subject/i), "Quote");
		await user.click(screen.getByTestId("send-button-tier0"));
		await waitFor(() => expect(sendMutate).toHaveBeenCalledTimes(1));
		expect(sendMutate.mock.calls[0][0].email.html as string).toContain("SIG-sales@b.test");
	});

	it("hides the picker for replies", async () => {
		renderPicker("sales@b.test", "reply");
		await screen.findByTestId("send-button-tier0");
		expect(screen.queryByLabelText("From")).toBeNull();
	});
});
