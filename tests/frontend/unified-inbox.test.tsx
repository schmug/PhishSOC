// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import { renderWithProviders } from "./test-utils";
import { useUIStore } from "~/hooks/useUIStore";
import type { UnifiedInboxResponse, UnifiedInboxRow } from "~/types";

function row(id: string, mailbox: string, extra: Partial<UnifiedInboxRow> = {}): UnifiedInboxRow {
	return {
		id,
		subject: `Subject ${id}`,
		sender: "someone@ext.test",
		recipient: mailbox,
		date: "2026-09-01T12:00:00.000Z",
		read: false,
		starred: false,
		thread_count: 1,
		thread_unread_count: 1,
		mailbox_id: mailbox,
		mailbox_email: mailbox,
		...extra,
	};
}

let response: UnifiedInboxResponse;
const useUnifiedInboxSpy = vi.fn();
vi.mock("~/queries/inbox", () => ({
	useUnifiedInbox: (before: string | null) => {
		useUnifiedInboxSpy(before);
		return { data: response, isFetching: false, isError: false };
	},
}));

vi.mock("~/queries/mailboxes", () => ({
	useMailboxes: () => ({
		data: [
			{ id: "ops@a.test", email: "ops@a.test", name: "ops@a.test" },
			{ id: "sales@b.test", email: "sales@b.test", name: "sales@b.test" },
			{ id: "gw@c.test", email: "gw@c.test", name: "gw@c.test", sidecar: true },
		],
	}),
}));

const updateMutate = vi.fn();
const deleteMutate = vi.fn();
vi.mock("~/queries/emails", () => ({
	useUpdateEmail: () => ({ mutate: updateMutate }),
	useMarkThreadRead: () => ({ mutate: vi.fn() }),
	useDeleteEmail: () => ({ mutate: deleteMutate }),
}));

vi.mock("~/lib/feedback", () => ({
	useFeedback: () => ({ error: vi.fn(), info: vi.fn(), success: vi.fn() }),
}));

vi.mock("~/components/phishsoc/Shell", () => ({
	default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock("~/components/EmailPanel", () => ({
	default: ({ emailId, mailboxId }: { emailId: string; mailboxId?: string }) => (
		<div data-testid="email-panel">{`${mailboxId}|${emailId}`}</div>
	),
}));

vi.mock("~/components/ComposePanel", () => ({
	default: ({ fromPicker }: { fromPicker?: { options: Array<{ id: string }>; defaultId: string | null } }) => (
		<div data-testid="compose-panel">{`${fromPicker?.options.map((o) => o.id).join(",")}|${fromPicker?.defaultId}`}</div>
	),
}));

import UnifiedInboxRoute from "~/routes/unified-inbox";

function renderInbox(path = "/inbox") {
	return renderWithProviders(
		<Routes>
			<Route path="/inbox" element={<UnifiedInboxRoute />} />
			<Route path="/mailboxes" element={<div>mailboxes page</div>} />
		</Routes>,
		{ initialEntries: [path] },
	);
}

describe("/inbox", () => {
	beforeEach(() => {
		useUnifiedInboxSpy.mockReset();
		updateMutate.mockReset();
		deleteMutate.mockReset();
		localStorage.clear();
		useUIStore.setState({ selectedEmailId: null, isComposing: false });
		response = {
			emails: [row("e1", "ops@a.test"), row("e2", "sales@b.test")],
			nextCursor: "CUR1",
			failed: [],
			mailboxCount: 2,
		};
	});

	it("renders merged rows with mailbox chips", () => {
		renderInbox();
		const chips = screen.getAllByTestId("row-mailbox").map((c) => c.textContent);
		expect(chips).toEqual(["ops@a.test", "sales@b.test"]);
	});

	it("opens a row against its own mailbox and marks it read there", async () => {
		const user = userEvent.setup();
		renderInbox();
		await user.click(screen.getByText("Subject e2"));
		expect(screen.getByTestId("email-panel")).toHaveTextContent("sales@b.test|e2");
		expect(updateMutate.mock.calls[0][0]).toMatchObject({ mailboxId: "sales@b.test", id: "e2", data: { read: true } });
	});

	it("pages older and back to newer via the cursor", async () => {
		const user = userEvent.setup();
		renderInbox();
		expect(useUnifiedInboxSpy).toHaveBeenLastCalledWith(null);
		expect(screen.getByRole("button", { name: /newer/i })).toBeDisabled();
		await user.click(screen.getByRole("button", { name: /older/i }));
		expect(useUnifiedInboxSpy).toHaveBeenLastCalledWith("CUR1");
		await user.click(screen.getByRole("button", { name: /newer/i }));
		expect(useUnifiedInboxSpy).toHaveBeenLastCalledWith(null);
	});

	it("disables Older on the last page", () => {
		response = { ...response, nextCursor: null };
		renderInbox();
		expect(screen.getByRole("button", { name: /older/i })).toBeDisabled();
	});

	it("shows a banner naming mailboxes that failed to load", () => {
		response = { ...response, failed: ["broken@z.test"] };
		renderInbox();
		expect(screen.getByText(/1 mailbox didn't load/i)).toHaveTextContent("broken@z.test");
	});

	it("shows the no-mailboxes empty state with a link to /mailboxes", async () => {
		response = { emails: [], nextCursor: null, failed: [], mailboxCount: 0 };
		const user = userEvent.setup();
		renderInbox();
		await user.click(screen.getByRole("link", { name: /manage mailboxes/i }));
		expect(screen.getByText("mailboxes page")).toBeInTheDocument();
	});

	it("opens the ?mailbox=&email= deep link", () => {
		renderInbox("/inbox?mailbox=ops%2Btag%40a.test&email=e9");
		expect(screen.getByTestId("email-panel")).toHaveTextContent("ops+tag@a.test|e9");
	});

	it("clears a selection carried over from a per-mailbox page", () => {
		useUIStore.setState({ selectedEmailId: "stale", isComposing: false });
		renderInbox();
		expect(screen.queryByTestId("email-panel")).toBeNull();
	});

	it("closes the reading pane when the open row is deleted", async () => {
		const user = userEvent.setup();
		vi.spyOn(window, "confirm").mockReturnValue(true);
		renderInbox();
		await user.click(screen.getByText("Subject e1"));
		expect(screen.getByTestId("email-panel")).toBeInTheDocument();
		const rowEl = screen.getByText("Subject e1").closest('[role="button"]') as HTMLElement;
		await user.click(within(rowEl).getByRole("button", { name: /delete/i }));
		expect(deleteMutate.mock.calls[0][0]).toMatchObject({ mailboxId: "ops@a.test", id: "e1" });
		expect(screen.queryByTestId("email-panel")).toBeNull();
	});

	it("offers inbox-navigable mailboxes in the From picker, defaulting to the open row's mailbox", async () => {
		const user = userEvent.setup();
		renderInbox();
		await user.click(screen.getByText("Subject e2"));
		await user.click(screen.getByRole("button", { name: /compose/i }));
		expect(screen.getByTestId("compose-panel")).toHaveTextContent("ops@a.test,sales@b.test|sales@b.test");
	});
});
