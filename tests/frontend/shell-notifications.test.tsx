// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Tests for the Shell topbar notifications popover (#185). Verifies:
//  - bell is reachable as a button with aria-label="Notifications"
//  - clicking the bell opens a popover
//  - popover shows "No notifications" when there's nothing to surface
//  - popover surfaces an "{N} open cases" item linking to `/mailbox/:id/cases`
//    when the dashboard summary reports `openCases > 0`
//  - bell shows a dot/badge iff there's at least one item
//  - aria-haspopup, aria-expanded, and Escape-to-close all work
//
// These tests don't mock fetch — `useDashboardSummary` is mocked at the
// module boundary — so URL substring rules don't apply here.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({
		data: { id: "m1", email: "alice@acme.com", name: "Alice" },
	}),
	useMailboxes: () => ({
		data: [{ id: "m1", email: "alice@acme.com", name: "Alice" }],
	}),
}));

vi.mock("~/queries/domains", () => ({
	useDomainStats: () => ({
		data: undefined,
		isLoading: false,
		isError: false,
	}),
}));

// `useDashboardSummary` is reassigned per-test via `setSummary`; the mock
// closure reads from a mutable ref so we don't have to re-import the module
// or restore mocks between cases.
let dashboardSummary: { openCases: number } | undefined = undefined;
function setSummary(next: { openCases: number } | undefined) {
	dashboardSummary = next;
}

vi.mock("~/queries/dashboard", () => ({
	useDashboardSummary: () => ({
		data: dashboardSummary,
		isLoading: false,
		isError: false,
	}),
}));

vi.mock("~/queries/folders", () => ({
	useFolders: () => ({ data: [] }),
}));

import Shell from "~/components/phishsoc/Shell";
import { useUIStore } from "~/hooks/useUIStore";
import { renderWithProviders } from "./test-utils";

function renderShell(initialEntries: string[] = ["/mailbox/m1/dashboard"]) {
	return renderWithProviders(
		<Routes>
			<Route
				path="/mailbox/:mailboxId/*"
				element={
					<Shell>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
			{/* Org-route variant — Shell still renders, just with mailboxId
			    undefined. Mirrors what `/`, `/mailboxes`, `/domains` do at
			    runtime so we can exercise the no-mailbox notifications path. */}
			<Route
				path="*"
				element={
					<Shell>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
		</Routes>,
		{ initialEntries },
	);
}

beforeEach(() => {
	useUIStore.setState({ isAgentPanelOpen: false, isSidebarOpen: false });
	setSummary(undefined);
});

afterEach(() => {
	setSummary(undefined);
});

describe("Shell notifications bell — closed state", () => {
	it("renders a button labeled 'Notifications' with popover affordances", () => {
		renderShell();
		const bell = screen.getByRole("button", { name: /notifications/i });
		// base-ui Popover.Trigger wires aria-haspopup + aria-expanded for free.
		expect(bell).toHaveAttribute("aria-haspopup");
		expect(bell).toHaveAttribute("aria-expanded", "false");
	});

	it("does not render the popover content before the bell is clicked", () => {
		renderShell();
		// Empty-state copy is the canary — it only mounts inside the popup.
		expect(screen.queryByText(/no notifications/i)).not.toBeInTheDocument();
	});

	it("does not show the badge when there are zero open cases", () => {
		setSummary({ openCases: 0 });
		renderShell();
		expect(screen.queryByTestId("notifications-badge")).not.toBeInTheDocument();
	});
});

describe("Shell notifications bell — empty state", () => {
	it("shows 'No notifications' when openCases is 0", async () => {
		setSummary({ openCases: 0 });
		const user = userEvent.setup();
		renderShell();
		const bell = screen.getByRole("button", { name: /notifications/i });
		await user.click(bell);
		expect(bell).toHaveAttribute("aria-expanded", "true");
		expect(await screen.findByText(/no notifications/i)).toBeInTheDocument();
	});

	it("shows 'No notifications' when summary is undefined (org / loading)", async () => {
		setSummary(undefined);
		const user = userEvent.setup();
		renderShell(["/"]);
		const bell = screen.getByRole("button", { name: /notifications/i });
		await user.click(bell);
		expect(await screen.findByText(/no notifications/i)).toBeInTheDocument();
	});
});

describe("Shell notifications bell — populated state", () => {
	it("shows '{N} open cases' linking to /mailbox/:id/cases when openCases > 0", async () => {
		setSummary({ openCases: 3 });
		const user = userEvent.setup();
		renderShell();
		const bell = screen.getByRole("button", { name: /notifications/i });
		// Badge dot is visible before opening.
		expect(screen.getByTestId("notifications-badge")).toBeInTheDocument();
		await user.click(bell);
		const link = await screen.findByRole("link", { name: /3 open cases/i });
		expect(link).toHaveAttribute("href", "/mailbox/m1/cases");
	});

	it("singularizes the label when openCases === 1", async () => {
		setSummary({ openCases: 1 });
		const user = userEvent.setup();
		renderShell();
		await user.click(screen.getByRole("button", { name: /notifications/i }));
		const link = await screen.findByRole("link", { name: /^1 open case$/i });
		expect(link).toHaveAttribute("href", "/mailbox/m1/cases");
	});

	it("does not render the empty-state copy when items exist", async () => {
		setSummary({ openCases: 2 });
		const user = userEvent.setup();
		renderShell();
		await user.click(screen.getByRole("button", { name: /notifications/i }));
		await screen.findByRole("link", { name: /open cases/i });
		expect(screen.queryByText(/no notifications/i)).not.toBeInTheDocument();
	});
});

describe("Shell notifications bell — keyboard / a11y", () => {
	it("Escape closes the popover", async () => {
		setSummary({ openCases: 2 });
		const user = userEvent.setup();
		renderShell();
		const bell = screen.getByRole("button", { name: /notifications/i });
		await user.click(bell);
		await screen.findByRole("link", { name: /open cases/i });
		await user.keyboard("{Escape}");
		// The popup unmounts on close; aria-expanded flips back to "false".
		await waitFor(() => {
			expect(bell).toHaveAttribute("aria-expanded", "false");
		});
		expect(screen.queryByRole("link", { name: /open cases/i })).not.toBeInTheDocument();
	});
});
