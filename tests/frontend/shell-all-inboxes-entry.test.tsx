// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { fireEvent, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Route, Routes, useLocation } from "react-router";

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({ data: undefined }),
	useMailboxes: () => ({
		data: [
			{ id: "m1", email: "alice@acme.com", name: "Alice" },
			{ id: "m2", email: "bob@acme.com", name: "Bob" },
		],
	}),
}));
vi.mock("~/queries/domains", () => ({ useDomainStats: () => ({ data: undefined, isLoading: false, isError: false }) }));
vi.mock("~/queries/dashboard", () => ({ useDashboardSummary: () => ({ data: undefined, isLoading: false, isError: false }) }));
vi.mock("~/queries/folders", () => ({ useFolders: () => ({ data: [] }) }));

import Shell from "~/components/phishsoc/Shell";
import { renderWithProviders } from "./test-utils";

function LocationReporter() {
	return <div data-testid="location">{useLocation().pathname}</div>;
}

function renderAt(path: string) {
	return renderWithProviders(
		<Routes>
			<Route path="/" element={<Shell><LocationReporter /></Shell>} />
			<Route path="/inbox" element={<Shell><LocationReporter /></Shell>} />
		</Routes>,
		{ initialEntries: [path] },
	);
}

async function openMenu(trigger: HTMLElement) {
	fireEvent.mouseDown(trigger);
	await new Promise((r) => setTimeout(r, 0));
}

describe("All inboxes entry points", () => {
	it("sidebar links to /inbox", () => {
		renderAt("/");
		const links = screen.getAllByRole("link", { name: /all inboxes/i });
		expect(links[0]).toHaveAttribute("href", "/inbox");
	});

	it("switcher item navigates to /inbox", async () => {
		const user = userEvent.setup();
		renderAt("/");
		await openMenu(screen.getAllByRole("button", { name: /select mailbox/i })[0]);
		const menu = await screen.findByRole("menu");
		await user.click(within(menu).getByRole("menuitem", { name: /all inboxes/i }));
		expect(screen.getByTestId("location")).toHaveTextContent("/inbox");
	});
});
