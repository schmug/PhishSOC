// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Route, Routes, useLocation } from "react-router";

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({
		data: { id: "m1", email: "alice@acme.com", name: "Alice" },
	}),
	useMailboxes: () => ({
		data: [{ id: "m1", email: "alice@acme.com", name: "Alice" }],
	}),
}));

vi.mock("~/queries/dashboard", () => ({
	useDashboardSummary: () => ({ data: undefined }),
}));

vi.mock("~/queries/domains", () => ({
	useDomainStats: () => ({ data: undefined, isLoading: false, isError: false }),
}));

vi.mock("~/queries/folders", () => ({
	useFolders: () => ({ data: [] }),
}));

import Shell from "~/components/phishsoc/Shell";
import { renderWithProviders } from "./test-utils";

function LocationReporter() {
	const loc = useLocation();
	return (
		<div data-testid="location">
			{loc.pathname}
			{loc.search}
		</div>
	);
}

function renderShell(initialEntries: string[] = ["/mailbox/m1/dashboard"]) {
	return renderWithProviders(
		<Routes>
			<Route
				path="/mailbox/:mailboxId/*"
				element={
					<Shell>
						<LocationReporter />
					</Shell>
				}
			/>
		</Routes>,
		{ initialEntries },
	);
}

// Render the shell with org-level routes only (no `:mailboxId`). Mirrors the
// real route table for `/`, `/settings`, `/mailboxes`, `/domains`, and
// `/domains/:domain` — none of which carry a mailbox in the URL.
function renderOrgShell(initialEntries: string[]) {
	return renderWithProviders(
		<Routes>
			<Route
				path="/"
				element={
					<Shell>
						<LocationReporter />
					</Shell>
				}
			/>
			<Route
				path="/settings"
				element={
					<Shell>
						<LocationReporter />
					</Shell>
				}
			/>
			<Route
				path="/mailboxes"
				element={
					<Shell>
						<LocationReporter />
					</Shell>
				}
			/>
			<Route
				path="/domains"
				element={
					<Shell>
						<LocationReporter />
					</Shell>
				}
			/>
			<Route
				path="/domains/:domain"
				element={
					<Shell>
						<LocationReporter />
					</Shell>
				}
			/>
			<Route
				path="/search"
				element={
					<Shell>
						<LocationReporter />
					</Shell>
				}
			/>
		</Routes>,
		{ initialEntries },
	);
}

describe("Shell search", () => {
	it("typing + Enter navigates to /mailbox/:id/search?q=…", async () => {
		const user = userEvent.setup();
		renderShell();
		const input = screen.getByRole("searchbox", { name: /search/i });
		await user.click(input);
		await user.keyboard("invoice");
		await user.keyboard("{Enter}");
		expect(screen.getByTestId("location")).toHaveTextContent(
			"/mailbox/m1/search?q=invoice",
		);
	});

	it("URL-encodes special characters in the query", async () => {
		const user = userEvent.setup();
		renderShell();
		const input = screen.getByRole("searchbox", { name: /search/i });
		await user.click(input);
		await user.type(input, "from:bob & jane");
		await user.keyboard("{Enter}");
		const location = screen.getByTestId("location").textContent ?? "";
		// `&` must be percent-encoded so the rest of the query string isn't lost.
		expect(location).toContain("/mailbox/m1/search?q=");
		expect(location).toContain("%26");
		expect(location).toContain("from%3Abob");
	});

	it("Enter on an empty input does not navigate", async () => {
		const user = userEvent.setup();
		renderShell();
		const input = screen.getByRole("searchbox", { name: /search/i });
		await user.click(input);
		await user.keyboard("{Enter}");
		expect(screen.getByTestId("location")).toHaveTextContent(
			"/mailbox/m1/dashboard",
		);
	});

	it("Cmd+K from anywhere focuses the search input", async () => {
		const user = userEvent.setup();
		renderShell();
		const input = screen.getByRole("searchbox", { name: /search/i });
		expect(document.activeElement).not.toBe(input);
		await user.keyboard("{Meta>}k{/Meta}");
		expect(document.activeElement).toBe(input);
	});

	it("Ctrl+K from anywhere focuses the search input", async () => {
		const user = userEvent.setup();
		renderShell();
		const input = screen.getByRole("searchbox", { name: /search/i });
		expect(document.activeElement).not.toBe(input);
		await user.keyboard("{Control>}k{/Control}");
		expect(document.activeElement).toBe(input);
	});

	it("placeholder copy doesn't promise more than the backend supports", () => {
		renderShell();
		const input = screen.getByRole("searchbox", { name: /search/i });
		const placeholder = input.getAttribute("placeholder") ?? "";
		// Backend only searches emails; should not promise indicators or cases.
		expect(placeholder).not.toMatch(/indicator/i);
		expect(placeholder).not.toMatch(/case/i);
		expect(placeholder).toMatch(/email|message|search/i);
	});
});

// Org-scope search (#197): on org-level routes (no `:mailboxId` in URL), a
// submit must navigate to the top-level `/search?q=…` route that fans out
// across every mailbox the caller can see. The previous disabled-input
// fallback (#187) is gone — operators get an actual cross-mailbox surface.
describe("Shell search on org-level routes (no mailboxId)", () => {
	it.each([
		["/"],
		["/settings"],
		["/mailboxes"],
		["/domains"],
		["/domains/example.com"],
	])("submitting on %s navigates to /search?q=…", async (path) => {
		const user = userEvent.setup();
		renderOrgShell([path]);
		const input = screen.getByRole("searchbox", { name: /search/i });
		expect(input).not.toBeDisabled();
		await user.click(input);
		await user.keyboard("invoice");
		await user.keyboard("{Enter}");
		expect(screen.getByTestId("location")).toHaveTextContent(
			"/search?q=invoice",
		);
	});

	it("URL-encodes special characters in org-scope queries", async () => {
		const user = userEvent.setup();
		renderOrgShell(["/"]);
		const input = screen.getByRole("searchbox", { name: /search/i });
		await user.click(input);
		await user.type(input, "from:bob & jane");
		await user.keyboard("{Enter}");
		const location = screen.getByTestId("location").textContent ?? "";
		expect(location).toContain("/search?q=");
		expect(location).toContain("%26");
		expect(location).toContain("from%3Abob");
	});

	it("cmd+K focuses the search input on org routes too", async () => {
		const user = userEvent.setup();
		renderOrgShell(["/"]);
		const input = screen.getByRole("searchbox", { name: /search/i });
		expect(input).not.toBeDisabled();
		await user.keyboard("{Meta>}k{/Meta}");
		expect(document.activeElement).toBe(input);
	});

	it("placeholder copy matches the mailbox-scoped surface", () => {
		renderOrgShell(["/"]);
		const input = screen.getByRole("searchbox", { name: /search/i });
		expect(input.getAttribute("placeholder")).toMatch(/⌘K/);
	});
});
