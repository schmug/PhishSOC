// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DomainListEntry } from "~/types";
import {
	shellDashboardMock,
	shellDomainsMock,
	shellMailboxesMock,
} from "./shell-mocks";

const refetch = vi.fn();
let queryState: {
	data: DomainListEntry[] | undefined;
	isLoading: boolean;
	isError: boolean;
};

vi.mock("~/queries/domains", () =>
	shellDomainsMock({
		useDomains: () => ({ ...queryState, refetch }),
	}),
);

// Shell pulls in mailbox/dashboard data — the shared factories return the
// same empty-list / undefined defaults so we render the route in isolation
// rather than fanning out to real fetchers.
vi.mock("~/queries/mailboxes", () => shellMailboxesMock());

vi.mock("~/queries/dashboard", () => shellDashboardMock());

vi.mock("~/queries/folders", () => ({
	useFolders: () => ({ data: [] }),
}));

import DomainsListRoute from "~/routes/domains-list";
import { renderWithProviders } from "./test-utils";

function renderDomainsList() {
	return renderWithProviders(
		<Routes>
			<Route path="/domains" element={<DomainsListRoute />} />
			<Route
				path="/domains/:domain"
				element={<div>Domain detail page</div>}
			/>
			<Route path="/mailboxes" element={<div>Mailboxes page</div>} />
		</Routes>,
		{ initialEntries: ["/domains"] },
	);
}

const populated: DomainListEntry[] = [
	{
		domain: "zulu.example",
		mailboxesCount: 1,
		threatsBlocked24h: 3,
		openCases: 1,
		verdictMix: { safe: 5, suspicious: 0, phishing: 1, spam: 0, bec: 0 },
	},
	{
		domain: "acme.com",
		mailboxesCount: 5,
		threatsBlocked24h: 42,
		openCases: 7,
		verdictMix: { safe: 10, suspicious: 4, phishing: 4, spam: 4, bec: 0 },
	},
	{
		domain: "midco.example",
		mailboxesCount: 3,
		threatsBlocked24h: 9,
		openCases: 2,
		verdictMix: { safe: 6, suspicious: 1, phishing: 1, spam: 1, bec: 0 },
	},
];

function rowDomains(): string[] {
	const tableBody = screen.getByRole("table").querySelector("tbody");
	if (!tableBody) return [];
	return Array.from(tableBody.querySelectorAll("tr")).map(
		(tr) => tr.querySelector("td")?.textContent?.trim() ?? "",
	);
}

describe("DomainsListRoute (#141)", () => {
	beforeEach(() => {
		refetch.mockReset();
	});

	it("renders the loader while the query is pending", () => {
		queryState = { data: undefined, isLoading: true, isError: false };
		renderDomainsList();
		expect(screen.getByText(/^Domains\.$/)).toBeInTheDocument();
		expect(screen.queryByRole("table")).not.toBeInTheDocument();
	});

	it("renders the empty state when no domains are provisioned", () => {
		queryState = { data: [], isLoading: false, isError: false };
		renderDomainsList();
		expect(screen.getByText(/no domains yet/i)).toBeInTheDocument();
	});

	it("defaults to alphabetical sort by domain name", () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderDomainsList();
		expect(rowDomains()).toEqual([
			"acme.com",
			"midco.example",
			"zulu.example",
		]);
	});

	it("re-orders rows when the operator picks a numeric sort key", async () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderDomainsList();

		const sort = screen.getByLabelText(/sort domains/i);
		await userEvent.selectOptions(sort, "threatsBlocked24h");
		// Highest threats-blocked first: acme(42) → midco(9) → zulu(3).
		expect(rowDomains()).toEqual([
			"acme.com",
			"midco.example",
			"zulu.example",
		]);

		await userEvent.selectOptions(sort, "openCases");
		// Highest open-cases first: acme(7) → midco(2) → zulu(1).
		expect(rowDomains()).toEqual([
			"acme.com",
			"midco.example",
			"zulu.example",
		]);

		await userEvent.selectOptions(sort, "mailboxesCount");
		// Highest mailbox count first: acme(5) → midco(3) → zulu(1).
		expect(rowDomains()).toEqual([
			"acme.com",
			"midco.example",
			"zulu.example",
		]);

		await userEvent.selectOptions(sort, "name");
		// Back to alphabetical default.
		expect(rowDomains()).toEqual([
			"acme.com",
			"midco.example",
			"zulu.example",
		]);
	});

	it("narrows the list when the operator types a substring filter (case-insensitive)", async () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderDomainsList();
		const filter = screen.getByLabelText(/filter domains by name/i);

		await userEvent.type(filter, "EXAMPLE");
		// `acme.com` filtered out; the two `.example` domains remain.
		expect(rowDomains()).toEqual(["midco.example", "zulu.example"]);

		// Sort order is preserved across filter changes.
		await userEvent.clear(filter);
		await userEvent.type(filter, "mid");
		expect(rowDomains()).toEqual(["midco.example"]);
	});

	it("renders 'no domains match' empty state when the filter excludes every row", async () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderDomainsList();
		const filter = screen.getByLabelText(/filter domains by name/i);

		await userEvent.type(filter, "nope");
		expect(screen.queryByRole("table")).not.toBeInTheDocument();
		expect(screen.getByText(/no domains match "nope"/i)).toBeInTheDocument();

		// "Clear filter" affordance restores the full list.
		await userEvent.click(
			screen.getByRole("button", { name: /clear filter/i }),
		);
		expect(rowDomains()).toEqual([
			"acme.com",
			"midco.example",
			"zulu.example",
		]);
	});

	it("links each row to /domains/:domain", () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderDomainsList();
		const link = screen.getByRole("link", { name: "acme.com" });
		expect(link).toHaveAttribute("href", "/domains/acme.com");
	});

	it("does not regress: row count matches data length when no filter applied", () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderDomainsList();
		const tbody = screen.getByRole("table").querySelector("tbody")!;
		expect(within(tbody).getAllByRole("row")).toHaveLength(populated.length);
	});
});
