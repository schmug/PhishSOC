// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import type { DomainStats } from "~/types";

// Shared mutable state so individual tests can vary the domain query result
// without reaching into the mock factory closure.
let domainQueryState: {
	data: DomainStats | undefined;
	isLoading: boolean;
	isError: boolean;
} = { data: undefined, isLoading: false, isError: false };

vi.mock("~/queries/domains", () => ({
	useDomainStats: (domain: string | undefined) => {
		// Mirror the production hook's `enabled: !!domain` gate so the test
		// surfaces the same loading/empty contract.
		if (!domain) {
			return { data: undefined, isLoading: false, isError: false };
		}
		return domainQueryState;
	},
}));

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({
		data: { id: "m1", email: "alice@acme.com", name: "Alice" },
	}),
	useMailboxes: () => ({
		data: [{ id: "m1", email: "alice@acme.com", name: "Alice" }],
	}),
}));

vi.mock("~/queries/dashboard", () => ({
	useDashboardSummary: () => ({
		data: undefined,
		isLoading: false,
		isError: false,
	}),
}));

vi.mock("~/queries/folders", () => ({
	useFolders: () => ({ data: [] }),
}));

import Shell from "~/components/phishsoc/Shell";
import { renderWithProviders } from "./test-utils";

const populated: DomainStats = {
	now: "2026-04-29T12:00:00Z",
	domain: "acme.com",
	mailboxes: [
		{ id: "m1", email: "alice@acme.com", name: "Alice" },
		{ id: "m2", email: "bob@acme.com", name: "Bob" },
	],
	threatsBlocked24h: 0,
	threatsBlocked7d: 0,
	openCases: 0,
	verdictMix: { safe: 0, suspicious: 0, phishing: 0, spam: 0, bec: 0 },
	dmarcPosture: {
		p: null,
		sp: null,
		pct: null,
		ruaConfigured: null,
		alignmentRate: null,
	},
	mtaStsPosture: {
		mode: null,
		mx: null,
		maxAge: null,
		id: null,
	},
	bimiPosture: {
		configured: false as const,
	},
	spfPosture: {
		record: null,
		allQualifier: null,
		mechanismCount: null,
		includes: null,
		totalLookups: null,
		exceedsLimit: null,
	},
	tlsRptPosture: {
		configured: null,
		endpoints: null,
	},
	dkimPosture: {
		selectors: [],
	},
	dnssec: {
		signed: false as const,
	},
	recentCases: [],
};

function renderShellAt(initialEntries: string[]) {
	return renderWithProviders(
		<Routes>
			<Route
				path="/domains/:domain"
				element={
					<Shell>
						<div>domain page</div>
					</Shell>
				}
			/>
			<Route
				path="/mailbox/:mailboxId/*"
				element={
					<Shell>
						<div>mailbox page</div>
					</Shell>
				}
			/>
			<Route
				path="*"
				element={
					<Shell>
						<div>fallback page</div>
					</Shell>
				}
			/>
		</Routes>,
		{ initialEntries },
	);
}

describe("Shell domain-scoped sidebar (#139)", () => {
	it("renders 'Mailboxes in :domain' on /domains/:domain when stats have loaded", () => {
		domainQueryState = { data: populated, isLoading: false, isError: false };
		renderShellAt(["/domains/acme.com"]);

		// Section label is present.
		expect(screen.getByText(/mailboxes in acme\.com/i)).toBeInTheDocument();

		// Each mailbox renders as a link to /mailbox/:id/dashboard.
		const aliceLink = screen.getByRole("link", { name: /alice@acme\.com/i });
		expect(aliceLink).toHaveAttribute("href", "/mailbox/m1/dashboard");
		const bobLink = screen.getByRole("link", { name: /bob@acme\.com/i });
		expect(bobLink).toHaveAttribute("href", "/mailbox/m2/dashboard");
	});

	it("falls back to org-level nav while the domain query is pending (no flash of 'undefined')", () => {
		domainQueryState = { data: undefined, isLoading: true, isError: false };
		const { container } = renderShellAt(["/domains/acme.com"]);

		// No domain section header rendered.
		expect(screen.queryByText(/mailboxes in/i)).toBeNull();
		// And no leaked "undefined" text from a half-rendered list.
		expect(container.textContent ?? "").not.toContain("undefined");

		// Org-level nav still shows.
		expect(screen.getByRole("link", { name: /org overview/i })).toBeInTheDocument();
		// Sidebar `Domains` entry. After #184 the breadcrumb also adds a
		// `Domains` link on `/domains/:domain`, so `getAllByRole` returns
		// both — at least one must be present.
		expect(
			screen.getAllByRole("link", { name: /^Domains$/ }).length,
		).toBeGreaterThanOrEqual(1);
	});

	it("does not render the domain section on /, /mailboxes, /domains, or /mailbox/:id/...", () => {
		// Even if the (cached) query had data, the route match should keep
		// the section out of the DOM on these other routes.
		domainQueryState = { data: populated, isLoading: false, isError: false };

		for (const path of [
			"/",
			"/mailboxes",
			"/domains",
			"/mailbox/m1/dashboard",
		]) {
			const { unmount } = renderShellAt([path]);
			expect(
				screen.queryByText(/mailboxes in acme\.com/i),
				`should not render the domain section at ${path}`,
			).toBeNull();
			unmount();
		}
	});

	it("URL-decodes the :domain route param in the section label", () => {
		// Some callers might percent-encode the domain. The label should
		// surface the human-readable form, matching the breadcrumb.
		domainQueryState = {
			data: { ...populated, domain: "héllo.example" },
			isLoading: false,
			isError: false,
		};
		renderShellAt([`/domains/${encodeURIComponent("héllo.example")}`]);
		expect(screen.getByText(/mailboxes in héllo\.example/i)).toBeInTheDocument();
	});

	it("includes the domain mailboxes in the mobile drawer too", async () => {
		domainQueryState = { data: populated, isLoading: false, isError: false };
		const { default: userEvent } = await import("@testing-library/user-event");
		const user = userEvent.setup();
		renderShellAt(["/domains/acme.com"]);

		// Open the drawer and confirm the same domain section is rendered
		// inside it (the shared NavContents fragment runs in both places).
		await user.click(screen.getByRole("button", { name: /open menu/i }));
		const drawer = await screen.findByRole("dialog", {
			name: /primary navigation/i,
		});
		expect(within(drawer).getByText(/mailboxes in acme\.com/i)).toBeInTheDocument();
	});
});
