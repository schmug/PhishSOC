// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

// Org-wide /settings nav entry (#153). Distinct from the per-mailbox
// `/mailbox/:id/settings` entry which is gated on a mailbox being selected.
// This entry must surface even when no mailbox has been picked, otherwise the
// org settings page is undiscoverable from a cold start.

interface MailboxFixture {
	id: string;
	email: string;
	name: string;
}

let mailboxFixture: MailboxFixture | undefined = undefined;
let mailboxesFixture: MailboxFixture[] = [];

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({ data: mailboxFixture }),
	useMailboxes: () => ({ data: mailboxesFixture }),
}));

vi.mock("~/queries/domains", () => ({
	useDomainStats: () => ({
		data: undefined,
		isLoading: false,
		isError: false,
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

function renderShellAt(initialEntries: string[]) {
	return renderWithProviders(
		<Routes>
			<Route
				path="/settings"
				element={
					<Shell>
						<div>org settings page</div>
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

describe("Shell org-settings nav entry (#153)", () => {
	beforeEach(() => {
		mailboxFixture = undefined;
		mailboxesFixture = [];
	});

	it("renders the 'Org settings' link even when no mailbox is selected", () => {
		// Cold-start fixture: no mailbox in the route, no mailboxes loaded.
		// The whole point of this entry is that the org settings page must
		// be reachable before the operator picks a mailbox.
		renderShellAt(["/"]);

		const link = screen.getByRole("link", { name: /org settings/i });
		expect(link).toHaveAttribute("href", "/settings");
	});

	it("highlights the Org settings nav entry when active on /settings", () => {
		renderShellAt(["/settings"]);

		const link = screen.getByRole("link", { name: /org settings/i });
		// `NavLink` adds `aria-current="page"` on the active match. Asserting
		// on aria-current keeps the test decoupled from styling classes.
		expect(link).toHaveAttribute("aria-current", "page");
	});

	it("does not mark Org settings active on the per-mailbox /mailbox/:id/settings route", () => {
		mailboxFixture = { id: "m1", email: "alice@acme.com", name: "Alice" };
		mailboxesFixture = [mailboxFixture];

		renderShellAt(["/mailbox/m1/settings"]);

		const orgLink = screen.getByRole("link", { name: /^org settings$/i });
		// `end` prop on the NavLink prevents `/settings` from matching as a
		// prefix of `/mailbox/:id/settings`.
		expect(orgLink).not.toHaveAttribute("aria-current", "page");
	});
});
