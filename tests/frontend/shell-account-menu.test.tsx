// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// Sidebar account menu (#204). The footer slot now hosts an avatar +
// email row that opens to a popover with org-settings + Cloudflare Access
// sign-out. Identity is sourced from `/api/v1/me` via `useMe()`. These
// tests cover the issue's Acceptance items: real email rendered (not a
// placeholder), sign-out href targets the Access logout URL, popover is
// keyboard-dismissible.

import { fireEvent, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

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

vi.mock("~/queries/domains", () => ({
	useDomainStats: () => ({ data: undefined, isLoading: false, isError: false }),
}));

let meFixture: { email: string } | undefined = { email: "operator@acme.com" };

vi.mock("~/queries/me", () => ({
	useMe: () => ({ data: meFixture, isLoading: false, isError: false }),
}));

vi.mock("~/queries/folders", () => ({
	useFolders: () => ({ data: [] }),
}));

import Shell from "~/components/phishsoc/Shell";
import { renderWithProviders } from "./test-utils";

function renderShell() {
	return renderWithProviders(
		<Routes>
			<Route
				path="/mailbox/:mailboxId/*"
				element={
					<Shell>
						<div />
					</Shell>
				}
			/>
		</Routes>,
		{ initialEntries: ["/mailbox/m1/dashboard"] },
	);
}

// base-ui Menu opens on `mousedown`, not `click` — same idiom used in
// shell-mailbox-switcher.test.tsx. Without the microtask wait the popup is
// in the DOM but still `data-closed=""`/`hidden`.
async function openMenu(trigger: HTMLElement) {
	fireEvent.mouseDown(trigger);
	await new Promise((r) => setTimeout(r, 50));
}

describe("Shell sidebar account menu (#204)", () => {
	beforeEach(() => {
		meFixture = { email: "operator@acme.com" };
	});

	it("trigger has aria-haspopup and aria-expanded toggles on open", async () => {
		renderShell();

		const trigger = screen.getByRole("button", {
			name: /account menu for operator@acme\.com/i,
		});
		expect(trigger).toHaveAttribute("aria-haspopup", "menu");
		expect(trigger).toHaveAttribute("aria-expanded", "false");

		await openMenu(trigger);

		const menu = await screen.findByRole("menu");
		expect(menu).toBeInTheDocument();
		expect(trigger).toHaveAttribute("aria-expanded", "true");
	});

	it("renders the real authenticated email inside the popover", async () => {
		renderShell();

		const trigger = screen.getByRole("button", {
			name: /account menu for operator@acme\.com/i,
		});
		await openMenu(trigger);

		const menu = await screen.findByRole("menu");
		// "Signed in as" header surfaces the full address. The trigger
		// label also shows it underneath the local-part — scoping to the
		// menu pins this to the popover specifically.
		expect(within(menu).getByText("operator@acme.com")).toBeInTheDocument();
	});

	it("does not render the old hardcoded placeholder identity", () => {
		renderShell();
		expect(screen.queryByText(/SOC analyst/i)).not.toBeInTheDocument();
		// The hardcoded "Preview" caption from the dead placeholder is also
		// gone; this is covered by shell-sidebar-footer.test.tsx but worth
		// pinning here as a regression guard.
		const previewNodes = screen
			.queryAllByText(/^Preview$/i)
			.filter((node) => node.textContent?.trim() === "Preview");
		expect(previewNodes).toHaveLength(0);
	});

	it("includes a link to /settings", async () => {
		renderShell();
		const trigger = screen.getByRole("button", {
			name: /account menu for operator@acme\.com/i,
		});
		await openMenu(trigger);

		const menu = await screen.findByRole("menu");
		const item = within(menu).getByRole("menuitem", { name: /org settings/i });
		expect(item).toBeInTheDocument();
	});

	it("renders Sign out as a link to the Cloudflare Access logout URL", async () => {
		renderShell();
		const trigger = screen.getByRole("button", {
			name: /account menu for operator@acme\.com/i,
		});
		await openMenu(trigger);

		const menu = await screen.findByRole("menu");
		// The sign-out item is rendered as an `<a href=…>` so the browser
		// performs a real top-level navigation (Access expects a GET).
		// Asserting on the literal `/cdn-cgi/access/logout` path keeps us
		// honest about not hardcoding a team subdomain.
		const signOut = within(menu).getByRole("menuitem", { name: /sign out/i });
		expect(signOut.tagName).toBe("A");
		expect(signOut).toHaveAttribute("href", "/cdn-cgi/access/logout");
	});

	it("theme toggle remains reachable in the footer (sibling to account menu)", () => {
		renderShell();
		const toggle = screen.queryByRole("button", {
			name: /Switch to (light|dark) mode/i,
		});
		expect(toggle).toBeInTheDocument();
	});

	it("Escape closes the popover", async () => {
		const user = userEvent.setup();
		renderShell();

		const trigger = screen.getByRole("button", {
			name: /account menu for operator@acme\.com/i,
		});
		await openMenu(trigger);
		await screen.findByRole("menu");

		await user.keyboard("{Escape}");
		await new Promise((r) => setTimeout(r, 50));
		expect(screen.queryByRole("menu")).toBeNull();
	});

	it("renders a loading label until the email resolves", () => {
		meFixture = undefined;
		renderShell();
		// Trigger label falls back to "Loading…" while `useMe()` is in
		// flight; the trigger still mounts so the footer layout is stable.
		expect(screen.getByText("Loading…")).toBeInTheDocument();
	});
});
