// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// Sidebar mailbox-switcher (#188). The card at the top of the sidebar used
// to be wired to `navigate("/")` — a no-op at the org root and a misleading
// affordance everywhere else (it sported a chevron and a "Select mailbox"
// placeholder). Path (a) of the issue: replace with a base-ui Menu that
// lists the mailboxes the user has access to and navigates on selection.

import { fireEvent, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes, useLocation } from "react-router";

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

function LocationReporter() {
	const loc = useLocation();
	return <div data-testid="location">{loc.pathname}</div>;
}

function renderShellAt(initialEntries: string[]) {
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
				path="/mailboxes"
				element={
					<Shell>
						<LocationReporter />
					</Shell>
				}
			/>
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

// base-ui Menu's trigger opens on `mousedown`, not `click` (the trigger
// passes `event: 'mousedown'` to floating-ui's `useClick`). In a real
// browser `userEvent.click` fires `pointerdown -> mousedown -> ...` and that
// drives the trigger fine, but under jsdom that path doesn't reliably toggle
// the open state — `fireEvent.mouseDown` does, and after a microtask the
// open-transition settles so testing-library can find the popup.
//
// We keep this helper local to the test file rather than reaching for
// `userEvent.pointer({ keys: '[MouseLeft]', target })` because the simpler
// fireEvent path is closer to what the trigger actually subscribes to and
// avoids userEvent's pointer-state bookkeeping interacting with base-ui's
// focus guards.
async function openMenu(trigger: HTMLElement) {
	fireEvent.mouseDown(trigger);
	// Yield for base-ui's mount/transition raf cycle. Without this the popup
	// is in the DOM but still has `data-closed=""` + `hidden=""`.
	await new Promise((r) => setTimeout(r, 50));
}

describe("Shell mailbox switcher (#188)", () => {
	beforeEach(() => {
		mailboxFixture = undefined;
		mailboxesFixture = [];
	});

	it("trigger has aria-haspopup=menu and aria-expanded toggles on open", async () => {
		mailboxesFixture = [
			{ id: "m1", email: "alice@acme.com", name: "Alice" },
			{ id: "m2", email: "bob@acme.com", name: "Bob" },
		];
		renderShellAt(["/"]);

		// Trigger label reads "Select mailbox" at the org root because no
		// mailbox is active — same string the old card displayed, just now
		// backed by a real picker.
		const trigger = screen.getByRole("button", { name: /select mailbox/i });
		expect(trigger).toHaveAttribute("aria-haspopup", "menu");
		expect(trigger).toHaveAttribute("aria-expanded", "false");

		await openMenu(trigger);

		const menu = await screen.findByRole("menu");
		expect(menu).toBeInTheDocument();
		expect(trigger).toHaveAttribute("aria-expanded", "true");
	});

	it("opens from / and selecting a mailbox navigates to its dashboard", async () => {
		mailboxesFixture = [
			{ id: "m1", email: "alice@acme.com", name: "Alice" },
			{ id: "m2", email: "bob@acme.com", name: "Bob" },
		];
		const user = userEvent.setup();
		renderShellAt(["/"]);

		expect(screen.getByTestId("location")).toHaveTextContent("/");

		const trigger = screen.getByRole("button", { name: /select mailbox/i });
		await openMenu(trigger);

		const menu = await screen.findByRole("menu");
		const bobItem = within(menu).getByRole("menuitem", { name: /bob/i });
		await user.click(bobItem);

		// Navigated to the per-mailbox landing route. The :mailboxId in the
		// URL is encoded — fixture ids are URL-safe so they round-trip
		// unchanged.
		expect(screen.getByTestId("location")).toHaveTextContent(
			"/mailbox/m2/dashboard",
		);
	});

	it("marks the active mailbox in the menu list", async () => {
		mailboxFixture = { id: "m1", email: "alice@acme.com", name: "Alice" };
		mailboxesFixture = [
			mailboxFixture,
			{ id: "m2", email: "bob@acme.com", name: "Bob" },
		];
		renderShellAt(["/mailbox/m1/dashboard"]);

		// On the per-mailbox route the trigger label switches to the active
		// mailbox name.
		const trigger = screen.getByRole("button", { name: /alice/i });
		await openMenu(trigger);

		const menu = await screen.findByRole("menu");
		// The active row carries the "Active mailbox" check glyph; the
		// inactive row does not.
		expect(within(menu).getByLabelText(/active mailbox/i)).toBeInTheDocument();
		// Sanity: there's exactly one active marker, not one per row.
		expect(within(menu).getAllByLabelText(/active mailbox/i)).toHaveLength(1);
	});

	it("with zero mailboxes shows the empty state with a link to /mailboxes", async () => {
		mailboxesFixture = [];
		const user = userEvent.setup();
		renderShellAt(["/"]);

		const trigger = screen.getByRole("button", { name: /select mailbox/i });
		await openMenu(trigger);

		const menu = await screen.findByRole("menu");
		// No selectable mailbox rows.
		expect(within(menu).queryAllByRole("menuitem")).toHaveLength(0);
		expect(within(menu).getByText(/no mailboxes yet/i)).toBeInTheDocument();

		const link = within(menu).getByRole("link", { name: /provision a mailbox/i });
		expect(link).toHaveAttribute("href", "/mailboxes");

		await user.click(link);
		expect(screen.getByTestId("location")).toHaveTextContent("/mailboxes");
	});

	// #203: search filter when mailbox count exceeds the threshold (>8).
	describe("search filter (#203)", () => {
		function makeMailboxes(n: number): MailboxFixture[] {
			return Array.from({ length: n }, (_, i) => ({
				id: `m${i + 1}`,
				email: `user${i + 1}@acme.com`,
				name: `Person ${i + 1}`,
			}));
		}

		it("does not render the search input when count <= 8", async () => {
			mailboxesFixture = makeMailboxes(8);
			renderShellAt(["/"]);

			const trigger = screen.getByRole("button", { name: /select mailbox/i });
			await openMenu(trigger);

			const menu = await screen.findByRole("menu");
			expect(
				within(menu).queryByRole("textbox", { name: /search mailboxes/i }),
			).toBeNull();
			// All 8 rows should be present.
			expect(within(menu).getAllByRole("menuitem")).toHaveLength(8);
		});

		it("renders the search input when count > 8 and filters by name substring", async () => {
			mailboxesFixture = makeMailboxes(12);
			// Give one mailbox a distinctive name so the substring search has
			// something unambiguous to match.
			mailboxesFixture[6] = {
				id: "m7",
				email: "needle@acme.com",
				name: "Needle Person",
			};
			renderShellAt(["/"]);

			const trigger = screen.getByRole("button", { name: /select mailbox/i });
			await openMenu(trigger);

			const menu = await screen.findByRole("menu");
			const input = within(menu).getByRole("textbox", {
				name: /search mailboxes/i,
			});
			expect(input).toBeInTheDocument();
			// All 12 rows visible before filtering.
			expect(within(menu).getAllByRole("menuitem")).toHaveLength(12);

			fireEvent.change(input, { target: { value: "needle" } });

			// Only the matching row remains.
			const items = within(menu).getAllByRole("menuitem");
			expect(items).toHaveLength(1);
			expect(items[0]).toHaveTextContent(/needle/i);
		});

		it("filter is case-insensitive and matches email substring", async () => {
			mailboxesFixture = makeMailboxes(12);
			mailboxesFixture[3] = {
				id: "m4",
				email: "unique-handle@acme.com",
				name: "Plain Name",
			};
			renderShellAt(["/"]);

			const trigger = screen.getByRole("button", { name: /select mailbox/i });
			await openMenu(trigger);

			const menu = await screen.findByRole("menu");
			const input = within(menu).getByRole("textbox", {
				name: /search mailboxes/i,
			});

			fireEvent.change(input, { target: { value: "UNIQUE-HANDLE" } });

			const items = within(menu).getAllByRole("menuitem");
			expect(items).toHaveLength(1);
			expect(items[0]).toHaveTextContent(/Plain Name/);
		});

		it('shows "No matches" when the filter empties the list, and clearing restores it', async () => {
			mailboxesFixture = makeMailboxes(12);
			renderShellAt(["/"]);

			const trigger = screen.getByRole("button", { name: /select mailbox/i });
			await openMenu(trigger);

			const menu = await screen.findByRole("menu");
			const input = within(menu).getByRole("textbox", {
				name: /search mailboxes/i,
			});

			fireEvent.change(input, { target: { value: "zzznomatchzzz" } });
			expect(within(menu).queryAllByRole("menuitem")).toHaveLength(0);
			expect(within(menu).getByText(/no matches/i)).toBeInTheDocument();

			fireEvent.change(input, { target: { value: "" } });
			// Full list restored.
			expect(within(menu).getAllByRole("menuitem")).toHaveLength(12);
		});
	});

	it("Escape closes the menu", async () => {
		mailboxesFixture = [{ id: "m1", email: "alice@acme.com", name: "Alice" }];
		const user = userEvent.setup();
		renderShellAt(["/"]);

		const trigger = screen.getByRole("button", { name: /select mailbox/i });
		await openMenu(trigger);
		await screen.findByRole("menu");

		await user.keyboard("{Escape}");
		// `findByRole` w/ a polling negative would be ideal but RTL doesn't
		// expose one; wait briefly for base-ui's close transition to detach
		// the popup, then assert. The visible menu is gone — that's the
		// observable Escape behavior the issue calls out. (`aria-expanded`
		// on the trigger lags by a render under jsdom because the open-state
		// store updates on a focus-cycle that the headless test environment
		// doesn't fully run; checking the popup itself is the more honest
		// assertion here.)
		await new Promise((r) => setTimeout(r, 50));
		expect(screen.queryByRole("menu")).toBeNull();
	});
});
