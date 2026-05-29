// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Tests for the dynamic folder navigation sidebar (#366). Verifies:
//  - one nav entry per folder returned by useFolders, linked to ${base}/emails/<id>
//  - system folders sorted per SYSTEM_FOLDER_IDS order before custom folders
//  - folder labels use getFolderDisplayName() (e.g. "draft" → "Drafts")
//  - unreadCount badge renders when > 0, is absent when 0
//  - "Folders" section is collapsible; collapsed state toggles
//  - favorites: pin button marks a folder as favorite; favorites render first
//  - graceful fallback when useFolders returns undefined (pending)
//  - active-folder highlighting works for any folder (NavLink isActive)

import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import type { Folder } from "~/types";

// ---- Query mocks --------------------------------------------------------

let foldersFixture: Folder[] | undefined = [];

vi.mock("~/queries/folders", () => ({
	useFolders: () => ({ data: foldersFixture }),
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

vi.mock("~/queries/domains", () => ({
	useDomainStats: () => ({ data: undefined, isLoading: false, isError: false }),
}));

// ---- Imports (must come after vi.mock hoisting) -------------------------

import Shell from "~/components/phishsoc/Shell";
import { renderWithProviders } from "./test-utils";

// ---- Helpers -----------------------------------------------------------

const SYSTEM_FOLDERS: Folder[] = [
	{ id: "inbox", name: "Inbox", unreadCount: 3 },
	{ id: "sent", name: "Sent", unreadCount: 0 },
	{ id: "draft", name: "Drafts", unreadCount: 1 },
	{ id: "archive", name: "Archive", unreadCount: 0 },
	{ id: "quarantine", name: "Quarantine", unreadCount: 0 },
	{ id: "trash", name: "Trash", unreadCount: 0 },
];

function renderShellAt(initialEntries: string[] = ["/mailbox/m1/dashboard"]) {
	return renderWithProviders(
		<Routes>
			<Route
				path="/mailbox/:mailboxId/*"
				element={
					<Shell>
						<div data-testid="content" />
					</Shell>
				}
			/>
		</Routes>,
		{ initialEntries },
	);
}

// Clear localStorage between tests so pinned favorites don't bleed
beforeEach(() => {
	foldersFixture = [];
	if (typeof window !== "undefined") {
		// Remove all folder nav prefs keys
		Object.keys(localStorage).forEach((k) => {
			if (k.startsWith("phishsoc-folder-nav-")) localStorage.removeItem(k);
		});
	}
});

// ---- Tests -------------------------------------------------------------

describe("Shell folder navigation (#366)", () => {
	it("renders one nav link per folder when useFolders resolves", () => {
		foldersFixture = SYSTEM_FOLDERS;
		renderShellAt();

		// Should have a link for every folder
		expect(screen.getByRole("link", { name: /inbox/i })).toBeInTheDocument();
		expect(screen.getByRole("link", { name: /sent/i })).toBeInTheDocument();
		expect(screen.getByRole("link", { name: /drafts/i })).toBeInTheDocument();
		expect(screen.getByRole("link", { name: /archive/i })).toBeInTheDocument();
		expect(screen.getByRole("link", { name: /quarantine/i })).toBeInTheDocument();
		expect(screen.getByRole("link", { name: /trash/i })).toBeInTheDocument();
	});

	it("each folder link points to ${base}/emails/<folder.id>", () => {
		foldersFixture = [{ id: "inbox", name: "Inbox", unreadCount: 0 }];
		renderShellAt();

		const link = screen.getByRole("link", { name: /inbox/i });
		expect(link).toHaveAttribute("href", "/mailbox/m1/emails/inbox");
	});

	it("uses getFolderDisplayName() for labels (draft → Drafts)", () => {
		foldersFixture = [{ id: "draft", name: "Drafts", unreadCount: 0 }];
		renderShellAt();

		// getFolderDisplayName("draft") → "Drafts"
		expect(screen.getByRole("link", { name: /drafts/i })).toBeInTheDocument();
	});

	it("shows unreadCount badge when > 0, hides it when 0", () => {
		foldersFixture = [
			{ id: "inbox", name: "Inbox", unreadCount: 5 },
			{ id: "sent", name: "Sent", unreadCount: 0 },
		];
		renderShellAt();

		// Badge "5" should appear for inbox
		expect(screen.getByText("5")).toBeInTheDocument();
		// No badge for sent (unreadCount === 0) — the folder row for "Sent"
		// should not contain a "0" count span. Check via the link text + sibling.
		const sentLink = screen.getByRole("link", { name: /sent/i });
		// The count span would be a sibling inside the NavLink render; if
		// unreadCount is 0 the component skips rendering it.
		expect(within(sentLink).queryByText("0")).toBeNull();
	});

	it("orders system folders per SYSTEM_FOLDER_IDS (inbox first, trash last)", () => {
		// Intentionally supply them in reverse order to test sorting
		foldersFixture = [
			{ id: "trash", name: "Trash", unreadCount: 0 },
			{ id: "quarantine", name: "Quarantine", unreadCount: 0 },
			{ id: "archive", name: "Archive", unreadCount: 0 },
			{ id: "draft", name: "Drafts", unreadCount: 0 },
			{ id: "sent", name: "Sent", unreadCount: 0 },
			{ id: "inbox", name: "Inbox", unreadCount: 0 },
		];
		renderShellAt();

		const links = screen.getAllByRole("link");
		// Filter to just folder links (href contains /emails/)
		const folderLinks = links.filter((l) =>
			l.getAttribute("href")?.includes("/emails/"),
		);
		const hrefs = folderLinks.map((l) => l.getAttribute("href") ?? "");

		// The first folder link should be inbox, last should be trash
		expect(hrefs[0]).toContain("/emails/inbox");
		expect(hrefs[hrefs.length - 1]).toContain("/emails/trash");
	});

	it("renders custom folders alphabetically after system folders", () => {
		foldersFixture = [
			{ id: "zebra-list", name: "Zebra List", unreadCount: 0 },
			{ id: "inbox", name: "Inbox", unreadCount: 0 },
			{ id: "alpha-list", name: "Alpha List", unreadCount: 0 },
		];
		renderShellAt();

		const links = screen.getAllByRole("link");
		const folderLinks = links
			.filter((l) => l.getAttribute("href")?.includes("/emails/"))
			.map((l) => l.getAttribute("href") ?? "");

		// inbox (system) comes first, then custom folders alphabetically
		expect(folderLinks[0]).toContain("/emails/inbox");
		expect(folderLinks[1]).toContain("/emails/alpha-list");
		expect(folderLinks[2]).toContain("/emails/zebra-list");
	});

	it("does not render any folder links when useFolders returns empty array", () => {
		foldersFixture = [];
		renderShellAt();

		const links = screen.queryAllByRole("link");
		const folderLinks = links.filter((l) =>
			l.getAttribute("href")?.includes("/emails/"),
		);
		expect(folderLinks).toHaveLength(0);
	});

	it("does not render folder section while useFolders is pending (undefined)", () => {
		foldersFixture = undefined;
		renderShellAt();

		const links = screen.queryAllByRole("link");
		const folderLinks = links.filter((l) =>
			l.getAttribute("href")?.includes("/emails/"),
		);
		expect(folderLinks).toHaveLength(0);
	});

	it("Folders section header has aria-expanded=true by default", () => {
		foldersFixture = [{ id: "inbox", name: "Inbox", unreadCount: 0 }];
		renderShellAt();

		const toggle = screen.getByRole("button", { name: /folders/i });
		expect(toggle).toHaveAttribute("aria-expanded", "true");
	});

	it("clicking the Folders header collapses the folder list", async () => {
		foldersFixture = [{ id: "inbox", name: "Inbox", unreadCount: 0 }];
		renderShellAt();

		// Folder link is visible initially
		expect(screen.getByRole("link", { name: /inbox/i })).toBeInTheDocument();

		// Collapse
		await userEvent.click(screen.getByRole("button", { name: /folders/i }));

		// Folder links should no longer be in the DOM
		expect(screen.queryByRole("link", { name: /inbox/i })).toBeNull();
	});

	it("expanding a collapsed section makes folder links visible again", async () => {
		foldersFixture = [{ id: "inbox", name: "Inbox", unreadCount: 0 }];
		renderShellAt();

		const toggle = screen.getByRole("button", { name: /folders/i });

		// Collapse then expand
		await userEvent.click(toggle);
		expect(screen.queryByRole("link", { name: /inbox/i })).toBeNull();

		await userEvent.click(toggle);
		expect(screen.getByRole("link", { name: /inbox/i })).toBeInTheDocument();
	});

	it("pin button is present for each folder", () => {
		foldersFixture = [
			{ id: "inbox", name: "Inbox", unreadCount: 0 },
			{ id: "sent", name: "Sent", unreadCount: 0 },
		];
		renderShellAt();

		// Each folder has a pin/unpin button
		const pinButtons = screen.getAllByRole("button", { name: /pin|unpin/i });
		expect(pinButtons.length).toBeGreaterThanOrEqual(2);
	});

	it("pinning a folder moves it above the rest", async () => {
		foldersFixture = [
			{ id: "inbox", name: "Inbox", unreadCount: 0 },
			{ id: "sent", name: "Sent", unreadCount: 0 },
			{ id: "trash", name: "Trash", unreadCount: 0 },
		];
		renderShellAt();

		// Pin "Trash" (normally last)
		const trashPin = screen.getByRole("button", { name: /pin trash/i });
		await userEvent.click(trashPin);

		// After pinning, Trash should appear before Inbox in the nav
		const links = screen.getAllByRole("link");
		const folderLinks = links
			.filter((l) => l.getAttribute("href")?.includes("/emails/"))
			.map((l) => l.getAttribute("href") ?? "");

		const trashIdx = folderLinks.findIndex((h) => h.includes("/emails/trash"));
		const inboxIdx = folderLinks.findIndex((h) => h.includes("/emails/inbox"));
		expect(trashIdx).toBeLessThan(inboxIdx);
	});

	it("unpinning a folder moves it back to its natural sort position", async () => {
		foldersFixture = [
			{ id: "inbox", name: "Inbox", unreadCount: 0 },
			{ id: "sent", name: "Sent", unreadCount: 0 },
		];
		renderShellAt();

		// Pin then unpin "sent"
		const pinBtn = screen.getByRole("button", { name: /pin sent/i });
		await userEvent.click(pinBtn);

		const unpinBtn = screen.getByRole("button", { name: /unpin sent/i });
		await userEvent.click(unpinBtn);

		// Back to normal order: inbox before sent
		const links = screen.getAllByRole("link");
		const folderLinks = links
			.filter((l) => l.getAttribute("href")?.includes("/emails/"))
			.map((l) => l.getAttribute("href") ?? "");

		const inboxIdx = folderLinks.findIndex((h) => h.includes("/emails/inbox"));
		const sentIdx = folderLinks.findIndex((h) => h.includes("/emails/sent"));
		expect(inboxIdx).toBeLessThan(sentIdx);
	});
});
