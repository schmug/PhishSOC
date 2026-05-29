// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import type { DashboardSummary } from "~/types";

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({
		data: { id: "m1", email: "alice@acme.com", name: "Alice" },
	}),
	useMailboxes: () => ({
		data: [{ id: "m1", email: "alice@acme.com", name: "Alice" }],
	}),
}));

const queryState: {
	data: DashboardSummary | undefined;
	isLoading: boolean;
	isError: boolean;
} = {
	data: {
		now: "2026-04-30T12:00:00Z",
		threatsBlocked: 0,
		openCases: 0,
		hubContributions: 0,
		corroboration: null,
		pipelineSuccess: 0.98,
		p95Ms: null,
		threatPressure: [],
		recentCases: [],
	},
	isLoading: false,
	isError: false,
};

vi.mock("~/queries/dashboard", () => ({
	useDashboardSummary: () => queryState,
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

describe("Shell sidebar footer (#189)", () => {
	it("does not render the hardcoded 'SOC analyst' placeholder", () => {
		renderShell();
		expect(screen.queryByText(/SOC analyst/i)).not.toBeInTheDocument();
	});

	it("does not render the hardcoded 'Preview' placeholder text", () => {
		renderShell();
		// Scope: the dead avatar slot's "Preview" caption must be gone. There
		// should be no element whose text content is exactly "Preview".
		const previewNodes = screen
			.queryAllByText(/^Preview$/i)
			// Filter out anything that's part of a larger phrase rendered elsewhere
			// (defensive — there is no such usage today).
			.filter((node) => node.textContent?.trim() === "Preview");
		expect(previewNodes).toHaveLength(0);
	});

	it("does not render the 'SA' avatar circle", () => {
		renderShell();
		// The dead avatar was a div containing only the literal "SA".
		const saNodes = screen
			.queryAllByText(/^SA$/)
			.filter((node) => node.textContent?.trim() === "SA");
		expect(saNodes).toHaveLength(0);
	});

	it("still renders the theme toggle in the sidebar footer", () => {
		renderShell();
		// The toggle's aria-label flips with theme; either label proves it's
		// still mounted.
		const toggle = screen.queryByRole("button", {
			name: /Switch to (light|dark) mode/i,
		});
		expect(toggle).toBeInTheDocument();
	});
});
