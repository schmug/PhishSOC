// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * "Link domains" dashboard card (#740): the empty state and one populated
 * domain row with its per-host breakdown. `DashboardRoute` renders this card
 * alongside the existing KPI/threat-pressure/recent-cases cards; those are
 * covered by tests/frontend/dashboard.test.tsx and are not re-asserted here.
 */

import { screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import type { DashboardSummary, LinkDomainsSummary } from "~/types";
import { shellDashboardMock } from "./shell-mocks";

let dashboardData: DashboardSummary | undefined;
let linkDomainsData: LinkDomainsSummary | undefined;

vi.mock("~/queries/dashboard", () =>
	shellDashboardMock({
		useDashboardSummary: () => ({ data: dashboardData, isLoading: false, isError: false, refetch: vi.fn() }),
		useLinkDomains: () => ({ data: linkDomainsData }),
	}),
);

import DashboardRoute from "~/routes/dashboard";
import { renderWithProviders } from "./test-utils";

function renderDashboard() {
	return renderWithProviders(
		<Routes>
			<Route path="/mailbox/:mailboxId/dashboard" element={<DashboardRoute />} />
		</Routes>,
		{ initialEntries: ["/mailbox/m1/dashboard"] },
	);
}

const baseDashboard: DashboardSummary = {
	now: "2026-04-29T12:00:00Z",
	threatsBlocked: 3,
	openCases: 0,
	hubContributions: 0,
	corroboration: null,
	pipelineSuccess: null,
	p95Ms: null,
	threatPressure: new Array(12).fill(0),
	recentCases: [],
};

describe("DashboardRoute — Link domains card", () => {
	beforeEach(() => {
		dashboardData = baseDashboard;
	});

	it("renders the empty state when there is no link-domains data yet", () => {
		linkDomainsData = undefined;
		renderDashboard();
		expect(screen.getByText("Link domains")).toBeInTheDocument();
		expect(screen.getByText(/no recurring link domains/i)).toBeInTheDocument();
	});

	it("renders the empty state when the rollup has no qualifying domains", () => {
		linkDomainsData = { window_days: 30, hosts: [], domains: [] };
		renderDashboard();
		expect(screen.getByText(/no recurring link domains/i)).toBeInTheDocument();
	});

	it("renders one populated domain row with its per-host breakdown", () => {
		linkDomainsData = {
			window_days: 30,
			hosts: [
				{ name: "login.evil-example.com", emails: 4, flagged: 4, phishing: 4, spam: 0 },
			],
			domains: [
				{ name: "evil-example.com", emails: 5, flagged: 4, phishing: 4, spam: 0 },
			],
		};
		renderDashboard();

		expect(screen.getByText(/link domains · 30d/i)).toBeInTheDocument();
		expect(screen.queryByText(/no recurring link domains/i)).not.toBeInTheDocument();

		// Domain row.
		expect(screen.getByText("evil-example.com")).toBeInTheDocument();
		// Nested host row underneath it.
		expect(screen.getByText("login.evil-example.com")).toBeInTheDocument();

		// Domain: 5 emails, 4/5 flagged and phishing (80%), 0/5 spam.
		// Host: 4 emails, 4/4 flagged and phishing (100%), 0/4 spam.
		expect(screen.getByText("5")).toBeInTheDocument();
		expect(screen.getByText("4")).toBeInTheDocument();
		expect(screen.getAllByText("80%")).toHaveLength(2); // domain flagged + phishing
		expect(screen.getAllByText("100%")).toHaveLength(2); // host flagged + phishing
		expect(screen.getAllByText("0%")).toHaveLength(2); // domain spam + host spam
	});
});
