// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Tests for the home-route empty-state and CF Access error UX (#68 Option A).
// Covers: EmptyOrg first-run checklist (G1, G3) and OrgError CF Access
// detection (G2).

import { screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import { ApiError } from "~/services/api";
import type { OrgOverview } from "~/types";
import {
	shellDashboardMock,
	shellDomainsMock,
	shellMailboxesMock,
} from "./shell-mocks";

// Mutable query state threaded through the vi.mock factory.
const refetch = vi.fn();
let orgQueryState: {
	data: OrgOverview | undefined;
	isLoading: boolean;
	isError: boolean;
	error: unknown;
	refetch: () => void;
};

vi.mock("~/queries/org", () => ({
	useOrgOverview: () => orgQueryState,
}));

vi.mock("~/queries/mailboxes", () => shellMailboxesMock());
vi.mock("~/queries/dashboard", () => shellDashboardMock());
vi.mock("~/queries/domains", () =>
	shellDomainsMock({
		useDomains: () => ({ data: [] }),
	}),
);

vi.mock("~/hooks/useAutoProvisionMailboxes", () => ({
	useAutoProvisionMailboxes: () => undefined,
}));

vi.mock("~/queries/folders", () => ({
	useFolders: () => ({ data: [] }),
}));

import HomeRoute from "~/routes/home";
import { renderWithProviders } from "./test-utils";

const EMPTY_ORG: OrgOverview = {
	now: "2026-05-14T00:00:00Z",
	threatsBlocked24h: 0,
	threatsBlocked7d: 0,
	openCasesTotal: 0,
	mailboxesCount: 0,
	domainsCount: 0,
	hubContributions24h: 0,
	verdictMix: { safe: 0, suspicious: 0, phishing: 0, spam: 0, bec: 0 },
	verdictMix7d: { safe: 0, suspicious: 0, phishing: 0, spam: 0, bec: 0 },
	topThreats: [],
	pipelineHealth: { successRate24h: null, p95Ms: null, runs24h: 0 },
};

function renderHome() {
	return renderWithProviders(
		<Routes>
			<Route path="/" element={<HomeRoute />} />
		</Routes>,
		{ initialEntries: ["/"] },
	);
}

describe("HomeRoute — EmptyOrg (G1, G3)", () => {
	beforeEach(() => {
		refetch.mockReset();
		orgQueryState = {
			data: EMPTY_ORG,
			isLoading: false,
			isError: false,
			error: null,
			refetch,
		};
	});

	it("shows the SOC-framed heading when there are no mailboxes", () => {
		renderHome();
		expect(
			screen.getByText(/No mailboxes yet — set one up to start triaging mail/i),
		).toBeInTheDocument();
	});

	it("renders all four first-run checklist items", () => {
		renderHome();
		expect(screen.getByText(/Configure Cloudflare Email Routing/i)).toBeInTheDocument();
		expect(screen.getByText(/Create your first mailbox/i)).toBeInTheDocument();
		expect(screen.getByText(/Set up domain security/i)).toBeInTheDocument();
		expect(screen.getByText(/Connect a threat-intel hub/i)).toBeInTheDocument();
	});

	it("links checklist items to the correct routes", () => {
		renderHome();
		const mailboxLink = screen.getByRole("link", { name: /Go to Mailboxes/i });
		const domainsLink = screen.getByRole("link", { name: /Go to Domains/i });
		const hubLink = screen.getByRole("link", { name: /Go to Hub/i });
		expect(mailboxLink).toHaveAttribute("href", "/mailboxes");
		expect(domainsLink).toHaveAttribute("href", "/domains");
		expect(hubLink).toHaveAttribute("href", "/hub");
	});
});

describe("HomeRoute — OrgError (G2)", () => {
	beforeEach(() => {
		refetch.mockReset();
	});

	it("shows the generic error message for non-Access errors", () => {
		orgQueryState = {
			data: undefined,
			isLoading: false,
			isError: true,
			error: new Error("network timeout"),
			refetch,
		};
		renderHome();
		expect(screen.getByText(/Couldn't load the org overview/i)).toBeInTheDocument();
		expect(screen.queryByText(/CF Access not configured/i)).not.toBeInTheDocument();
	});

	it("shows the CF Access card for a 401 ApiError", () => {
		orgQueryState = {
			data: undefined,
			isLoading: false,
			isError: true,
			error: new ApiError(401, {}),
			refetch,
		};
		renderHome();
		expect(screen.getByText(/CF Access not configured/i)).toBeInTheDocument();
		expect(screen.queryByText(/Couldn't load the org overview/i)).not.toBeInTheDocument();
	});

	it("shows the CF Access card for a 403 ApiError", () => {
		orgQueryState = {
			data: undefined,
			isLoading: false,
			isError: true,
			error: new ApiError(403, {}),
			refetch,
		};
		renderHome();
		expect(screen.getByText(/CF Access not configured/i)).toBeInTheDocument();
	});

	it("CF Access card has a troubleshooting link", () => {
		orgQueryState = {
			data: undefined,
			isLoading: false,
			isError: true,
			error: new ApiError(401, {}),
			refetch,
		};
		renderHome();
		const link = screen.getByRole("link", { name: /Troubleshooting steps/i });
		expect(link).toHaveAttribute(
			"href",
			"https://github.com/schmug/PhishSOC/blob/main/README.md#troubleshooting-access",
		);
	});
});
