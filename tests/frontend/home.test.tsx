// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import type { DomainListEntry, OrgOverview } from "~/types";
import {
	shellDashboardMock,
	shellDomainsMock,
	shellMailboxesMock,
} from "./shell-mocks";

const refetch = vi.fn();
let queryState: {
	data: OrgOverview | undefined;
	isLoading: boolean;
	isError: boolean;
};

vi.mock("~/queries/org", () => ({
	useOrgOverview: () => ({ ...queryState, refetch }),
}));

// `TopDomainsCard` (#141) consumes `useDomains()`. Default to an empty list
// so existing assertions (which were written before the widget existed) keep
// passing; tests that exercise the widget override `domainsState` per case.
// `useDomainStats` is provided by `shellDomainsMock()` for Shell — at `/` it
// gates on `enabled: false` but the import still has to resolve.
let domainsState: {
	data: DomainListEntry[] | undefined;
	isLoading: boolean;
	isError: boolean;
} = { data: [], isLoading: false, isError: false };

vi.mock("~/queries/domains", () =>
	shellDomainsMock({
		useDomains: () => ({ ...domainsState, refetch: vi.fn() }),
	}),
);

// The org-overview home page renders an "N mailboxes" hint sourced from
// `useMailboxes`; Shell also consumes `useMailbox`. The shared factory
// returns the empty-list / undefined defaults that keep render fan-out out
// of the real fetchers.
vi.mock("~/queries/mailboxes", () => shellMailboxesMock());

// Shell renders the per-mailbox dashboard summary into the pipeline pill;
// at "/" mailboxId is undefined and the query is disabled, but the hook is
// still imported, so the shared default keeps the test independent of
// TanStack internals.
vi.mock("~/queries/dashboard", () => shellDashboardMock());

// `useAutoProvisionMailboxes` reads config + mailboxes and may fire a POST
// when EMAIL_ADDRESSES is set. The org-overview test doesn't exercise that
// path, so stub it out to keep the surface focused.
vi.mock("~/hooks/useAutoProvisionMailboxes", () => ({
	useAutoProvisionMailboxes: () => undefined,
}));

vi.mock("~/queries/folders", () => ({
	useFolders: () => ({ data: [] }),
}));

import HomeRoute from "~/routes/home";
import { renderWithProviders } from "./test-utils";

function renderHome() {
	return renderWithProviders(
		<Routes>
			<Route path="/" element={<HomeRoute />} />
			<Route path="/mailboxes" element={<div>Mailboxes page</div>} />
			<Route path="/domains" element={<div>Domains list page</div>} />
			<Route
				path="/domains/:domain"
				element={<div>Domain detail page</div>}
			/>
		</Routes>,
		{ initialEntries: ["/"] },
	);
}

const populated: OrgOverview = {
	now: "2026-04-29T12:00:00Z",
	threatsBlocked24h: 12,
	threatsBlocked7d: 84,
	openCasesTotal: 5,
	mailboxesCount: 3,
	domainsCount: 2,
	hubContributions24h: 4,
	verdictMix: { safe: 50, suspicious: 6, phishing: 3, spam: 8, bec: 1 },
	verdictMix7d: { safe: 360, suspicious: 40, phishing: 21, spam: 56, bec: 7 },
	topThreats: [
		{
			category: "phishing",
			count: 9,
			samples: [
				{ emailId: "e1", subject: "Reset your password", sender: "fake@bank.example" },
				{ emailId: "e2", subject: "Invoice attached", sender: "billing@evil.example" },
			],
		},
		{ category: "spam", count: 4 },
	],
	pipelineHealth: { successRate24h: 0.92, p95Ms: null, runs24h: 200 },
};

const empty: OrgOverview = {
	now: "2026-04-29T12:00:00Z",
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

describe("HomeRoute (org overview)", () => {
	beforeEach(() => {
		refetch.mockReset();
		// Reset the domains-query mock to its default empty state. Tests that
		// exercise the "Top domains" widget override this explicitly so a
		// stray fixture from a previous test can't bleed across cases.
		domainsState = { data: [], isLoading: false, isError: false };
	});

	it("renders the loader while the query is pending", () => {
		queryState = { data: undefined, isLoading: true, isError: false };
		renderHome();
		expect(screen.getByText(/across the fleet/i)).toBeInTheDocument();
		expect(screen.queryByText(/threats blocked · 24h/i)).not.toBeInTheDocument();
	});

	it("renders error UI with a working retry when the query fails", async () => {
		queryState = { data: undefined, isLoading: false, isError: true };
		renderHome();
		expect(screen.getByText(/couldn't load the org overview/i)).toBeInTheDocument();
		await userEvent.click(screen.getByRole("button", { name: /retry/i }));
		expect(refetch).toHaveBeenCalledTimes(1);
	});

	it("renders KPIs, verdict mix, and top threats when data is present", () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderHome();
		expect(screen.getByText(/threats blocked · 24h/i)).toBeInTheDocument();
		expect(screen.getByText("12")).toBeInTheDocument(); // threatsBlocked24h
		expect(screen.getByText("84")).toBeInTheDocument(); // threatsBlocked7d
		expect(screen.getByText("92%")).toBeInTheDocument(); // pipelineSuccess
		expect(screen.getByText("3 mailboxes · 2 domains")).toBeInTheDocument();
		expect(screen.getByText(/top threats/i)).toBeInTheDocument();
		// "phishing" appears as both a verdict-mix label and a top-threats
		// category, so assert on count rather than presence.
		expect(screen.getAllByText(/phishing/i).length).toBeGreaterThanOrEqual(2);
		expect(screen.getByText("9")).toBeInTheDocument(); // top-threats count
	});

	it("shows an empty-state CTA linking to /mailboxes when zero mailboxes", () => {
		queryState = { data: empty, isLoading: false, isError: false };
		renderHome();
		expect(screen.getByText(/no mailboxes yet/i)).toBeInTheDocument();
		const cta = screen.getByRole("link", { name: /go to mailboxes/i });
		expect(cta).toHaveAttribute("href", "/mailboxes");
	});

	it("renders '—' for both pipeline KPIs when no scans have run", () => {
		queryState = {
			data: { ...populated, pipelineHealth: { successRate24h: null, p95Ms: null, runs24h: 0 } },
			isLoading: false,
			isError: false,
		};
		renderHome();
		// Both Pipeline success and Pipeline p95 fall back to "—".
		expect(screen.getAllByText("—")).toHaveLength(2);
	});

	it("toggles the verdict-mix card between 24h and 7d windows", async () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderHome();

		// Default view is 24h: total classified count is 50+6+3+8+1 = 68.
		expect(screen.getByText(/68 classified/)).toBeInTheDocument();

		// Switch to the 7d tab — total becomes 360+40+21+56+7 = 484.
		await userEvent.click(screen.getByRole("tab", { name: "7d" }));
		expect(screen.getByText(/484 classified/)).toBeInTheDocument();

		// Switch back to 24h.
		await userEvent.click(screen.getByRole("tab", { name: "24h" }));
		expect(screen.getByText(/68 classified/)).toBeInTheDocument();
	});

	it("expands a top-threats row to reveal sample emails (#101)", async () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderHome();

		// Samples are inside <details>, hidden until expanded — but jsdom keeps
		// them in the DOM either way. Easier to assert via the disclosure
		// element's open state than visibility heuristics.
		const phishingSummary = screen.getByText("phishing").closest("summary");
		expect(phishingSummary).toBeTruthy();
		const details = phishingSummary!.closest("details") as HTMLDetailsElement;
		expect(details.open).toBe(false);

		await userEvent.click(phishingSummary!);
		expect(details.open).toBe(true);

		// Sample rows render the subject + sender for each emailId.
		expect(screen.getByText("Reset your password")).toBeInTheDocument();
		expect(screen.getByText("fake@bank.example")).toBeInTheDocument();
		expect(screen.getByText("Invoice attached")).toBeInTheDocument();
		expect(screen.getByText("billing@evil.example")).toBeInTheDocument();
	});

	it("renders a top-threats category without samples as a count-only row", () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderHome();
		// `spam` has no samples in the populated fixture — should render
		// without a <details> wrapper (older deploys must not regress).
		const spamLabel = screen.getByText("spam");
		expect(spamLabel.closest("details")).toBeNull();
	});

	it("formats p95 latency on the org overview KPI grid", () => {
		queryState = {
			data: { ...populated, pipelineHealth: { successRate24h: 0.92, p95Ms: 1500, runs24h: 200 } },
			isLoading: false,
			isError: false,
		};
		renderHome();
		expect(screen.getByText("1.5s")).toBeInTheDocument();
	});

	// ----- Cross-domain comparison + drill-down (#141) ---------------------

	it("renders the Domains KPI as a link to /domains", () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderHome();
		// "Domains" also appears in the Shell sidebar nav and elsewhere — scope
		// the lookup to the KPI grid (the only place where the label and the
		// numeric value are siblings inside the same card).
		const links = screen
			.getAllByRole("link")
			.filter((el) => el.getAttribute("href") === "/domains");
		// Expect at least one /domains link rendered by HomeRoute itself
		// (Shell may add another from sidebar nav). The KPI card link wraps
		// both the "Domains" label and its numeric value, so check for that.
		const kpiLink = links.find(
			(el) =>
				el.textContent?.includes("Domains") &&
				el.textContent?.includes(String(populated.domainsCount)),
		);
		expect(kpiLink).toBeTruthy();
	});

	it("hides the Top domains widget when only one domain is configured", () => {
		queryState = {
			data: { ...populated, domainsCount: 1 },
			isLoading: false,
			isError: false,
		};
		domainsState = {
			data: [
				{
					domain: "acme.com",
					mailboxesCount: 3,
					threatsBlocked24h: 9,
					openCases: 2,
					verdictMix: { safe: 10, suspicious: 1, phishing: 1, spam: 1, bec: 0 },
				},
			],
			isLoading: false,
			isError: false,
		};
		renderHome();
		expect(
			screen.queryByText(/top domains · 24h/i),
		).not.toBeInTheDocument();
	});

	it("renders the Top domains widget sorted by threats blocked desc with per-row drill-down", () => {
		queryState = { data: populated, isLoading: false, isError: false };
		domainsState = {
			data: [
				{
					domain: "low.example",
					mailboxesCount: 1,
					threatsBlocked24h: 1,
					openCases: 0,
					verdictMix: { safe: 5, suspicious: 0, phishing: 0, spam: 0, bec: 0 },
				},
				{
					domain: "noisy.example",
					mailboxesCount: 4,
					threatsBlocked24h: 42,
					openCases: 3,
					verdictMix: { safe: 5, suspicious: 5, phishing: 5, spam: 5, bec: 0 },
				},
				{
					domain: "mid.example",
					mailboxesCount: 2,
					threatsBlocked24h: 7,
					openCases: 1,
					verdictMix: { safe: 5, suspicious: 1, phishing: 1, spam: 0, bec: 0 },
				},
				{
					domain: "tail.example",
					mailboxesCount: 1,
					threatsBlocked24h: 0,
					openCases: 0,
					verdictMix: { safe: 5, suspicious: 0, phishing: 0, spam: 0, bec: 0 },
				},
			],
			isLoading: false,
			isError: false,
		};
		renderHome();

		const heading = screen.getByText(/top domains · 24h/i);
		const card = heading.closest("div.pp-card") as HTMLElement;
		expect(card).not.toBeNull();

		// First three by threatsBlocked24h desc are noisy → mid → low. The
		// `tail.example` row (count 0) is past the N=3 cap and should not
		// appear.
		const rows = within(card).getAllByRole("listitem");
		expect(rows).toHaveLength(3);
		expect(rows[0]).toHaveTextContent("noisy.example");
		expect(rows[0]).toHaveTextContent("42");
		expect(rows[1]).toHaveTextContent("mid.example");
		expect(rows[2]).toHaveTextContent("low.example");
		expect(within(card).queryByText("tail.example")).not.toBeInTheDocument();

		// Each row is a drill-down link to /domains/:domain.
		const noisyLink = within(rows[0]).getByRole("link", {
			name: /noisy\.example/,
		});
		expect(noisyLink).toHaveAttribute("href", "/domains/noisy.example");

		// Header has a "View all domains" affordance to /domains.
		const viewAll = within(card).getByRole("link", {
			name: /view all domains/i,
		});
		expect(viewAll).toHaveAttribute("href", "/domains");
	});
});
