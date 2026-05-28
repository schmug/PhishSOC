// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import type { DomainStats } from "~/types";
import {
	shellDashboardMock,
	shellDomainsMock,
	shellMailboxesMock,
} from "./shell-mocks";

const refetch = vi.fn();
let queryState: {
	data: DomainStats | undefined;
	isLoading: boolean;
	isError: boolean;
};

// `useDomainStats` is the route's primary query and Shell's domain-scoped
// sidebar source — both wire through the same hook, so the per-test
// override here drives both.
vi.mock("~/queries/domains", () =>
	shellDomainsMock({
		useDomainStats: () => ({ ...queryState, refetch }),
	}),
);

// Shell pulls in mailbox/dashboard data — the shared factories return the
// same empty-list / undefined defaults so we render the route in isolation
// rather than fanning out to real fetchers.
vi.mock("~/queries/mailboxes", () => shellMailboxesMock());

vi.mock("~/queries/dashboard", () => shellDashboardMock());

import DomainDetailRoute from "~/routes/domain-detail";
import { renderWithProviders } from "./test-utils";

function renderDomainDetail(domain: string) {
	return renderWithProviders(
		<Routes>
			<Route path="/domains/:domain" element={<DomainDetailRoute />} />
			<Route
				path="/mailbox/:mailboxId/dashboard"
				element={<div>Mailbox dashboard</div>}
			/>
		</Routes>,
		{ initialEntries: [`/domains/${encodeURIComponent(domain)}`] },
	);
}

const populated: DomainStats = {
	now: "2026-04-29T12:00:00Z",
	domain: "acme.com",
	mailboxes: [
		{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
		{ id: "bob@acme.com", email: "bob@acme.com", name: "Bob" },
	],
	threatsBlocked24h: 12,
	threatsBlocked7d: 84,
	openCases: 5,
	verdictMix: { safe: 50, suspicious: 6, phishing: 3, spam: 8, bec: 1 },
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
	recentCases: [
		{
			id: "C1",
			title: "Suspicious wire transfer",
			status: "open",
			updated_at: "2026-04-29T11:00:00Z",
		},
	],
};

describe("DomainDetailRoute", () => {
	beforeEach(() => {
		refetch.mockReset();
	});

	it("renders the loader while the query is pending", () => {
		queryState = { data: undefined, isLoading: true, isError: false };
		renderDomainDetail("acme.com");
		// Domain header is always shown (also appears in the breadcrumb);
		// KPIs only after data lands.
		expect(screen.getAllByText("acme.com").length).toBeGreaterThanOrEqual(1);
		expect(screen.getByRole("heading", { name: "acme.com" })).toBeInTheDocument();
		expect(screen.queryByText(/threats blocked · 24h/i)).not.toBeInTheDocument();
	});

	it("renders error UI with a working retry when the query fails", async () => {
		queryState = { data: undefined, isLoading: false, isError: true };
		renderDomainDetail("acme.com");
		expect(screen.getByText(/couldn't load this domain/i)).toBeInTheDocument();
		await userEvent.click(screen.getByRole("button", { name: /retry/i }));
		expect(refetch).toHaveBeenCalledTimes(1);
	});

	it("renders KPIs, mailbox links, and DMARC null-posture affordance", () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderDomainDetail("acme.com");

		// KPIs.
		expect(screen.getByText(/threats blocked · 24h/i)).toBeInTheDocument();
		expect(screen.getByText("12")).toBeInTheDocument();
		expect(screen.getByText("84")).toBeInTheDocument();
		// Open cases = 5.
		expect(screen.getByText("5")).toBeInTheDocument();

		// Each mailbox links to its per-mailbox dashboard. Scope to the main
		// content region — the domain-scoped sidebar nav (#139) also renders
		// links to the same mailboxes, so the unscoped query would now match
		// twice.
		const main = screen.getByRole("main");
		const aliceLink = within(main).getByRole("link", {
			name: /alice@acme.com/i,
		});
		expect(aliceLink).toHaveAttribute(
			"href",
			"/mailbox/alice%40acme.com/dashboard",
		);
		const bobLink = within(main).getByRole("link", { name: /bob@acme.com/i });
		expect(bobLink).toHaveAttribute(
			"href",
			"/mailbox/bob%40acme.com/dashboard",
		);

		// DMARC posture v1 is all-null — the UI explains why rather than
		// rendering misleading defaults.
		expect(
			screen.getByText(/apex-domain dmarc posture isn't ingested yet/i),
		).toBeInTheDocument();

		// Recent cases panel.
		expect(screen.getByText(/recent cases/i)).toBeInTheDocument();
		expect(screen.getByText(/suspicious wire transfer/i)).toBeInTheDocument();
	});

	it("renders the DKIM tile empty-state when no selectors have been observed (#170)", () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderDomainDetail("acme.com");
		const dkimCard = screen
			.getByText(/dkim posture/i)
			.closest(".pp-card") as HTMLElement;
		expect(
			within(dkimCard).getByText(/no dkim selectors observed signing as this domain/i),
		).toBeInTheDocument();
	});

	it("renders observed DKIM selectors with published / missing affordances (#170)", () => {
		queryState = {
			data: {
				...populated,
				dkimPosture: {
					selectors: [
						{ selector: "google", published: true },
						{ selector: "retired", published: false },
						// `null` is the transient-unavailable sentinel; per the
						// #170 Constraints it renders identically to `false`
						// (the same "missing" affordance) so the operator
						// re-checks on the next refresh rather than acting on a
						// distinct "lookup failed" tier.
						{ selector: "blip", published: null },
					],
				},
			},
			isLoading: false,
			isError: false,
		};
		renderDomainDetail("acme.com");
		const dkimCard = screen
			.getByText(/dkim posture/i)
			.closest(".pp-card") as HTMLElement;
		expect(within(dkimCard).getByText("google")).toBeInTheDocument();
		expect(within(dkimCard).getByText("published")).toBeInTheDocument();
		// Two selectors render "missing": the durable-false and the transient-null.
		expect(within(dkimCard).getAllByText("missing")).toHaveLength(2);
	});

	it("renders 'policy file unreachable' when _mta-sts TXT id is present but policy fields are null (#359)", () => {
		queryState = {
			data: {
				...populated,
				mtaStsPosture: {
					mode: null,
					mx: null,
					maxAge: null,
					id: "20260331",
				},
			},
			isLoading: false,
			isError: false,
		};
		renderDomainDetail("acme.com");
		const mtaCard = screen
			.getByText(/mta-sts posture/i)
			.closest(".pp-card") as HTMLElement;
		expect(
			within(mtaCard).getByText(/policy file unreachable/i),
		).toBeInTheDocument();
		expect(within(mtaCard).getByText("20260331")).toBeInTheDocument();
		expect(
			within(mtaCard).getByText("mta-sts.acme.com/.well-known/mta-sts.txt"),
		).toBeInTheDocument();
		// Must not render bare dashes for the missing fields.
		expect(within(mtaCard).queryByText("—")).not.toBeInTheDocument();
	});

	it("renders 'isn't published' empty state when MTA-STS posture is all-null (#359)", () => {
		queryState = {
			data: {
				...populated,
				mtaStsPosture: { mode: null, mx: null, maxAge: null, id: null },
			},
			isLoading: false,
			isError: false,
		};
		renderDomainDetail("acme.com");
		const mtaCard = screen
			.getByText(/mta-sts posture/i)
			.closest(".pp-card") as HTMLElement;
		expect(
			within(mtaCard).getByText(/mta-sts isn't published/i),
		).toBeInTheDocument();
		expect(
			within(mtaCard).queryByText(/policy file unreachable/i),
		).not.toBeInTheDocument();
	});

	it("renders the MTA-STS dl rows when fully configured (#359)", () => {
		queryState = {
			data: {
				...populated,
				mtaStsPosture: {
					mode: "enforce",
					mx: ["mail.acme.com"],
					maxAge: 604800,
					id: "20260101",
				},
			},
			isLoading: false,
			isError: false,
		};
		renderDomainDetail("acme.com");
		const mtaCard = screen
			.getByText(/mta-sts posture/i)
			.closest(".pp-card") as HTMLElement;
		expect(within(mtaCard).getByText("enforce")).toBeInTheDocument();
		expect(within(mtaCard).getByText("604800s")).toBeInTheDocument();
		expect(within(mtaCard).getByText("mail.acme.com")).toBeInTheDocument();
		expect(
			within(mtaCard).queryByText(/policy file unreachable/i),
		).not.toBeInTheDocument();
	});

	it("renders the DMARC fields when posture data is present (forward-compatible)", () => {
		queryState = {
			data: {
				...populated,
				dmarcPosture: {
					p: "reject",
					sp: "reject",
					pct: 100,
					ruaConfigured: true,
					alignmentRate: 0.97,
				},
			},
			isLoading: false,
			isError: false,
		};
		renderDomainDetail("acme.com");
		// Both `p` and `sp` show "reject"; assert via the DOM list rather than
		// counting matches so the test stays readable.
		const dmarcCard = screen
			.getByText(/dmarc posture/i)
			.closest(".pp-card") as HTMLElement;
		expect(within(dmarcCard).getAllByText("reject")).toHaveLength(2);
		expect(within(dmarcCard).getByText("100%")).toBeInTheDocument();
		expect(within(dmarcCard).getByText("configured")).toBeInTheDocument();
		expect(within(dmarcCard).getByText("97%")).toBeInTheDocument();
	});
});
