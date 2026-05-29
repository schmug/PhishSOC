// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Coverage for the org-scope co-pilot wiring (#198), which replaces the
// disabled-state fallback added in #186.
//
// Before #198: the Shell topbar's "Ask co-pilot" button was `disabled` on
// every org-level route (`/`, `/settings`, `/mailboxes`, `/domains`,
// `/domains/:domain`) because the panel only mounted inside
// `/mailbox/:mailboxId/*` (mailbox.tsx was the only caller passing
// `rightPanel`). #198 wires Shell to mount a sibling `OrgAgentPanel`
// whenever no `rightPanel` is supplied AND there's no `mailboxId`, so the
// button opens a working org-scope panel on those routes. The per-mailbox
// route is unchanged.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
	useDomainStats: () => ({
		data: undefined,
		isLoading: false,
		isError: false,
	}),
}));

// Mock the agent SDK hooks so OrgAgentPanel (v2) doesn't attempt real
// WebSocket/HTTP connections to an agent server that doesn't exist in the
// test environment.
vi.mock("agents/react", () => ({
	useAgent: () => ({}),
}));

vi.mock("@cloudflare/ai-chat/react", () => ({
	useAgentChat: () => ({
		messages: [],
		sendMessage: vi.fn(),
		status: "idle" as const,
		setMessages: vi.fn(),
		stop: vi.fn(),
	}),
}));

vi.mock("~/queries/org", () => ({
	useOrgOverview: () => ({
		data: {
			now: "2026-05-03T00:00:00Z",
			threatsBlocked24h: 12,
			threatsBlocked7d: 84,
			openCasesTotal: 3,
			mailboxesCount: 4,
			domainsCount: 2,
			verdictMix: { safe: 100, suspicious: 5, phishing: 2, spam: 8, bec: 0 },
			verdictMix7d: { safe: 700, suspicious: 30, phishing: 12, spam: 50, bec: 1 },
			topThreats: [{ category: "phishing", count: 7 }],
			pipelineHealth: { successRate24h: 0.99, p95Ms: 1200, runs24h: 250 },
			hubContributions24h: 5,
		},
		isLoading: false,
		isError: false,
	}),
}));

vi.mock("~/queries/folders", () => ({
	useFolders: () => ({ data: [] }),
}));

import Shell from "~/components/phishsoc/Shell";
import { useUIStore } from "~/hooks/useUIStore";
import { renderWithProviders } from "./test-utils";

const RIGHT_PANEL_TEST_ID = "agent-panel-content";
const ORG_PANEL_TEST_ID = "org-agent-panel";

function RightPanelStub() {
	return <div data-testid={RIGHT_PANEL_TEST_ID}>agent panel content</div>;
}

// Renders Shell mounted at the route patterns the app actually uses, so
// `useParams<{ mailboxId }>()` resolves the same way it does in production.
// Org-level routes pass no `rightPanel` (Shell falls back to OrgAgentPanel);
// mailbox-level routes pass the per-mailbox AgentSidebar stub.
function renderAtRoute(initialEntry: string) {
	return renderWithProviders(
		<Routes>
			<Route
				path="/"
				element={
					<Shell>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
			<Route
				path="/settings"
				element={
					<Shell>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
			<Route
				path="/mailboxes"
				element={
					<Shell>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
			<Route
				path="/domains"
				element={
					<Shell>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
			<Route
				path="/domains/:domain"
				element={
					<Shell>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
			<Route
				path="/domains/:domain/settings"
				element={
					<Shell>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
			<Route
				path="/mailbox/:mailboxId/*"
				element={
					<Shell rightPanel={<RightPanelStub />}>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
		</Routes>,
		{ initialEntries: [initialEntry] },
	);
}

beforeEach(() => {
	useUIStore.setState({ isAgentPanelOpen: false });
	// xl+ in-flow render — keeps the slot a plain `<aside>` rather than a
	// base-ui Dialog portal, which simplifies queries.
	window.matchMedia = vi.fn().mockImplementation((query: string) => ({
		matches: query === "(min-width: 1280px)",
		media: query,
		onchange: null,
		addListener: vi.fn(),
		removeListener: vi.fn(),
		addEventListener: vi.fn(),
		removeEventListener: vi.fn(),
		dispatchEvent: vi.fn(),
	}));
});

afterEach(() => {
	useUIStore.setState({ isAgentPanelOpen: false });
});

describe("Shell 'Ask co-pilot' button — org-level routes (#198)", () => {
	const orgRoutes: Array<[label: string, path: string]> = [
		["org overview /", "/"],
		["org settings /settings", "/settings"],
		["mailboxes list /mailboxes", "/mailboxes"],
		["domains list /domains", "/domains"],
		["domain detail /domains/:domain", "/domains/example.com"],
		[
			"domain settings /domains/:domain/settings",
			"/domains/example.com/settings",
		],
	];

	for (const [label, path] of orgRoutes) {
		it(`is enabled and advertises panel state on ${label}`, () => {
			renderAtRoute(path);
			const trigger = screen.getByRole("button", {
				name: /ask co-?pilot/i,
			});
			expect(trigger).not.toBeDisabled();
			expect(trigger).not.toHaveAttribute("title");
			// Closed-but-enabled — aria-expanded should be advertised so AT
			// announces the state once the panel can actually open.
			expect(trigger).toHaveAttribute("aria-expanded", "false");
		});

		it(`clicking it on ${label} mounts the org-scope co-pilot`, async () => {
			const user = userEvent.setup();
			renderAtRoute(path);
			const trigger = screen.getByRole("button", {
				name: /ask co-?pilot/i,
			});
			expect(useUIStore.getState().isAgentPanelOpen).toBe(false);
			expect(screen.queryByTestId(ORG_PANEL_TEST_ID)).not.toBeInTheDocument();
			await user.click(trigger);
			expect(useUIStore.getState().isAgentPanelOpen).toBe(true);
			expect(screen.getByTestId(ORG_PANEL_TEST_ID)).toBeInTheDocument();
			// The per-mailbox panel must NOT be mounted on org routes.
			expect(
				screen.queryByTestId(RIGHT_PANEL_TEST_ID),
			).not.toBeInTheDocument();
			expect(trigger).toHaveAttribute("aria-expanded", "true");
		});
	}

	it("the org-scope panel header is visibly distinct from the per-mailbox agent's", async () => {
		const user = userEvent.setup();
		renderAtRoute("/");
		await user.click(screen.getByRole("button", { name: /ask co-?pilot/i }));
		const panel = screen.getByTestId(ORG_PANEL_TEST_ID);
		// Org badge + "Org Co-pilot" label, not the per-mailbox "AI" / "Email Agent".
		expect(panel).toHaveTextContent(/Org/);
		expect(panel).toHaveTextContent(/Org Co-pilot/);
		expect(panel).not.toHaveTextContent(/Email Agent/);
	});
});

describe("Shell 'Ask co-pilot' button — mailbox-level route still works", () => {
	it("is enabled on /mailbox/:mailboxId/* and opens the per-mailbox panel on click", async () => {
		const user = userEvent.setup();
		renderAtRoute("/mailbox/m1/dashboard");
		const trigger = screen.getByRole("button", { name: /ask co-?pilot/i });
		expect(trigger).not.toBeDisabled();
		expect(trigger).not.toHaveAttribute("title");
		expect(trigger).toHaveAttribute("aria-expanded", "false");
		await user.click(trigger);
		expect(useUIStore.getState().isAgentPanelOpen).toBe(true);
		// Per-mailbox stub mounts; org-scope panel does NOT.
		expect(screen.getByTestId(RIGHT_PANEL_TEST_ID)).toBeInTheDocument();
		expect(screen.queryByTestId(ORG_PANEL_TEST_ID)).not.toBeInTheDocument();
		expect(trigger).toHaveAttribute("aria-expanded", "true");
	});
});
