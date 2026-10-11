// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

import CaseDetailRoute from "~/routes/case-detail";
import { renderWithProviders } from "./test-utils";

// Per-case score is now persisted on the `cases` table at case-creation
// time (issue #126). The API returns it as `score: number | null`. The
// title bar renders <ScoreRing> when score is present and a muted "—"
// when null/undefined.
const baseCase = {
	id: "case_abc123",
	created_at: "2026-04-29T11:00:00Z",
	updated_at: "2026-04-29T11:30:00Z",
	status: "open",
	title: "Suspicious wire-transfer request",
	notes: null,
	shared_to_hub: 0,
	hub_event_uuid: null,
	score: null as number | null,
	// Aggregate confidence (issue #220). Null for pre-#105 cases, 0–1 otherwise.
	confidence: null as number | null,
	summary: null as string | null,
	summary_status: null as "pending" | "ready" | "failed" | null,
	stage_trace: null as
		| Array<{
			stage: string;
			status: string;
			score_contrib: number;
			duration_ms: number;
			reason?: string;
		}>
		| null,
	stage_trace_error: null as string | null,
	emails: [],
	observables: [],
};

function mockFetchOnce(payload: unknown) {
	const fetchMock = vi.fn().mockResolvedValue({
		ok: true,
		json: async () => payload,
	} as Response);
	vi.stubGlobal("fetch", fetchMock);
	return fetchMock;
}

// Test-only fetch mock that returns a pre-defined sequence of payloads
// for successive calls. Used by the summary-polling test (#127) where
// the first GET returns `pending` and the second returns `ready`.
function mockFetchSequence(payloads: unknown[]) {
	let i = 0;
	const fetchMock = vi.fn().mockImplementation(async () => {
		const payload = payloads[Math.min(i, payloads.length - 1)];
		i++;
		return { ok: true, json: async () => payload } as Response;
	});
	vi.stubGlobal("fetch", fetchMock);
	return fetchMock;
}

function renderCaseDetail() {
	return renderWithProviders(
		<Routes>
			<Route
				path="/mailbox/:mailboxId/cases/:caseId"
				element={<CaseDetailRoute />}
			/>
		</Routes>,
		{ initialEntries: ["/mailbox/m1/cases/case_abc123"] },
	);
}

describe("CaseDetailRoute (issue #126 — real per-case score)", () => {
	beforeEach(() => {
		vi.unstubAllGlobals();
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("renders <ScoreRing> with the real score when data.score is present", async () => {
		mockFetchOnce({ case: { ...baseCase, score: 75 } });
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();

		// ScoreRing renders the literal "/ 100" subtitle and the numeric
		// rounded score. Confirm both, plus the absence of the empty-state
		// glyph.
		expect(screen.getByText(/\/\s*100/)).toBeInTheDocument();
		expect(screen.getByText(/^75$/)).toBeInTheDocument();
		expect(screen.queryByTestId("case-score-empty")).toBeNull();
	});

	it("renders a muted '—' in the score slot when data.score is null", async () => {
		mockFetchOnce({ case: { ...baseCase, score: null } });
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();

		// No ring → no "/ 100" subtitle. Empty-state placeholder present.
		expect(screen.queryByText(/\/\s*100/)).toBeNull();
		expect(screen.getByTestId("case-score-empty")).toBeInTheDocument();

		// And none of the legacy fabricated badges (status-derived
		// 80 / 30 from the old PR #125 placeholder) leak through.
		expect(screen.queryByText(/^80$/)).toBeNull();
		expect(screen.queryByText(/^30$/)).toBeNull();
	});

	it("still renders core case content (title, status pill, id) even without a score", async () => {
		mockFetchOnce({
			case: { ...baseCase, status: "closed-fp", score: null },
		});
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();
		await waitFor(() => {
			expect(screen.queryByText(/\/\s*100/)).toBeNull();
		});
		expect(screen.getByText(/case_abc123/i)).toBeInTheDocument();
	});
});

// ── AI co-pilot summary card (issue #127) ─────────────────────────
//
// The card renders only when `data.summary_status` is non-null.
// Lifecycle: pending → ready | failed. The "loading" state is the
// 'pending' card; "empty" is `summary_status === null` (card hidden);
// "error" is the 'failed' card with a refresh affordance.
describe("CaseDetailRoute — AI co-pilot summary card (#127)", () => {
	beforeEach(() => {
		vi.unstubAllGlobals();
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("hides the card entirely when summary_status is null (empty state)", async () => {
		mockFetchOnce({ case: { ...baseCase, summary_status: null, summary: null } });
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();
		expect(screen.queryByTestId("copilot-summary-card")).toBeNull();
		expect(screen.queryByText(/Co-pilot summary/i)).toBeNull();
	});

	it("renders the loading state while summary_status is 'pending'", async () => {
		mockFetchSequence([
			{ case: { ...baseCase, summary_status: "pending", summary: null } },
		]);
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();
		expect(screen.getByTestId("copilot-summary-pending")).toBeInTheDocument();
		expect(screen.getByText(/Generating summary…/i)).toBeInTheDocument();
		expect(screen.queryByTestId("copilot-summary-ready")).toBeNull();
		expect(screen.queryByTestId("copilot-summary-failed")).toBeNull();
	});

	it("renders the summary text when summary_status is 'ready'", async () => {
		const summaryText =
			"This email pressures the recipient into a same-day wire " +
			"transfer using a spoofed CFO display name. Two suspicious " +
			"links and an urgency cue suggest a BEC attempt.";
		mockFetchOnce({
			case: { ...baseCase, summary_status: "ready", summary: summaryText },
		});
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();
		expect(screen.getByTestId("copilot-summary-ready")).toHaveTextContent(
			/wire transfer/i,
		);
		expect(screen.queryByTestId("copilot-summary-pending")).toBeNull();
		expect(screen.queryByTestId("copilot-summary-failed")).toBeNull();
	});

	it("renders the error state with a Refresh affordance when summary_status is 'failed'", async () => {
		mockFetchOnce({
			case: { ...baseCase, summary_status: "failed", summary: null },
		});
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();
		const failed = await screen.findByTestId("copilot-summary-failed");
		expect(failed).toHaveTextContent(/couldn'?t generate/i);
		expect(
			screen.getByRole("button", { name: /refresh/i }),
		).toBeInTheDocument();
	});

	it("polls while pending and switches to ready when the next fetch resolves", async () => {
		const summaryText = "Verdict-reasoning summary text from the AI.";
		const fetchMock = mockFetchSequence([
			{ case: { ...baseCase, summary_status: "pending", summary: null } },
			{ case: { ...baseCase, summary_status: "ready", summary: summaryText } },
		]);
		renderCaseDetail();

		await screen.findByTestId("copilot-summary-pending");

		await waitFor(
			() => {
				expect(screen.queryByTestId("copilot-summary-ready")).not.toBeNull();
			},
			{ timeout: 8000 },
		);
		expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2);
		expect(screen.queryByTestId("copilot-summary-pending")).toBeNull();
		expect(screen.getByTestId("copilot-summary-ready")).toHaveTextContent(
			summaryText,
		);
	});
});

// ── Pipeline trace timeline (issue #128) ──────────────────────────
//
// The card renders only when `data.stage_trace` is a non-empty array.
// PR #125 deleted the fabricated explanatory placeholder; this card
// must stay hidden in the same conditions (no trace = empty space, not
// marketing copy). When present we render one row per stage with a
// status pill, score contribution, and duration.
describe("CaseDetailRoute — pipeline trace timeline (#128)", () => {
	const sampleTrace = [
		{ stage: "auth" as const, status: "ok" as const, score_contrib: 0, duration_ms: 1, reason: "DMARC pass" },
		{ stage: "url" as const, status: "ok" as const, score_contrib: 12, duration_ms: 2 },
		{ stage: "reputation" as const, status: "ok" as const, score_contrib: 5, duration_ms: 3 },
		{ stage: "intel" as const, status: "ok" as const, score_contrib: 0, duration_ms: 1 },
		{ stage: "triage" as const, status: "ok" as const, score_contrib: 0, duration_ms: 0 },
		{ stage: "llm" as const, status: "ok" as const, score_contrib: 35, duration_ms: 1850 },
		{ stage: "verdict" as const, status: "ok" as const, score_contrib: 52, duration_ms: 1 },
	];

	beforeEach(() => { vi.unstubAllGlobals(); });
	afterEach(() => { vi.unstubAllGlobals(); });

	it("hides the card entirely when stage_trace is null (no fabricated placeholder)", async () => {
		mockFetchOnce({ case: { ...baseCase, stage_trace: null } });
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();
		expect(screen.queryByTestId("pipeline-trace-card")).toBeNull();
		// Guard against PR #125 regression: the explanatory copy must stay deleted.
		expect(
			screen.queryByText(/Stage-level scoring isn't surfaced/i),
		).toBeNull();
	});

	it("hides the card when stage_trace is an empty array (treated as absent)", async () => {
		mockFetchOnce({ case: { ...baseCase, stage_trace: [] } });
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();
		expect(screen.queryByTestId("pipeline-trace-card")).toBeNull();
	});

	it("renders one row per stage in the order returned by the API", async () => {
		mockFetchOnce({ case: { ...baseCase, stage_trace: sampleTrace } });
		renderCaseDetail();

		await screen.findByTestId("pipeline-trace-card");

		// All seven stages render.
		for (const r of sampleTrace) {
			expect(
				screen.getByTestId(`pipeline-stage-${r.stage}`),
			).toBeInTheDocument();
		}
		// Human-readable labels for the named stages we want to surface.
		expect(screen.getByText(/Authentication/)).toBeInTheDocument();
		expect(screen.getByText(/Classifier \(LLM\)/)).toBeInTheDocument();
		expect(screen.getByText(/Verdict/)).toBeInTheDocument();
	});

	it("surfaces score contribution and duration on each row", async () => {
		mockFetchOnce({ case: { ...baseCase, stage_trace: sampleTrace } });
		renderCaseDetail();

		await screen.findByTestId("pipeline-trace-card");

		// LLM row carries the largest contribution and a real duration.
		const llmRow = screen.getByTestId("pipeline-stage-llm");
		expect(llmRow).toHaveTextContent("+35");
		expect(llmRow).toHaveTextContent("1850ms");

		// Verdict row labels the final score (no leading "+", with separator).
		const verdictRow = screen.getByTestId("pipeline-stage-verdict");
		expect(verdictRow).toHaveTextContent("score 52");
	});

	it("renders a short-circuited triage row with the final verdict score", async () => {
		// Pipeline contract: on the triage short-circuit path, the boost
		// the intel feed contributed is folded into the triage verdict
		// score, and the intel row carries score_contrib=0 with the
		// matched feed surfaced via `reason`. This keeps row-sum sanity:
		// an analyst summing visible contributions gets a number that
		// matches the final verdict.
		const shortCircuitTrace = [
			{ stage: "auth" as const, status: "ok" as const, score_contrib: 0, duration_ms: 1 },
			{ stage: "url" as const, status: "ok" as const, score_contrib: 0, duration_ms: 1 },
			{ stage: "reputation" as const, status: "ok" as const, score_contrib: 0, duration_ms: 0 },
			{
				stage: "intel" as const,
				status: "ok" as const,
				score_contrib: 0,
				duration_ms: 1,
				reason: "phishtank:https://evil.example/login",
			},
			{
				stage: "triage" as const,
				status: "short_circuited" as const,
				score_contrib: 95,
				duration_ms: 1,
				reason: "hard_block: confirmed-intel match",
			},
			{ stage: "llm" as const, status: "skipped" as const, score_contrib: 0, duration_ms: 0 },
			{ stage: "verdict" as const, status: "ok" as const, score_contrib: 95, duration_ms: 0 },
		];
		mockFetchOnce({ case: { ...baseCase, stage_trace: shortCircuitTrace } });
		renderCaseDetail();

		await screen.findByTestId("pipeline-trace-card");

		const triageRow = screen.getByTestId("pipeline-stage-triage");
		expect(triageRow.dataset.status).toBe("short_circuited");
		expect(triageRow).toHaveTextContent("short-circuited");
		expect(triageRow).toHaveTextContent("+95");

		// LLM was skipped — no "+0" contribution leaks through, status pill present.
		const llmRow = screen.getByTestId("pipeline-stage-llm");
		expect(llmRow.dataset.status).toBe("skipped");
		expect(llmRow).toHaveTextContent("skipped");

		// Intel row: matched feed surfaced via reason, but no doubled
		// score_contrib — the boost lives on the triage row.
		const intelRow = screen.getByTestId("pipeline-stage-intel");
		expect(intelRow).toHaveTextContent("phishtank:https://evil.example/login");
		expect(intelRow).not.toHaveTextContent(/\+\d/);
	});

	it("renders a one-line error affordance when stage_trace_error is set (corrupted storage)", async () => {
		mockFetchOnce({
			case: { ...baseCase, stage_trace: null, stage_trace_error: "malformed" },
		});
		renderCaseDetail();

		expect(
			await screen.findByTestId("pipeline-trace-error"),
		).toBeInTheDocument();
		expect(screen.queryByTestId("pipeline-trace-card")).toBeNull();
		expect(screen.getByTestId("pipeline-trace-error")).toHaveTextContent(
			/Pipeline trace unavailable/i,
		);
	});
});

// ── Verdict confidence indicator in title bar (issue #220) ────────────
//
// The title bar shows a small confidence label below the ScoreRing (or the
// muted-dash placeholder). When `confidence` is null (pre-#105 cases) the
// label renders "— conf." so operators can distinguish "unknown" from 0%.
describe("CaseDetailRoute — confidence indicator in title bar (#220)", () => {
	beforeEach(() => { vi.unstubAllGlobals(); });
	afterEach(() => { vi.unstubAllGlobals(); });

	it("renders the confidence percentage when data.confidence is present", async () => {
		mockFetchOnce({ case: { ...baseCase, score: 85, confidence: 0.85 } });
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();

		const indicator = screen.getByTestId("case-confidence");
		expect(indicator).toBeInTheDocument();
		expect(indicator).toHaveTextContent("85% conf.");
	});

	it("renders '— conf.' when data.confidence is null (pre-#105 row)", async () => {
		mockFetchOnce({ case: { ...baseCase, score: 75, confidence: null } });
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();

		const indicator = screen.getByTestId("case-confidence");
		expect(indicator).toHaveTextContent("— conf.");
		expect(indicator).not.toHaveTextContent("0%");
	});

	it("renders '— conf.' when data.confidence is undefined (missing from API response)", async () => {
		// API response omits the field entirely (pre-#220 API version)
		const { confidence: _omit, ...baseCaseNoConfidence } = { ...baseCase, confidence: undefined };
		mockFetchOnce({ case: baseCaseNoConfidence });
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();

		const indicator = screen.getByTestId("case-confidence");
		expect(indicator).toHaveTextContent("— conf.");
	});
});

describe("Cloudflare categorization card (issue #755)", () => {
	const withDomain = {
		...baseCase,
		status: "closed-tp",
		observables: [{ id: "o1", kind: "domain", value: "evil-example.test" }],
	};

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("disables the button when the token is not configured", async () => {
		mockFetchOnce({ case: { ...withDomain, cloudflare_submit_enabled: false } });
		renderCaseDetail();
		const btn = await screen.findByRole("button", { name: /Submit to Cloudflare/ });
		expect((btn as HTMLButtonElement).disabled).toBe(true);
	});

	it("shows the submission date with no status claim", async () => {
		mockFetchOnce({
			case: {
				...withDomain,
				cloudflare_submit_enabled: true,
				cloudflare_submissions: [
					{ domain: "evil-example.test", submitted_at: "2026-10-11T12:00:00Z", category_id: 131 },
				],
			},
		});
		renderCaseDetail();
		const el = await screen.findByTestId("cloudflare-submitted");
		expect(el.textContent).toMatch(/^Submitted to Cloudflare /);
		expect(el.textContent).not.toMatch(/approved|blocked|pending/i);
	});
});
