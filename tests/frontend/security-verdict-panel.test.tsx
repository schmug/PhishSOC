// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Frontend tests for SecurityVerdictPanel confidence chip (issue #220).
 *
 * Acceptance:
 * - Chip renders with the correct percentage text for a verdict with confidence: 0.85
 * - Chip renders "—" (em dash) when confidence is absent (pre-#105 persisted verdicts)
 * - Panel does not crash for allow verdicts (returns null)
 */

import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import SecurityVerdictPanel from "~/components/email-panel/SecurityVerdictPanel";
import type { Email } from "~/types";
import { renderWithProviders } from "./test-utils";

function makeEmail(verdictOverrides: object | null): Email {
	const verdict =
		verdictOverrides === null
			? null
			: JSON.stringify({
					action: "block",
					score: 85,
					explanation: "Phishing detected.",
					auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
					classification: {
						label: "phishing",
						confidence: 0.92,
						reasoning: "High-urgency credential-harvest template.",
					},
					signals: ["spf_pass", "known_phishing_kit"],
					...verdictOverrides,
				});

	return {
		id: "email_1",
		subject: "Urgent: verify your account",
		sender: "attacker@evil.example",
		recipient: "victim@corp.example",
		date: "2026-05-06T10:00:00Z",
		read: false,
		starred: false,
		security_verdict: verdict,
	};
}

describe("SecurityVerdictPanel — confidence chip (issue #220)", () => {
	it("renders the confidence chip with 85% for confidence: 0.85", () => {
		const email = makeEmail({ confidence: 0.85 });
		render(<SecurityVerdictPanel email={email} />);

		const chip = screen.getByTestId("verdict-confidence-chip");
		expect(chip).toBeInTheDocument();
		// The chip should show the rounded percentage
		expect(chip).toHaveTextContent("85%");
		expect(chip).toHaveTextContent("confidence");
	});

	it("renders '—' in the confidence chip when confidence is absent (pre-#105 verdict)", () => {
		// Old persisted verdicts do not have a top-level `confidence` field.
		const email = makeEmail({ /* no confidence field */ });
		render(<SecurityVerdictPanel email={email} />);

		const chip = screen.getByTestId("verdict-confidence-chip");
		expect(chip).toBeInTheDocument();
		expect(chip).toHaveTextContent("—");
		// Must NOT show "0%" — that would misrepresent "unknown" as "zero"
		expect(chip).not.toHaveTextContent("0%");
	});

	it("rounds fractional confidence values correctly (0.856 → 86%)", () => {
		const email = makeEmail({ confidence: 0.856 });
		render(<SecurityVerdictPanel email={email} />);

		const chip = screen.getByTestId("verdict-confidence-chip");
		expect(chip).toHaveTextContent("86%");
	});

	it("does not render the panel at all for a clean allow verdict", () => {
		const email = makeEmail({
			action: "allow",
			score: 5,
			classification: { label: "safe", confidence: 0.99, reasoning: "No signals." },
			signals: [],
		});
		render(<SecurityVerdictPanel email={email} />);

		// Panel returns null for allow (no hard-block/attachment-block triage)
		expect(screen.queryByTestId("verdict-confidence-chip")).toBeNull();
	});

	it("does not crash when security_verdict is null", () => {
		const email = makeEmail(null);
		render(<SecurityVerdictPanel email={email} />);

		// Panel renders nothing — no crash.
		expect(screen.queryByTestId("verdict-confidence-chip")).toBeNull();
	});
});

describe("SecurityVerdictPanel — confidence chip in case-detail title bar (issue #220)", () => {
	/**
	 * The case-detail confidence indicator is tested in case-detail.test.tsx.
	 * These tests cover the SecurityVerdictPanel surface only.
	 */
	it("renders confidence chip next to the score for a quarantine verdict", () => {
		const email = makeEmail({ action: "quarantine", score: 70, confidence: 0.72 });
		render(<SecurityVerdictPanel email={email} />);

		expect(screen.getByTestId("verdict-confidence-chip")).toHaveTextContent("72%");
		// Score label still present — additive, not replacing
		expect(screen.getByText(/score 70\/100/)).toBeInTheDocument();
	});

	it("renders confidence chip next to the score for a tag verdict", () => {
		const email = makeEmail({ action: "tag", score: 45, confidence: 0.5 });
		render(<SecurityVerdictPanel email={email} />);

		expect(screen.getByTestId("verdict-confidence-chip")).toHaveTextContent("50%");
	});
});

/**
 * Inline-gateway relay outcome badge (issue #581). `relay_status` is NULL for
 * domains without a relay policy, so the badge renders only when it is set —
 * and independently of the verdict card, which stays quiet for plain allow mail.
 */
describe("SecurityVerdictPanel — relay status badge (issue #581)", () => {
	const ALLOW = {
		action: "allow",
		score: 5,
		classification: { label: "safe", confidence: 0.99, reasoning: "No signals." },
		signals: [],
	};

	it("shows the badge for relayed allow-verdict mail even though the verdict card is hidden", () => {
		const email: Email = { ...makeEmail(ALLOW), relay_status: "relayed" };
		renderWithProviders(<SecurityVerdictPanel email={email} />);

		expect(screen.queryByTestId("verdict-confidence-chip")).toBeNull();
		expect(screen.getByTestId("relay-status-badge")).toHaveTextContent("relayed");
	});

	it("shows the badge when the pipeline produced no verdict (fail-open relay)", () => {
		const email: Email = { ...makeEmail(null), relay_status: "relayed" };
		renderWithProviders(<SecurityVerdictPanel email={email} />);

		expect(screen.getByTestId("relay-status-badge")).toHaveTextContent("relayed");
	});

	it.each(["held", "failed", "dropped"] as const)("shows the %s outcome alongside a block verdict", (status) => {
		const email: Email = { ...makeEmail({ confidence: 0.9 }), relay_status: status };
		renderWithProviders(<SecurityVerdictPanel email={email} />);

		expect(screen.getByTestId("verdict-confidence-chip")).toBeInTheDocument();
		expect(screen.getByTestId("relay-status-badge")).toHaveTextContent(status);
	});

	it("renders no badge for non-gateway mail (NULL relay_status)", () => {
		renderWithProviders(<SecurityVerdictPanel email={{ ...makeEmail(ALLOW), relay_status: null }} />);
		expect(screen.queryByTestId("relay-status-badge")).toBeNull();

		renderWithProviders(<SecurityVerdictPanel email={{ ...makeEmail({}), relay_status: null }} />);
		expect(screen.getByTestId("verdict-confidence-chip")).toBeInTheDocument();
		expect(screen.queryByTestId("relay-status-badge")).toBeNull();
	});
});

describe("SecurityVerdictPanel — send-risk badge", () => {
	const sent = (sendRisk: string | null): Email => ({
		id: "sent_1",
		subject: "Invoice",
		sender: "me@corp.example",
		recipient: "vendor@acme.example",
		date: "2026-05-06T10:00:00Z",
		read: true,
		starred: false,
		send_risk: sendRisk,
	});

	it("renders the tier, verified marker, and reasons for a stepped-up send", () => {
		render(
			<SecurityVerdictPanel
				email={sent(JSON.stringify({ v: 1, tier: 1, reasons: ["External recipient(s): vendor@acme.example"], confirmed: true }))}
			/>,
		);
		const badge = screen.getByTestId("send-risk-badge");
		expect(badge).toHaveTextContent("tier 1");
		expect(badge).toHaveTextContent("verified");
		expect(badge).toHaveTextContent("External recipient(s): vendor@acme.example");
	});

	it("renders nothing without a record or for a malformed one", () => {
		const { unmount } = render(<SecurityVerdictPanel email={sent(null)} />);
		expect(screen.queryByTestId("send-risk-badge")).toBeNull();
		unmount();
		render(<SecurityVerdictPanel email={sent("{not json")} />);
		expect(screen.queryByTestId("send-risk-badge")).toBeNull();
	});
});
