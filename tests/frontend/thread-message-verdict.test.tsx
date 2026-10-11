// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Multi-message threads render each message through ThreadMessage, not
 * SingleMessageView, so the verdict card must render there too.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Email } from "~/types";

vi.mock("~/components/EmailIframe", () => ({ default: () => null }));

import ThreadMessage from "~/components/email-panel/ThreadMessage";

const email: Email = {
	id: "email_1",
	subject: "Your next listeners",
	sender: "noreply@res.podview.com",
	recipient: "clodcast@cortech.online",
	date: "2026-09-27T12:19:00Z",
	read: true,
	starred: false,
	security_verdict: JSON.stringify({
		action: "allow",
		score: 14,
		explanation: "classifier: spam (93%)",
		auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
		classification: { label: "spam", confidence: 0.93, reasoning: "jev-1.13.0: spam 0.93" },
		signals: [],
	}),
};

describe("ThreadMessage — security verdict", () => {
	it("shows the verdict card when the message is expanded", () => {
		render(<ThreadMessage email={email} isLast isExpanded onToggleExpand={() => {}} />);
		expect(screen.getByText("Allowed by security pipeline")).toBeInTheDocument();
		expect(screen.getByText(/score 14\/100/)).toBeInTheDocument();
	});

	it("does not show the verdict card while collapsed", () => {
		render(<ThreadMessage email={email} isLast isExpanded={false} onToggleExpand={() => {}} />);
		expect(screen.queryByText("Allowed by security pipeline")).toBeNull();
	});
});
