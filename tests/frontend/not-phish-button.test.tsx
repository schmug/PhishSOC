// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import NotPhishButton from "~/components/NotPhishButton";
import { renderWithProviders } from "./test-utils";

const MAILBOX = "box@a.test";
const PATH = `/api/v1/mailboxes/${MAILBOX}/emails/e1/not-phish`;

let posts: string[] = [];
let status = 200;

beforeEach(() => {
	posts = [];
	status = 200;
	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = new URL(String(input), window.location.origin);
			if (decodeURIComponent(url.pathname) === PATH && init?.method === "POST") {
				posts.push(url.pathname);
				return new Response(JSON.stringify({ feedback: {} }), { status, headers: { "content-type": "application/json" } });
			}
			return new Response("not found", { status: 404 });
		}),
	);
});

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("NotPhishButton", () => {
	it("exposes an aria-label and POSTs to the mailbox-scoped route", async () => {
		renderWithProviders(<NotPhishButton mailboxId={MAILBOX} emailId="e1" />);
		await userEvent.click(screen.getByRole("button", { name: "Not phish" }));
		await waitFor(() => expect(posts).toHaveLength(1));
	});

	it("survives a server error without throwing", async () => {
		status = 404;
		renderWithProviders(<NotPhishButton mailboxId={MAILBOX} emailId="e1" />);
		await userEvent.click(screen.getByRole("button", { name: "Not phish" }));
		await waitFor(() => expect(posts).toHaveLength(1));
		expect(screen.getByRole("button", { name: "Not phish" })).toBeEnabled();
	});
});
