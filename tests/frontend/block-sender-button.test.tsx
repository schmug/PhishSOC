// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Block sender dialog (spec 2026-09-27-sender-blocklist, UI section).
 * Fetch mock routes on the parsed URL pathname, never a substring
 * (repo CLAUDE.md, CodeQL js/incomplete-url-substring-sanitization).
 */

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import BlockSenderButton from "~/components/BlockSenderButton";
import type { Email } from "~/types";
import { renderWithProviders } from "./test-utils";

const MAILBOX = "clodcast@cortech.online";
const BLOCK_PATH = `/api/v1/mailboxes/${MAILBOX}/blocklist`;

function makeEmail(over: Partial<Email> = {}): Email {
	return {
		id: "e1",
		sender: "noreply@res.podview.com",
		subject: "Your next listeners won't search",
		security_verdict: JSON.stringify({ auth: { dmarc: "pass", trusted: true } }),
		...over,
	} as Email;
}

let posts: unknown[] = [];
let responses: Array<{ status: number; body: unknown }> = [];

beforeEach(() => {
	posts = [];
	responses = [];
	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = new URL(String(input), window.location.origin);
			if (decodeURIComponent(url.pathname) === BLOCK_PATH && init?.method === "POST") {
				posts.push(JSON.parse(String(init.body)));
				const r = responses.shift() ?? { status: 201, body: { rule: { match: "x" }, moved: 2 } };
				return new Response(JSON.stringify(r.body), { status: r.status, headers: { "content-type": "application/json" } });
			}
			return new Response("not found", { status: 404 });
		}),
	);
});

afterEach(() => {
	vi.unstubAllGlobals();
});

async function openDialog(email = makeEmail(), isSidecar = false) {
	renderWithProviders(<BlockSenderButton mailboxId={MAILBOX} email={email} isSidecar={isSidecar} />);
	await userEvent.click(screen.getByRole("button", { name: "Block sender" }));
}

describe("BlockSenderButton", () => {
	it("defaults to the full address and Spam, and posts move_existing", async () => {
		await openDialog();
		expect(screen.getByRole("radio", { name: "noreply@res.podview.com" })).toBeChecked();
		expect(screen.getByRole("radio", { name: "Move to Spam" })).toBeChecked();
		await userEvent.click(screen.getByRole("button", { name: "Block" }));
		await waitFor(() => expect(posts).toHaveLength(1));
		expect(posts[0]).toEqual({ match: "noreply@res.podview.com", action: "spam", move_existing: true });
	});

	it("offers the registrable domain and the exact subdomain", async () => {
		await openDialog();
		await userEvent.click(screen.getByRole("radio", { name: "podview.com (and subdomains)" }));
		expect(screen.getByRole("radio", { name: "res.podview.com (and subdomains)" })).toBeInTheDocument();
		await userEvent.click(screen.getByRole("button", { name: "Block" }));
		await waitFor(() => expect(posts).toHaveLength(1));
		expect(posts[0]).toMatchObject({ match: "podview.com" });
	});

	it("shows the bounce message only for Bounce, prefilled with the default", async () => {
		await openDialog();
		expect(screen.queryByLabelText("Bounce message")).toBeNull();
		await userEvent.click(screen.getByRole("radio", { name: "Bounce with message" }));
		const box = screen.getByLabelText("Bounce message");
		expect(box).toHaveValue("Unsolicited commercial email refused by recipient");
		await userEvent.clear(box);
		await userEvent.type(box, "Stop spamming");
		await userEvent.click(screen.getByRole("button", { name: "Block" }));
		await waitFor(() => expect(posts).toHaveLength(1));
		expect(posts[0]).toMatchObject({ action: "reject", reason: "Stop spamming" });
	});

	it("warns when the sender is not DMARC-authenticated", async () => {
		await openDialog(makeEmail({ security_verdict: JSON.stringify({ auth: { dmarc: "fail", trusted: true } }) }));
		expect(screen.getByText(/may be forged/)).toBeInTheDocument();
	});

	it("does not warn for a trusted DMARC pass", async () => {
		await openDialog();
		expect(screen.queryByText(/may be forged/)).toBeNull();
	});

	it("labels Bounce as unavailable on a sidecar mailbox", async () => {
		await openDialog(makeEmail(), true);
		expect(screen.getByRole("radio", { name: "Bounce (unavailable for Google Workspace — will drop)" })).toBeInTheDocument();
	});

	it("requires confirmation for a shared domain before posting", async () => {
		await openDialog(makeEmail({ sender: "spammer@gmail.com" }));
		await userEvent.click(screen.getByRole("radio", { name: "gmail.com (and subdomains)" }));
		expect(screen.getByRole("button", { name: "Block" })).toBeDisabled();
		await userEvent.click(screen.getByRole("checkbox", { name: "I understand this blocks every sender at gmail.com" }));
		await userEvent.click(screen.getByRole("button", { name: "Block" }));
		await waitFor(() => expect(posts).toHaveLength(1));
		expect(posts[0]).toMatchObject({ match: "gmail.com", confirm_shared_domain: true });
	});

	it("on a server shared_domain_unconfirmed 400 asks for confirmation and resends", async () => {
		responses.push({ status: 400, body: { error: "shared", code: "shared_domain_unconfirmed" } });
		await openDialog();
		await userEvent.click(screen.getByRole("radio", { name: "podview.com (and subdomains)" }));
		await userEvent.click(screen.getByRole("button", { name: "Block" }));
		const confirm = await screen.findByRole("checkbox", { name: "I understand this blocks every sender at podview.com" });
		await userEvent.click(confirm);
		await userEvent.click(screen.getByRole("button", { name: "Block" }));
		await waitFor(() => expect(posts).toHaveLength(2));
		expect(posts[1]).toMatchObject({ match: "podview.com", confirm_shared_domain: true });
	});

	it("uses the current email's sender after the panel switches emails", async () => {
		const view = renderWithProviders(<BlockSenderButton mailboxId={MAILBOX} email={makeEmail()} />);
		view.rerender(<BlockSenderButton mailboxId={MAILBOX} email={makeEmail({ id: "e2", sender: "other@example.org" })} />);
		await userEvent.click(screen.getByRole("button", { name: "Block sender" }));
		await userEvent.click(screen.getByRole("button", { name: "Block" }));
		await waitFor(() => expect(posts).toHaveLength(1));
		expect(posts[0]).toMatchObject({ match: "other@example.org" });
	});
});
