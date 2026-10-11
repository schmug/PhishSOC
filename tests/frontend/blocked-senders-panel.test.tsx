// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Blocked senders settings panel (spec 2026-09-27-sender-blocklist, UI).
 * Fetch mock routes on the parsed, decoded URL pathname + method (repo CLAUDE.md).
 */

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BlockedSendersPanel } from "~/components/BlockedSendersPanel";
import { renderWithProviders } from "./test-utils";

const MB = "clodcast@cortech.online";
const rule = (id: string, match: string, action = "drop") => ({ id, match, action, created_at: "2026-09-27T12:00:00Z" });

/** Row accessible-name matcher on whole whitespace-separated tokens — exact
 *  equality, not a substring/regex match (CodeQL js/regex/missing-regexp-anchor). */
const hasToken = (token: string) => (name: string) => name.split(/\s+/).includes(token);

let calls: Array<{ method: string; path: string; body?: unknown }> = [];
let routes: Record<string, { status: number; body: unknown }> = {};

beforeEach(() => {
	calls = [];
	routes = {};
	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = new URL(String(input), window.location.origin);
			const method = init?.method ?? "GET";
			const path = decodeURIComponent(url.pathname);
			calls.push({ method, path, body: init?.body ? JSON.parse(String(init.body)) : undefined });
			const r = routes[`${method} ${path}`];
			if (!r) return new Response("{}", { status: 404 });
			return new Response(r.status === 204 ? null : JSON.stringify(r.body), {
				status: r.status,
				headers: { "content-type": "application/json" },
			});
		}),
	);
});

afterEach(() => vi.unstubAllGlobals());

describe("BlockedSendersPanel — mailbox tier", () => {
	beforeEach(() => {
		routes[`GET /api/v1/mailboxes/${MB}/settings/effective`] = {
			status: 200,
			body: {
				settings: {
					raw: { blocklist: [rule("m1", "podview.com", "spam")] },
					domain: { blocklist: [rule("d1", "spam.example", "reject")] },
					org: { blocklist: [rule("o1", "junk.example")] },
				},
			},
		};
		routes[`GET /api/v1/mailboxes/${MB}/blocked-log`] = {
			status: 200,
			body: { rows: [{ id: 1, ts: "2026-09-27T12:00:00Z", sender: "x@junk.example", subject: "Buy now", action: "drop", tier: "org", rule_id: "o1" }] },
		};
		routes[`DELETE /api/v1/mailboxes/${MB}/blocklist/m1`] = { status: 204, body: null };
	});

	it("lists own rules with Remove and inherited rules read-only, with tier badges", async () => {
		renderWithProviders(<BlockedSendersPanel tier="mailbox" mailboxId={MB} />);
		await screen.findByRole("button", { name: "Remove podview.com" });
		const rules = within(screen.getByRole("table", { name: "Block rules" }));
		const own = rules.getByRole("row", { name: hasToken("podview.com") });
		expect(within(own).getByText("mailbox")).toBeInTheDocument();
		expect(within(own).getByRole("button", { name: "Remove podview.com" })).toBeInTheDocument();
		const inherited = rules.getByRole("row", { name: hasToken("spam.example") });
		expect(within(inherited).getByText("domain")).toBeInTheDocument();
		expect(within(inherited).queryByRole("button")).toBeNull();
		expect(within(rules.getByRole("row", { name: hasToken("junk.example") })).getByText("org")).toBeInTheDocument();
	});

	it("Remove deletes the rule and drops the row", async () => {
		renderWithProviders(<BlockedSendersPanel tier="mailbox" mailboxId={MB} />);
		await userEvent.click(await screen.findByRole("button", { name: "Remove podview.com" }));
		await waitFor(() => expect(screen.queryByRole("row", { name: hasToken("podview.com") })).toBeNull());
		expect(calls).toContainEqual(expect.objectContaining({ method: "DELETE", path: `/api/v1/mailboxes/${MB}/blocklist/m1` }));
	});

	it("shows recently blocked messages", async () => {
		renderWithProviders(<BlockedSendersPanel tier="mailbox" mailboxId={MB} />);
		expect(await screen.findByText("Buy now")).toBeInTheDocument();
		expect(screen.getByText("x@junk.example")).toBeInTheDocument();
	});
});

describe("BlockedSendersPanel — org tier", () => {
	beforeEach(() => {
		routes["GET /api/v1/org/settings"] = { status: 200, body: { settings: { blocklist: [] } } };
	});

	it("adds a rule via POST /api/v1/org/blocklist", async () => {
		routes["POST /api/v1/org/blocklist"] = { status: 201, body: { rule: rule("n1", "podview.com", "reject") } };
		renderWithProviders(<BlockedSendersPanel tier="org" />);
		await userEvent.type(await screen.findByLabelText("Sender or domain"), "podview.com");
		await userEvent.selectOptions(screen.getByLabelText("Action"), "reject");
		await userEvent.click(screen.getByRole("button", { name: "Add rule" }));
		await screen.findByRole("row", { name: hasToken("podview.com") });
		expect(calls).toContainEqual(
			expect.objectContaining({ method: "POST", path: "/api/v1/org/blocklist", body: expect.objectContaining({ match: "podview.com", action: "reject" }) }),
		);
	});

	it("shows the server error for a public suffix", async () => {
		routes["POST /api/v1/org/blocklist"] = { status: 400, body: { error: "co.uk is a public suffix; block a specific domain instead", code: "public_suffix" } };
		renderWithProviders(<BlockedSendersPanel tier="org" />);
		await userEvent.type(await screen.findByLabelText("Sender or domain"), "co.uk");
		await userEvent.click(screen.getByRole("button", { name: "Add rule" }));
		expect(await screen.findByText(/is a public suffix/)).toBeInTheDocument();
	});
});
