// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	aggregateOrgSearch,
	mailboxesForOrgSearch,
	type PerMailboxSearchResult,
} from "../../workers/lib/org-search";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";

function row(id: string, date: string | null, extra: Record<string, unknown> = {}) {
	return { id, date, ...extra };
}

describe("mailboxesForOrgSearch (#27 ACL)", () => {
	it("excludes mailboxes the caller is not permitted to access", () => {
		const mailboxes = [
			{ id: "alice@acme.com", email: "alice@acme.com" },
			{ id: "bob@acme.com", email: "bob@acme.com" },
		];
		const acls: Array<MailboxAcl | null> = [
			{ owner: "alice@acme.com", members: ["alice@acme.com"] },
			{ owner: "bob@acme.com", members: ["bob@acme.com"] },
		];
		const visible = mailboxesForOrgSearch(mailboxes, acls, "alice@acme.com", []);
		expect(visible.map((m) => m.id)).toEqual(["alice@acme.com"]);
	});

	it("includes mailboxes granted via CF Access group", () => {
		const mailboxes = [{ id: "shared@acme.com", email: "shared@acme.com" }];
		const acls: Array<MailboxAcl | null> = [
			{ owner: "alice@acme.com", members: ["alice@acme.com"], groups: ["soc"] },
		];
		const visible = mailboxesForOrgSearch(mailboxes, acls, "bob@acme.com", ["soc"]);
		expect(visible).toHaveLength(1);
	});
});

describe("aggregateOrgSearch", () => {
	it("merges + tags rows from each mailbox with mailbox metadata", () => {
		const perMailbox: PerMailboxSearchResult[] = [
			{
				mailboxId: "alice@acme.com",
				mailboxEmail: "alice@acme.com",
				count: 1,
				emails: [row("e1", "2026-05-01T00:00:00Z", { sender: "x" })],
			},
			{
				mailboxId: "bob@acme.com",
				mailboxEmail: "bob@acme.com",
				count: 1,
				emails: [row("e2", "2026-05-02T00:00:00Z", { sender: "y" })],
			},
		];
		const out = aggregateOrgSearch(perMailbox, 1, 25);
		expect(out.totalCount).toBe(2);
		expect(out.emails).toHaveLength(2);
		// Tagged with mailbox provenance so the UI can render a per-row chip.
		expect(out.emails[0]).toMatchObject({
			id: "e2",
			mailbox_id: "bob@acme.com",
			mailbox_email: "bob@acme.com",
		});
		expect(out.emails[1]).toMatchObject({
			id: "e1",
			mailbox_id: "alice@acme.com",
		});
	});

	it("orders merged rows by date DESC across mailboxes", () => {
		const perMailbox: PerMailboxSearchResult[] = [
			{
				mailboxId: "a",
				mailboxEmail: "a",
				count: 2,
				emails: [
					row("a-old", "2026-01-01T00:00:00Z"),
					row("a-new", "2026-04-01T00:00:00Z"),
				],
			},
			{
				mailboxId: "b",
				mailboxEmail: "b",
				count: 2,
				emails: [
					row("b-mid", "2026-03-01T00:00:00Z"),
					row("b-newest", "2026-05-01T00:00:00Z"),
				],
			},
		];
		const out = aggregateOrgSearch(perMailbox, 1, 25);
		expect(out.emails.map((e) => e.id)).toEqual([
			"b-newest",
			"a-new",
			"b-mid",
			"a-old",
		]);
	});

	it("paginates the merged result set, totalCount stays absolute", () => {
		const emails = Array.from({ length: 30 }, (_, i) =>
			row(`e${i}`, `2026-04-${String(i + 1).padStart(2, "0")}T00:00:00Z`),
		);
		const perMailbox: PerMailboxSearchResult[] = [
			{ mailboxId: "a", mailboxEmail: "a", count: 30, emails },
		];
		const page1 = aggregateOrgSearch(perMailbox, 1, 10);
		const page2 = aggregateOrgSearch(perMailbox, 2, 10);
		const page4 = aggregateOrgSearch(perMailbox, 4, 10);
		expect(page1.emails).toHaveLength(10);
		expect(page2.emails).toHaveLength(10);
		expect(page4.emails).toHaveLength(0); // past the end
		// Both pages report the same total.
		expect(page1.totalCount).toBe(30);
		expect(page2.totalCount).toBe(30);
		expect(page4.totalCount).toBe(30);
		// Pages don't overlap.
		const page1Ids = new Set(page1.emails.map((e) => e.id));
		expect(page2.emails.every((e) => !page1Ids.has(e.id))).toBe(true);
	});

	it("sums counts across mailboxes (totalCount tracks the underlying DB total, not the page)", () => {
		// Common case: each mailbox has many matches but only a slice of each
		// mailbox's matches makes it into the merged page. totalCount is what
		// pagination uses and must reflect the org-wide match total.
		const perMailbox: PerMailboxSearchResult[] = [
			{ mailboxId: "a", mailboxEmail: "a", count: 142, emails: [row("a1", "2026-05-01")] },
			{ mailboxId: "b", mailboxEmail: "b", count: 7, emails: [row("b1", "2026-04-01")] },
			{ mailboxId: "c", mailboxEmail: "c", count: 0, emails: [] },
		];
		const out = aggregateOrgSearch(perMailbox, 1, 25);
		expect(out.totalCount).toBe(149);
		expect(out.emails.map((e) => e.id)).toEqual(["a1", "b1"]);
	});

	it("handles missing dates by sorting them to the end", () => {
		const perMailbox: PerMailboxSearchResult[] = [
			{
				mailboxId: "a",
				mailboxEmail: "a",
				count: 3,
				emails: [
					row("dated", "2026-04-01"),
					row("undated-1", null),
					row("undated-2", null),
				],
			},
		];
		const out = aggregateOrgSearch(perMailbox, 1, 25);
		expect(out.emails[0].id).toBe("dated");
		// The two undated rows trail; their relative order is unspecified.
		expect(out.emails.slice(1).map((e) => e.id).sort()).toEqual([
			"undated-1",
			"undated-2",
		]);
	});

	it("returns an empty response when no mailboxes match", () => {
		const out = aggregateOrgSearch([], 1, 25);
		expect(out).toEqual({ emails: [], totalCount: 0 });
	});
});
