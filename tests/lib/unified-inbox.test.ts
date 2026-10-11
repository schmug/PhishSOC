// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";
import {
	compareInboxRows,
	decodeCursor,
	encodeCursor,
	mergeInboxPages,
	selectInboxMailboxes,
	type InboxCursor,
	type InboxMailboxFlags,
	type InboxRow,
	type PerMailboxInboxPage,
} from "../../workers/lib/unified-inbox";

const SHOWN: InboxMailboxFlags = { honeypot: false, sidecar: false, hidden: false };

describe("selectInboxMailboxes", () => {
	const mailboxes = [
		{ id: "open@a.test", email: "open@a.test" },
		{ id: "mine@a.test", email: "mine@a.test" },
		{ id: "theirs@b.test", email: "theirs@b.test" },
		{ id: "pot@a.test", email: "pot@a.test" },
		{ id: "side@a.test", email: "side@a.test" },
		{ id: "quiet@b.test", email: "quiet@b.test" },
		{ id: "broken@b.test", email: "broken@b.test" },
		{ id: "broken-theirs@b.test", email: "broken-theirs@b.test" },
	];
	const alice: MailboxAcl = { owner: "alice@corp.test", members: ["alice@corp.test"] };
	const bob: MailboxAcl = { owner: "bob@corp.test", members: ["bob@corp.test"] };
	const acls: Array<MailboxAcl | null> = [null, alice, bob, null, null, null, null, bob];
	const flags: Array<InboxMailboxFlags | null> = [
		SHOWN,
		SHOWN,
		SHOWN,
		{ ...SHOWN, honeypot: true },
		{ ...SHOWN, sidecar: true },
		{ ...SHOWN, hidden: true },
		null,
		null,
	];

	it("keeps unscoped and permitted mailboxes; drops ACL-denied, honeypot, sidecar and hidden", () => {
		const { selected } = selectInboxMailboxes(mailboxes, acls, flags, "alice@corp.test", []);
		expect(selected.map((m) => m.id)).toEqual(["open@a.test", "mine@a.test"]);
	});

	it("reports unreadable-settings mailboxes only when the caller passes their ACL", () => {
		const { selected, unreadable } = selectInboxMailboxes(mailboxes, acls, flags, "alice@corp.test", []);
		expect(unreadable.map((m) => m.id)).toEqual(["broken@b.test"]);
		expect(selected.map((m) => m.id)).not.toContain("broken@b.test");
	});

	it("fails closed for a null caller outside dev (scoped mailboxes hidden)", () => {
		const { selected } = selectInboxMailboxes(mailboxes, acls, flags, null, [], false);
		expect(selected.map((m) => m.id)).toEqual(["open@a.test"]);
	});
});

describe("cursor encoding", () => {
	it("round-trips", () => {
		const c: InboxCursor = { date: "2026-09-01T12:00:00.000Z", id: "9f1c2d3e-0000-4000-8000-000000000001" };
		expect(decodeCursor(encodeCursor(c))).toEqual(c);
	});

	it("uses base64url characters only", () => {
		expect(encodeCursor({ date: "2026-09-01T12:00:00.000Z", id: "x".repeat(40) })).toMatch(/^[A-Za-z0-9_-]+$/);
	});

	it.each([
		["not base64", "%%%"],
		["not JSON", btoa("hello")],
		["wrong shape", btoa(JSON.stringify({ date: "2026-09-01T12:00:00.000Z" }))],
		["empty id", btoa(JSON.stringify({ d: "2026-09-01T12:00:00.000Z", i: "" }))],
		["non-date", btoa(JSON.stringify({ d: "yesterday", i: "abc" }))],
	])("rejects %s", (_label, input) => {
		expect(decodeCursor(input)).toBeNull();
	});
});

describe("compareInboxRows", () => {
	it("sorts newer first, then higher id first on equal dates", () => {
		const rows = [
			{ id: "a", date: "2026-09-01T10:00:00.000Z" },
			{ id: "b", date: "2026-09-01T12:00:00.000Z" },
			{ id: "c", date: "2026-09-01T12:00:00.000Z" },
		];
		expect([...rows].sort(compareInboxRows).map((r) => r.id)).toEqual(["c", "b", "a"]);
	});
});

// Simulates MailboxDO.getThreadedEmails({ before, limit }) in JS: rows strictly
// after the cursor in (date DESC, id DESC) order. The SQL side is tested in
// test/durableObject/threaded-emails.test.ts.
function doPage(rows: InboxRow[], before: InboxCursor | null, limit: number): InboxRow[] {
	return [...rows]
		.sort(compareInboxRows)
		.filter((r) => !before || compareInboxRows(r, before) > 0)
		.slice(0, limit);
}

function mkRows(prefix: string, dates: string[]): InboxRow[] {
	return dates.map((d, i) => ({ id: `${prefix}-${String(i).padStart(3, "0")}`, date: d, subject: `${prefix} ${i}` }));
}

describe("mergeInboxPages", () => {
	const SAME = "2026-09-01T12:00:00.000Z";
	const fixture: Record<string, InboxRow[]> = {
		"ops@a.test": mkRows("a", [SAME, "2026-09-01T09:00:00.000Z", "2026-08-30T00:00:00.000Z", "2026-08-01T00:00:00.000Z"]),
		"ops@b.test": mkRows("b", [SAME, SAME, "2026-09-02T00:00:00.000Z"]),
		"ops@c.test": mkRows("c", Array.from({ length: 9 }, (_, i) => `2026-07-${String(10 + i).padStart(2, "0")}T00:00:00.000Z`)),
	};

	function pageAt(before: InboxCursor | null, limit: number): PerMailboxInboxPage[] {
		return Object.entries(fixture).map(([id, rows]) => ({
			mailboxId: id,
			mailboxEmail: id,
			emails: doPage(rows, before, limit + 1),
		}));
	}

	it("tags rows with their mailbox and orders across mailboxes", () => {
		const { emails } = mergeInboxPages(pageAt(null, 4), 4);
		expect(emails.map((e) => [e.mailbox_id, e.id])).toEqual([
			["ops@b.test", "b-002"],
			["ops@b.test", "b-001"],
			["ops@b.test", "b-000"],
			["ops@a.test", "a-000"],
		]);
	});

	it("walks every row exactly once across pages, matching one global sort", () => {
		const all = Object.values(fixture).flat().sort(compareInboxRows).map((r) => r.id);
		const seen: string[] = [];
		let before: InboxCursor | null = null;
		for (let guard = 0; guard < 20; guard++) {
			const { emails, nextCursor } = mergeInboxPages(pageAt(before, 3), 3);
			seen.push(...emails.map((e) => e.id));
			if (!nextCursor) break;
			before = decodeCursor(nextCursor);
		}
		expect(seen).toEqual(all);
	});

	it("returns a null cursor exactly when nothing remains", () => {
		const total = Object.values(fixture).flat().length; // 16
		expect(mergeInboxPages(pageAt(null, total), total).nextCursor).toBeNull();
		expect(mergeInboxPages(pageAt(null, total - 1), total - 1).nextCursor).not.toBeNull();
	});

	it("drops rows without a date (they cannot be cursor-paged)", () => {
		const { emails } = mergeInboxPages(
			[{ mailboxId: "x@a.test", mailboxEmail: "x@a.test", emails: [{ id: "n", date: null }, { id: "d", date: SAME }] }],
			10,
		);
		expect(emails.map((e) => e.id)).toEqual(["d"]);
	});
});
