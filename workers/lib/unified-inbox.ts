// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Pure helpers for the unified "All inboxes" endpoint (GET /api/v1/inbox,
 * workers/routes/unified-inbox.ts). No env, no I/O.
 * Spec: docs/superpowers/specs/2026-09-26-unified-inbox-design.md
 *
 * Ordering invariant: rows merge by (date DESC, id DESC). Email ids are
 * crypto.randomUUID() (workers/index.ts receiveEmail) and dates are ISO-8601,
 * so the pair is a strict total order across mailboxes and a {date, id}
 * cursor never duplicates or skips a row. JS string `<` and SQLite BINARY
 * collation agree on these ASCII values, so this sort matches the DO's
 * `ORDER BY lif.date DESC, lif.id DESC` (workers/durableObject/threaded-emails.ts).
 */

import { callerInAcl, type MailboxAcl } from "./mailbox-acl";

export type InboxCursor = { date: string; id: string };

export type InboxMailboxFlags = { honeypot: boolean; sidecar: boolean; hidden: boolean };

export type InboxRow = { id: string; date: string | null; [k: string]: unknown };

export type PerMailboxInboxPage = {
	mailboxId: string;
	mailboxEmail: string;
	emails: InboxRow[];
};

export type UnifiedInboxRow = InboxRow & { mailbox_id: string; mailbox_email: string };

/**
 * ACL first, then settings flags. `flags[i] === null` means the settings read
 * failed: the mailbox is excluded (unknown honeypot/hidden state must not leak
 * lure mail into the list) and reported in `unreadable` so the UI can show it.
 * A mailbox the caller cannot see never reaches `unreadable` — its id must not
 * leak through the `failed` list.
 */
export function selectInboxMailboxes<T extends { id: string }>(
	mailboxes: T[],
	acls: Array<MailboxAcl | null>,
	flags: Array<InboxMailboxFlags | null>,
	callerEmail: string | null | undefined,
	callerGroups: string[],
	isDev: boolean = false,
): { selected: T[]; unreadable: T[] } {
	const selected: T[] = [];
	const unreadable: T[] = [];
	mailboxes.forEach((m, i) => {
		if (!callerInAcl(acls[i], callerEmail, callerGroups, isDev)) return;
		const f = flags[i];
		if (f === null) {
			unreadable.push(m);
			return;
		}
		if (f.honeypot || f.sidecar || f.hidden) return;
		selected.push(m);
	});
	return { selected, unreadable };
}

/** Negative when `a` sorts first: newer date first, then higher id first. */
export function compareInboxRows(
	a: { date: string | null; id: string },
	b: { date: string | null; id: string },
): number {
	const da = a.date ?? "";
	const db = b.date ?? "";
	if (da !== db) return da < db ? 1 : -1;
	if (a.id !== b.id) return a.id < b.id ? 1 : -1;
	return 0;
}

export function encodeCursor(c: InboxCursor): string {
	return btoa(JSON.stringify({ d: c.date, i: c.id }))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

export function decodeCursor(s: string): InboxCursor | null {
	try {
		const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
		const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
		const v = JSON.parse(atob(padded)) as unknown;
		if (!v || typeof v !== "object") return null;
		const { d, i } = v as { d?: unknown; i?: unknown };
		if (typeof d !== "string" || typeof i !== "string" || !d || !i) return null;
		if (Number.isNaN(Date.parse(d))) return null;
		return { date: d, id: i };
	} catch {
		return null;
	}
}

/**
 * Each page in `perMailbox` must be that mailbox's first `limit + 1` rows after
 * the cursor. The merged set then holds more than `limit` rows exactly when
 * another page exists. Rows without a date are dropped: inbox rows always carry
 * a receive time, and a null date cannot be encoded in a cursor.
 */
export function mergeInboxPages(
	perMailbox: PerMailboxInboxPage[],
	limit: number,
): { emails: UnifiedInboxRow[]; nextCursor: string | null } {
	const rows: UnifiedInboxRow[] = [];
	for (const p of perMailbox) {
		for (const e of p.emails) {
			if (typeof e.date !== "string" || e.date === "") continue;
			rows.push({ ...e, mailbox_id: p.mailboxId, mailbox_email: p.mailboxEmail });
		}
	}
	rows.sort(compareInboxRows);
	const page = rows.slice(0, limit);
	const last = page[page.length - 1];
	const nextCursor =
		rows.length > limit && last ? encodeCursor({ date: last.date as string, id: last.id }) : null;
	return { emails: page, nextCursor };
}
