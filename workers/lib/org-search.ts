// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Pure aggregator for the org-scope search endpoint (#197).
 *
 * The HTTP handler fans out only across mailboxes the caller may access
 * (`callerInAcl`, #27/#295), collects per-mailbox `searchEmails` +
 * `countSearchResults` results, then merges them here. Keeping the merge as a
 * pure function lets us unit-test ordering, pagination, and per-mailbox tagging
 * without having to mock R2 + every Durable Object stub.
 */

import { callerInAcl, type MailboxAcl } from "./mailbox-acl";

/** Restrict org-search fan-out to mailboxes the caller is permitted to access. */
export function mailboxesForOrgSearch<T extends { id: string }>(
	mailboxes: T[],
	acls: Array<MailboxAcl | null>,
	callerEmail: string | null | undefined,
	callerGroups: string[],
): T[] {
	return mailboxes.filter((_, i) => callerInAcl(acls[i], callerEmail, callerGroups));
}

export type OrgSearchEmailRow = {
	id: string;
	date: string | null;
	[k: string]: unknown;
};

export type PerMailboxSearchResult = {
	mailboxId: string;
	mailboxEmail: string;
	emails: OrgSearchEmailRow[];
	count: number;
};

export type OrgSearchResponseRow = OrgSearchEmailRow & {
	mailbox_id: string;
	mailbox_email: string;
};

export type OrgSearchResponse = {
	emails: OrgSearchResponseRow[];
	totalCount: number;
};

/**
 * Merge per-mailbox search results into a single page-sliced response.
 *
 * Ordering matches per-mailbox search: `date DESC`, with `null`/missing dates
 * sorted to the end so they don't displace dated rows.
 */
export function aggregateOrgSearch(
	perMailbox: PerMailboxSearchResult[],
	page: number,
	limit: number,
): OrgSearchResponse {
	const rows: OrgSearchResponseRow[] = [];
	let totalCount = 0;
	for (const r of perMailbox) {
		totalCount += r.count;
		for (const e of r.emails) {
			rows.push({
				...e,
				mailbox_id: r.mailboxId,
				mailbox_email: r.mailboxEmail,
			});
		}
	}
	rows.sort((a, b) => {
		const da = a.date ?? "";
		const db = b.date ?? "";
		if (!da && !db) return 0;
		if (!da) return 1;
		if (!db) return -1;
		return db.localeCompare(da);
	});
	const start = Math.max(0, (page - 1) * limit);
	const slice = rows.slice(start, start + limit);
	return { emails: slice, totalCount };
}
