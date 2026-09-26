// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * GET /api/v1/inbox — unified "All inboxes" list.
 * Spec: docs/superpowers/specs/2026-09-26-unified-inbox-design.md
 *
 * Mounted at /api/v1/inbox in workers/index.ts, OUTSIDE
 * /api/v1/mailboxes/:mailboxId, so requireMailbox does not run: this handler
 * applies the per-mailbox ACL itself via selectInboxMailboxes. Identity comes
 * from the verified CF Access JWT only (f17) — never the
 * cf-access-authenticated-user-email header.
 *
 * Query: before (opaque cursor from a previous nextCursor), limit (1–50, default 25).
 * Response: { emails, nextCursor, failed, mailboxCount }.
 */

import { Hono } from "hono";
import { Folders } from "../../shared/folders";
import { listMailboxes } from "../lib/email-helpers";
import { callerEmailFromJwt, callerGroupsFromJwt, readMailboxAcl } from "../lib/mailbox-acl";
import { resolveMailboxSettings } from "../lib/mailbox-settings";
import { sidecarConfigOf } from "../lib/sidecar-config";
import {
	decodeCursor,
	mergeInboxPages,
	selectInboxMailboxes,
	type InboxCursor,
	type InboxMailboxFlags,
	type InboxRow,
	type PerMailboxInboxPage,
} from "../lib/unified-inbox";
import type { Env } from "../types";

export const UNIFIED_INBOX_DEFAULT_LIMIT = 25;
export const UNIFIED_INBOX_MAX_LIMIT = 50;

/** The one MailboxDO RPC this route calls (workers/durableObject/index.ts getThreadedEmails). */
type ThreadedInboxStub = {
	getThreadedEmails(opts: { folder: string; limit: number; before?: InboxCursor }): Promise<InboxRow[]>;
};

export const unifiedInboxRoutes = new Hono<{ Bindings: Env }>();

unifiedInboxRoutes.get("/", async (c) => {
	const jwt = c.req.header("cf-access-jwt-assertion");
	const callerEmail = callerEmailFromJwt(jwt)?.toLowerCase() ?? null;
	const callerGroups = callerGroupsFromJwt(jwt);

	let before: InboxCursor | undefined;
	const rawBefore = c.req.query("before");
	if (rawBefore) {
		const decoded = decodeCursor(rawBefore);
		if (!decoded) return c.json({ error: "Invalid cursor" }, 400);
		before = decoded;
	}
	const parsedLimit = Number.parseInt(c.req.query("limit") ?? "", 10);
	const limit = Number.isFinite(parsedLimit)
		? Math.min(Math.max(parsedLimit, 1), UNIFIED_INBOX_MAX_LIMIT)
		: UNIFIED_INBOX_DEFAULT_LIMIT;

	const mailboxes = await listMailboxes(c.env.BUCKET);
	const [acls, flags] = await Promise.all([
		Promise.all(mailboxes.map((m) => readMailboxAcl(c.env, m.id))),
		Promise.all(
			mailboxes.map(async (m): Promise<InboxMailboxFlags | null> => {
				try {
					const raw = (await resolveMailboxSettings(c.env, m.id)).raw;
					return {
						honeypot: !!raw?.honeypot?.enabled,
						sidecar: !!sidecarConfigOf(raw),
						hidden: raw?.hideFromAllInboxes === true,
					};
				} catch (err) {
					console.error("unified-inbox: settings read failed:", m.id, (err as Error)?.message);
					return null;
				}
			}),
		),
	]);
	const { selected, unreadable } = selectInboxMailboxes(
		mailboxes,
		acls,
		flags,
		callerEmail,
		callerGroups,
		import.meta.env.DEV,
	);

	const settled = await Promise.allSettled(
		selected.map(async (m): Promise<PerMailboxInboxPage> => {
			const stub = c.env.MAILBOX.get(c.env.MAILBOX.idFromName(m.id)) as unknown as ThreadedInboxStub;
			const emails = await stub.getThreadedEmails({ folder: Folders.INBOX, limit: limit + 1, before });
			return { mailboxId: m.id, mailboxEmail: m.email, emails };
		}),
	);
	const pages: PerMailboxInboxPage[] = [];
	const failed = unreadable.map((m) => m.id);
	settled.forEach((r, i) => {
		if (r.status === "fulfilled") {
			pages.push(r.value);
			return;
		}
		failed.push(selected[i].id);
		console.error("unified-inbox: mailbox query failed:", selected[i].id, (r.reason as Error)?.message);
	});

	return c.json({ ...mergeInboxPages(pages, limit), failed, mailboxCount: selected.length });
});
