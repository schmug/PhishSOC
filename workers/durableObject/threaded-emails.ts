// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Threaded (conversation-grouped) folder listing for non-draft folders,
 * extracted from MailboxDO.getThreadedEmails so node:sqlite tests can drive it
 * (test/durableObject/threaded-emails.test.ts).
 *
 * `before` is the unified-inbox keyset cursor (GET /api/v1/inbox,
 * workers/lib/unified-inbox.ts): only conversations whose latest in-folder
 * message sorts strictly after {date, id} in (date DESC, id DESC) order.
 * OFFSET is ignored when `before` is set.
 */

import type { SqlLike } from "./catchall-intel";

/**
 * SQL expression to normalize email subjects by stripping common
 * reply/forward prefixes (Re:, Fwd:, FW:, AW:, WG:, Réf:, SV:).
 * Used for conversation grouping. Hardcoded to the `subject` column.
 */
export const NORMALIZED_SUBJECT_SQL = `LOWER(TRIM(
	REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
		LOWER(subject),
		'aw: ', ''), 'wg: ', ''), 'réf: ', ''), 'sv: ', ''),
		're: ', ''), 'fwd: ', ''), 'fw: ', '')
))`;

export type ThreadedCursor = { date: string; id: string };

export type ThreadedEmailRow = {
	id: string;
	subject: string | null;
	sender: string | null;
	recipient: string | null;
	date: string | null;
	read: boolean;
	starred: boolean;
	thread_id: string | null;
	folder_id: string;
	in_reply_to: string | null;
	email_references: string | null;
	snippet: string | null;
	thread_count: number;
	thread_unread_count: number;
	participants: string;
	needs_reply: boolean;
	has_draft: boolean;
};

export function _getThreadedEmailsImpl(
	sql: SqlLike,
	q: { folder: string; limit: number; offset: number; before?: ThreadedCursor },
): ThreadedEmailRow[] {
	const result = sql.exec<Record<string, unknown>>(
		`WITH
		folder_emails AS (
			SELECT *,
				COALESCE(thread_id, id) as raw_thread_id,
				${NORMALIZED_SUBJECT_SQL} as normalized_subject
			FROM emails
			WHERE folder_id = (SELECT id FROM folders WHERE name = ?1 OR id = ?1 LIMIT 1)
		),
		thread_to_conversation AS (
			SELECT
				raw_thread_id,
				normalized_subject,
				CASE
					WHEN thread_id IS NOT NULL THEN raw_thread_id
					ELSE MIN(raw_thread_id) OVER (PARTITION BY normalized_subject)
				END as conversation_id
			FROM folder_emails
			GROUP BY raw_thread_id, normalized_subject, thread_id
		),
		all_emails_with_conversation AS (
			SELECT
				e.*,
				COALESCE(tc.conversation_id, COALESCE(e.thread_id, e.id)) as conversation_id
			FROM emails e
			LEFT JOIN thread_to_conversation tc
				ON COALESCE(e.thread_id, e.id) = tc.raw_thread_id
		),
		conversation_stats AS (
			SELECT
				conversation_id,
				COUNT(*) as thread_count,
				SUM(CASE WHEN read = 0 THEN 1 ELSE 0 END) as thread_unread_count,
				SUM(CASE WHEN read = 1 THEN 1 ELSE 0 END) as thread_read_count,
				GROUP_CONCAT(DISTINCT sender) as participants,
				SUM(CASE WHEN folder_id = (SELECT id FROM folders WHERE name = 'draft' LIMIT 1) THEN 1 ELSE 0 END) as has_draft
			FROM all_emails_with_conversation
			WHERE conversation_id IN (
				SELECT DISTINCT conversation_id FROM all_emails_with_conversation
				WHERE folder_id = (SELECT id FROM folders WHERE name = ?1 OR id = ?1 LIMIT 1)
			)
			GROUP BY conversation_id
		),
		latest_message_per_conversation AS (
			SELECT
				conversation_id,
				folder_id,
				ROW_NUMBER() OVER (PARTITION BY conversation_id ORDER BY date DESC) as rn
			FROM all_emails_with_conversation
		),
		latest_in_folder AS (
			SELECT
				fe.*,
				COALESCE(tc.conversation_id, fe.raw_thread_id) as conversation_id,
				ROW_NUMBER() OVER (
					PARTITION BY COALESCE(tc.conversation_id, fe.raw_thread_id)
					ORDER BY fe.date DESC
				) as rn
			FROM folder_emails fe
			LEFT JOIN thread_to_conversation tc
				ON fe.raw_thread_id = tc.raw_thread_id
		)
		SELECT
			lif.id, lif.subject, lif.sender, lif.recipient, lif.date,
			lif.read, lif.starred, lif.thread_id, lif.folder_id,
			lif.in_reply_to, lif.email_references,
			SUBSTR(lif.body, 1, 300) as snippet,
			cs.thread_count, cs.thread_unread_count, cs.participants,
			CASE WHEN lmc.folder_id != (SELECT id FROM folders WHERE name = 'sent' LIMIT 1)
				AND lmc.folder_id != (SELECT id FROM folders WHERE name = 'draft' LIMIT 1)
				AND cs.thread_read_count > 0
				THEN 1 ELSE 0 END as needs_reply,
			CASE WHEN cs.has_draft > 0 THEN 1 ELSE 0 END as has_draft
		FROM latest_in_folder lif
		JOIN conversation_stats cs ON lif.conversation_id = cs.conversation_id
		LEFT JOIN latest_message_per_conversation lmc
			ON lmc.conversation_id = lif.conversation_id AND lmc.rn = 1
		WHERE lif.rn = 1
			AND (?4 IS NULL OR lif.date < ?4 OR (lif.date = ?4 AND lif.id < ?5)) -- CHANGED: keyset cursor
		ORDER BY lif.date DESC, lif.id DESC -- CHANGED: id tie-break
		LIMIT ?2 OFFSET ?3`,
		q.folder,
		q.limit,
		q.before ? 0 : q.offset,
		q.before?.date ?? null,
		q.before?.id ?? null,
	);

	return [...result].map((row: any) => ({
		...row,
		read: !!row.read,
		starred: !!row.starred,
		thread_count: row.thread_count || 1,
		thread_unread_count: row.thread_unread_count || 0,
		participants: row.participants || row.sender,
		needs_reply: !!row.needs_reply,
		has_draft: !!row.has_draft,
	}));
}
