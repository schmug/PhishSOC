// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Resolve outbound send-risk provenance from a draft row (#266).
 * Callers pass `draft_id` on send/preflight; we read `created_by` from the
 * DO so clients cannot spoof agent-authored tier bumps.
 */

export type SendCreatedBy = "agent" | "user";

type DraftRow = { created_by?: string | null } | null;

export async function resolveCreatedByFromDraft(
	stub: { getEmail(id: string): Promise<DraftRow> },
	draftId?: string,
): Promise<SendCreatedBy | undefined> {
	if (!draftId) return undefined;
	const row = await stub.getEmail(draftId);
	if (!row) return undefined;
	return row.created_by === "agent" ? "agent" : "user";
}
