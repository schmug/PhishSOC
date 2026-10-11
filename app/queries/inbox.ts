// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { useQuery } from "@tanstack/react-query";
import api from "~/services/api";
import type { UnifiedInboxResponse } from "~/types";
import { queryKeys } from "./keys";

/**
 * Polling instead of per-mailbox WebSockets: one socket per mailbox does not
 * scale to the operator's >10 mailboxes. React Query pauses the interval
 * while the tab is hidden.
 */
export const UNIFIED_INBOX_REFRESH_MS = 30_000;

export function useUnifiedInbox(before: string | null) {
	return useQuery<UnifiedInboxResponse>({
		queryKey: queryKeys.unifiedInbox.page(before),
		queryFn: () => api.listUnifiedInbox({ before }),
		refetchInterval: UNIFIED_INBOX_REFRESH_MS,
		refetchOnWindowFocus: true,
	});
}
