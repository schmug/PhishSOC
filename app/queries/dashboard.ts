// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { useQuery } from "@tanstack/react-query";
import api from "~/services/api";
import type { DashboardSummary, LinkDomainsSummary } from "~/types";
import { queryKeys } from "./keys";

export function useDashboardSummary(mailboxId: string | undefined) {
	return useQuery<DashboardSummary>({
		queryKey: mailboxId ? queryKeys.dashboard(mailboxId) : ["dashboard", "_disabled"],
		queryFn: ({ signal }) =>
			api.getDashboardSummary(mailboxId!, { signal }) as Promise<DashboardSummary>,
		enabled: !!mailboxId,
		staleTime: 30_000,
	});
}

export function useLinkDomains(mailboxId: string | undefined, days = 30) {
	return useQuery<LinkDomainsSummary>({
		queryKey: mailboxId ? queryKeys.linkDomains(mailboxId, days) : ["dashboard", "_disabled", "link-domains", days],
		queryFn: ({ signal }) =>
			api.getLinkDomains(mailboxId!, days, { signal }) as Promise<LinkDomainsSummary>,
		enabled: !!mailboxId,
		staleTime: 60_000,
	});
}
