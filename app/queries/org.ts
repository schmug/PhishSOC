// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { useQuery } from "@tanstack/react-query";
import api from "~/services/api";
import type { AclOverviewEntry, OrgOverview } from "~/types";
import { queryKeys } from "./keys";

export function useOrgOverview() {
	return useQuery<OrgOverview>({
		queryKey: queryKeys.org.overview,
		queryFn: ({ signal }) => api.getOrgOverview({ signal }) as Promise<OrgOverview>,
		// Server caches the merged result for 60s, so a 30s client stale window
		// keeps navigation snappy without ever serving data older than ~90s.
		staleTime: 30_000,
	});
}

export function useOrgAclOverview() {
	return useQuery<AclOverviewEntry[]>({
		queryKey: queryKeys.org.aclOverview,
		queryFn: ({ signal }) =>
			api.getOrgAclOverview({ signal }) as Promise<AclOverviewEntry[]>,
	});
}
