// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "~/services/api";
import type { CatchallSummary, DomainListEntry, DomainStats, DmarcRufRecord } from "~/types";
import { queryKeys } from "./keys";

/**
 * `/api/v1/domains` — domains list with aggregate stats (#85). The worker
 * caches the merged result for 60s, so a 30s client stale window keeps
 * navigation snappy without serving data older than ~90s.
 */
export function useDomains() {
	return useQuery<DomainListEntry[]>({
		queryKey: queryKeys.domains.list,
		queryFn: ({ signal }) =>
			api.listDomains({ signal }) as Promise<DomainListEntry[]>,
		staleTime: 30_000,
	});
}

export function useDomainStats(domain: string | undefined) {
	return useQuery<DomainStats>({
		queryKey: domain ? queryKeys.domains.detail(domain) : ["domains", "_disabled"],
		queryFn: ({ signal }) =>
			api.getDomainStats(domain!, { signal }) as Promise<DomainStats>,
		enabled: !!domain,
		staleTime: 30_000,
	});
}

export function useAddDomain() {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: (domain: string) => api.addDomain(domain),
		onSuccess: () => {
			// Invalidate config so the New Mailbox dropdown picks up the new domain.
			qc.invalidateQueries({ queryKey: queryKeys.config });
		},
	});
}

export function useRemoveDomain() {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: (domain: string) => api.removeDomain(domain),
		onSuccess: () => {
			qc.invalidateQueries({ queryKey: queryKeys.config });
		},
	});
}

export interface RufRecordsResponse {
	enabled: boolean;
	records: DmarcRufRecord[];
}

export function useRufRecords(domain: string | undefined) {
	return useQuery<RufRecordsResponse>({
		queryKey: domain ? ["domains", domain, "ruf-records"] : ["domains", "_disabled", "ruf-records"],
		queryFn: ({ signal }) =>
			api.getDomainRufRecords(domain!, { signal }) as Promise<RufRecordsResponse>,
		enabled: !!domain,
		staleTime: 60_000,
	});
}

export function useCatchallIntel(domain: string | undefined) {
	return useQuery<CatchallSummary>({
		queryKey: domain
			? queryKeys.domains.catchallIntel(domain)
			: ["domains", "_disabled", "catchall-intel"],
		queryFn: ({ signal }) =>
			api.getDomainCatchallIntel(domain!, { signal }) as Promise<CatchallSummary>,
		enabled: !!domain,
		staleTime: 60_000,
	});
}
