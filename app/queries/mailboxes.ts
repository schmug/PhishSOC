// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api, { ApiError } from "~/services/api";
import type { Mailbox } from "~/types";
import { queryKeys } from "./keys";

export function useMailboxes() {
	return useQuery<Mailbox[]>({
		queryKey: queryKeys.mailboxes.all,
		queryFn: () => api.listMailboxes() as Promise<Mailbox[]>,
	});
}

export function useMailbox(mailboxId: string | undefined) {
	return useQuery<Mailbox>({
		queryKey: mailboxId
			? queryKeys.mailboxes.detail(mailboxId)
			: ["mailboxes", "_disabled"],
		queryFn: () => api.getMailbox(mailboxId!) as Promise<Mailbox>,
		enabled: !!mailboxId,
	});
}

export function useCreateMailbox() {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: ({ email, name }: { email: string; name: string }) =>
			api.createMailbox(email, name),
		onSuccess: () => {
			qc.invalidateQueries({ queryKey: queryKeys.mailboxes.all });
		},
	});
}

export function useUpdateMailbox() {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: ({
			mailboxId,
			settings,
		}: { mailboxId: string; settings: unknown }) =>
			api.updateMailbox(mailboxId, settings),
		onSuccess: (_data, { mailboxId }) => {
			qc.invalidateQueries({ queryKey: queryKeys.mailboxes.detail(mailboxId) });
			qc.invalidateQueries({ queryKey: queryKeys.mailboxes.all });
		},
	});
}

export function useDeleteMailbox() {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: (mailboxId: string) => api.deleteMailbox(mailboxId),
		onSuccess: () => {
			qc.invalidateQueries({ queryKey: queryKeys.mailboxes.all });
		},
	});
}

export function useLockDownMailbox() {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: (mailboxId: string) => api.lockDownMailbox(mailboxId),
		onSuccess: () => {
			qc.invalidateQueries({ queryKey: queryKeys.mailboxes.all });
		},
	});
}

export function useLockDownAllMailboxes() {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: () => api.lockDownAllMailboxes(),
		onSuccess: () => {
			qc.invalidateQueries({ queryKey: queryKeys.mailboxes.all });
		},
	});
}

export function useMailboxAcl(mailboxId: string | undefined) {
	return useQuery<{ owner: string; members: string[] } | null>({
		queryKey: mailboxId ? queryKeys.mailboxes.acl(mailboxId) : ["mailboxes", "_acl_disabled"],
		queryFn: async () => {
			try {
				return await api.getMailboxAcl(mailboxId!) as { owner: string; members: string[] };
			} catch (err) {
				if (err instanceof ApiError && err.status === 404) return null;
				throw err;
			}
		},
		enabled: !!mailboxId,
	});
}

export function useAddAclMember(mailboxId: string) {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: (email: string) => api.addAclMember(mailboxId, email),
		onSuccess: () => {
			qc.invalidateQueries({ queryKey: queryKeys.mailboxes.acl(mailboxId) });
		},
	});
}

export function useRemoveAclMember(mailboxId: string) {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: (email: string) => api.removeAclMember(mailboxId, email),
		onSuccess: () => {
			qc.invalidateQueries({ queryKey: queryKeys.mailboxes.acl(mailboxId) });
		},
	});
}

export function useTransferAclOwnership(mailboxId: string) {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: (email: string) => api.transferAclOwnership(mailboxId, email),
		onSuccess: () => {
			qc.invalidateQueries({ queryKey: queryKeys.mailboxes.acl(mailboxId) });
		},
	});
}

export function useOrgAclOverview() {
	return useQuery<{
		mailboxes: Array<{
			email: string;
			acl_status: "scoped" | "unscoped";
			owner: string | null;
			members: string[];
		}>;
	}>({
		queryKey: queryKeys.org.aclOverview,
		queryFn: () => api.getOrgAclOverview(),
	});
}
