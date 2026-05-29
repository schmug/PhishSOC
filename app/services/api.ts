// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import type {
	DashboardSummary,
	DomainListEntry,
	DomainStats,
	DmarcRufRecord,
	Email,
	EmailUrl,
	Folder,
	HubContributionsResponse,
	HubDestroylistResponse,
	HubInviteRequest,
	HubInviteResponse,
	HubSharingGroupsResponse,
	Mailbox,
	OrgOverview,
} from "~/types";

const REQUEST_TIMEOUT_MS = 30_000;

export class ApiError extends Error {
	status: number;
	body: Record<string, unknown>;

	constructor(status: number, body: Record<string, unknown>) {
		super((body.error as string) || `Request failed: ${status}`);
		this.name = "ApiError";
		this.status = status;
		this.body = body;
	}
}

async function request<T>(
	url: string,
	options: RequestInit = {},
): Promise<T> {
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

	// Combine caller signal (e.g. TanStack Query abort) with our timeout signal
	const signal = options.signal
		? AbortSignal.any([options.signal, controller.signal])
		: controller.signal;

	try {
		const res = await fetch(url, {
			...options,
			signal,
			headers: {
				"Content-Type": "application/json",
				...(options.headers as Record<string, string>),
			},
		});

		if (!res.ok) {
			const body = await res.json().catch(() => ({}));
			throw new ApiError(res.status, body as Record<string, unknown>);
		}

		if (res.status === 204) return undefined as T;

		const contentType = res.headers.get("content-type") ?? "";
		if (contentType.includes("application/json")) {
			return res.json() as Promise<T>;
		}
		return res.blob() as unknown as T;
	} finally {
		clearTimeout(timeout);
	}
}

function get<T>(url: string, opts?: { params?: Record<string, string>; responseType?: string; signal?: AbortSignal }) {
	const query = opts?.params ? `?${new URLSearchParams(opts.params)}` : "";
	return request<T>(`${url}${query}`, {
		method: "GET",
		signal: opts?.signal,
		...(opts?.responseType === "blob" ? { headers: { Accept: "*/*" } } : {}),
	});
}

function post<T>(
	url: string,
	body?: unknown,
	opts?: { signal?: AbortSignal; headers?: Record<string, string> },
) {
	return request<T>(url, {
		method: "POST",
		signal: opts?.signal,
		...(opts?.headers ? { headers: opts.headers } : {}),
		body: body != null ? JSON.stringify(body) : undefined,
	});
}

/** x-confirmation-token header opts for a step-up–gated send (#285). */
function confirmOpts(confirmationToken?: string) {
	return confirmationToken
		? { headers: { "x-confirmation-token": confirmationToken } }
		: undefined;
}

function put<T>(url: string, body?: unknown) {
	return request<T>(url, {
		method: "PUT",
		body: body != null ? JSON.stringify(body) : undefined,
	});
}

function del<T>(url: string) {
	return request<T>(url, { method: "DELETE" });
}

// ---------- Typed response shapes ----------

interface EmailListResponse {
	emails: Email[];
	totalCount: number;
}

// ---------- API client ----------

const api = {
	// Config
	getConfig: () =>
		get<{ domains: string[]; emailAddresses: string[] }>("/api/v1/config"),

	// Authenticated-user identity (#204). Sourced from the worker's
	// `/api/v1/me` endpoint, which reads the verified-by-Access
	// `Cf-Access-Authenticated-User-Email` header.
	getMe: () => get<{ email: string }>("/api/v1/me"),

	// Mailboxes
	listMailboxes: () => get<Mailbox[]>("/api/v1/mailboxes"),
	createMailbox: (email: string, name: string, settings?: unknown) =>
		post<Mailbox>("/api/v1/mailboxes", { email, name, settings }),
	getMailbox: (mailboxId: string) =>
		get<Mailbox>(`/api/v1/mailboxes/${mailboxId}`),
	updateMailbox: (mailboxId: string, settings: unknown) =>
		put<Mailbox>(`/api/v1/mailboxes/${mailboxId}`, { settings }),
	deleteMailbox: (mailboxId: string) =>
		del<void>(`/api/v1/mailboxes/${mailboxId}`),
	lockDownMailbox: (mailboxId: string) =>
		post<{ owner: string; members: string[] }>(`/api/v1/mailboxes/${mailboxId}/acl`),
	lockDownAllMailboxes: () =>
		post<{ locked: number; skipped: number; errors: string[] }>("/api/v1/mailboxes/bulk-lockdown"),
	getMailboxAcl: (mailboxId: string) =>
		get<{ owner: string; members: string[]; groups: string[] }>(`/api/v1/mailboxes/${mailboxId}/acl`),
	addAclMember: (mailboxId: string, email: string) =>
		post<{ owner: string; members: string[]; groups: string[] }>(`/api/v1/mailboxes/${mailboxId}/acl/members`, { email }),
	removeAclMember: (mailboxId: string, email: string) =>
		del<{ owner: string; members: string[]; groups: string[] }>(`/api/v1/mailboxes/${mailboxId}/acl/members/${encodeURIComponent(email)}`),
	transferAclOwnership: (mailboxId: string, email: string) =>
		post<{ owner: string; members: string[]; groups: string[] }>(`/api/v1/mailboxes/${mailboxId}/acl/transfer`, { email }),
	addAclGroup: (mailboxId: string, group: string) =>
		post<{ owner: string; members: string[]; groups: string[] }>(`/api/v1/mailboxes/${mailboxId}/acl/groups`, { group }),
	removeAclGroup: (mailboxId: string, group: string) =>
		del<{ owner: string; members: string[]; groups: string[] }>(`/api/v1/mailboxes/${mailboxId}/acl/groups/${encodeURIComponent(group)}`),
	// Org-level settings (#106). Backed by R2 key org/settings.json behind a
	// module-scope ETag cache; the GET returns the raw blob (or {} if missing),
	// PUT validates through the OrgSettings Zod schema worker-side.
	getAclOverview: () =>
		get<Array<{ email: string; acl_status: "scoped" | "unscoped"; owner: string | null; members: string[] }>>(
			"/api/v1/org/acl-overview",
		),
	getOrgSettings: () =>
		get<{ settings: Record<string, unknown> }>("/api/v1/org/settings"),
	updateOrgSettings: (settings: unknown) =>
		put<{ settings: Record<string, unknown> }>("/api/v1/org/settings", { settings }),
	// Resolved (inheritance-applied) settings for a mailbox: mailbox > org > default.
	// Used by the settings UI's "Inherited from org" indicator to render the
	// org value as a preview when the mailbox tier is absent.
	getEffectiveMailboxSettings: (mailboxId: string) =>
		get<{ id: string; settings: Record<string, unknown> }>(
			`/api/v1/mailboxes/${mailboxId}/settings/effective`,
		),
	// Domain-level settings (#142). Sits between mailbox and org in the
	// inheritance hierarchy. Same R2/ETag pattern as the org endpoints.
	getDomainSettings: (domain: string) =>
		get<{ domain: string; settings: Record<string, unknown> }>(
			`/api/v1/domains/${encodeURIComponent(domain)}/settings`,
		),
	updateDomainSettings: (domain: string, settings: unknown) =>
		put<{ domain: string; settings: Record<string, unknown> }>(
			`/api/v1/domains/${encodeURIComponent(domain)}/settings`,
			{ settings },
		),

	// Emails
	listEmails: (mailboxId: string, params: Record<string, string>, opts?: { signal?: AbortSignal }) =>
		get<EmailListResponse | Email[]>(`/api/v1/mailboxes/${mailboxId}/emails`, { params, signal: opts?.signal }),
	preflightEmail: (mailboxId: string, email: unknown) =>
		post<{ tier: 0 | 1 | 2; reasons: string[] }>(
			`/api/v1/mailboxes/${mailboxId}/emails/preflight`,
			email,
		),
	sendEmail: (mailboxId: string, email: unknown, confirmationToken?: string) =>
		post<void>(`/api/v1/mailboxes/${mailboxId}/emails`, email, confirmOpts(confirmationToken)),
	getEmail: (mailboxId: string, id: string, opts?: { signal?: AbortSignal }) =>
		get<Email>(`/api/v1/mailboxes/${mailboxId}/emails/${id}`, { signal: opts?.signal }),
	updateEmail: (mailboxId: string, id: string, data: unknown) =>
		put<Email>(`/api/v1/mailboxes/${mailboxId}/emails/${id}`, data),
	deleteEmail: (mailboxId: string, id: string) =>
		del<void>(`/api/v1/mailboxes/${mailboxId}/emails/${id}`),
	moveEmail: (mailboxId: string, id: string, folderId: string) =>
		post<void>(`/api/v1/mailboxes/${mailboxId}/emails/${id}/move`, { folderId }),
	getThread: (mailboxId: string, threadId: string, opts?: { signal?: AbortSignal }) =>
		get<Email[]>(`/api/v1/mailboxes/${mailboxId}/threads/${threadId}`, { signal: opts?.signal }),
	markThreadRead: (mailboxId: string, threadId: string) =>
		post<void>(`/api/v1/mailboxes/${mailboxId}/threads/${threadId}/read`),
	getEmailUrls: (mailboxId: string, emailId: string) =>
		get<{ urls: EmailUrl[] }>(`/api/v1/mailboxes/${mailboxId}/emails/${emailId}/urls`),
	getAttachment: (mailboxId: string, emailId: string, attachmentId: string) =>
		get<Blob>(`/api/v1/mailboxes/${mailboxId}/emails/${emailId}/attachments/${attachmentId}`, { responseType: "blob" }),
	saveDraft: (
		mailboxId: string,
		draft: {
			to?: string;
			cc?: string;
			bcc?: string;
			subject?: string;
			body: string;
			in_reply_to?: string;
			thread_id?: string;
			draft_id?: string;
		},
	) => post<{ draft_id: string }>(`/api/v1/mailboxes/${mailboxId}/drafts`, draft),
	replyToEmail: (mailboxId: string, emailId: string, email: unknown, confirmationToken?: string) =>
		post<void>(`/api/v1/mailboxes/${mailboxId}/emails/${emailId}/reply`, email, confirmOpts(confirmationToken)),
	forwardEmail: (mailboxId: string, emailId: string, email: unknown, confirmationToken?: string) =>
		post<void>(`/api/v1/mailboxes/${mailboxId}/emails/${emailId}/forward`, email, confirmOpts(confirmationToken)),

	// Folders
	listFolders: (mailboxId: string) =>
		get<Folder[]>(`/api/v1/mailboxes/${mailboxId}/folders`),
	createFolder: (mailboxId: string, name: string) =>
		post<Folder>(`/api/v1/mailboxes/${mailboxId}/folders`, { name }),
	updateFolder: (mailboxId: string, id: string, name: string) =>
		put<Folder>(`/api/v1/mailboxes/${mailboxId}/folders/${id}`, { name }),
	deleteFolder: (mailboxId: string, id: string) =>
		del<void>(`/api/v1/mailboxes/${mailboxId}/folders/${id}`),

	// Search
	searchEmails: (mailboxId: string, params: Record<string, string>) =>
		get<EmailListResponse | Email[]>(`/api/v1/mailboxes/${mailboxId}/search`, { params }),

	// Org-scope search across every mailbox the caller can see (#197).
	searchOrgEmails: (params: Record<string, string>) =>
		get<EmailListResponse>("/api/v1/org/search", { params }),

	// Dashboard
	getDashboardSummary: (mailboxId: string, opts?: { signal?: AbortSignal }) =>
		get<DashboardSummary>(`/api/v1/mailboxes/${mailboxId}/dashboard`, { signal: opts?.signal }),

	// Org overview
	getOrgOverview: (opts?: { signal?: AbortSignal }) =>
		get<OrgOverview>("/api/v1/org/overview", { signal: opts?.signal }),

	// Domains (#85). Domain identifiers are hostname-shaped (a-z, 0-9, hyphen,
	// dot); they don't need encodeURIComponent for those characters, but we
	// still encode defensively in case future IDN handling lands.
	listDomains: (opts?: { signal?: AbortSignal }) =>
		get<DomainListEntry[]>("/api/v1/domains", { signal: opts?.signal }),
	getDomainStats: (domain: string, opts?: { signal?: AbortSignal }) =>
		get<DomainStats>(`/api/v1/domains/${encodeURIComponent(domain)}/stats`, {
			signal: opts?.signal,
		}),
	addDomain: (domain: string) =>
		post<{ domain: string; domains: string[] }>("/api/v1/org/domains", { domain }),
	removeDomain: (domain: string) =>
		del<{ domains: string[] }>(`/api/v1/org/domains/${encodeURIComponent(domain)}`),
	getDomainRufRecords: (domain: string, opts?: { signal?: AbortSignal }) =>
		get<{ enabled: boolean; records: DmarcRufRecord[] }>(
			`/api/v1/domains/${encodeURIComponent(domain)}/ruf-records`,
			{ signal: opts?.signal },
		),

	// Hub
	getHubContributions: (mailboxId: string, opts?: { signal?: AbortSignal }) =>
		get<HubContributionsResponse>(`/api/v1/mailboxes/${mailboxId}/hub/contributions`, {
			signal: opts?.signal,
		}),
	getHubDestroylist: (mailboxId: string, opts?: { signal?: AbortSignal }) =>
		get<HubDestroylistResponse>(`/api/v1/mailboxes/${mailboxId}/hub/destroylist`, {
			signal: opts?.signal,
		}),
	getHubSharingGroups: (mailboxId: string, opts?: { signal?: AbortSignal }) =>
		get<HubSharingGroupsResponse>(`/api/v1/mailboxes/${mailboxId}/hub/sharing-groups`, {
			signal: opts?.signal,
		}),
	createHubInvite: (mailboxId: string, body: HubInviteRequest) =>
		post<HubInviteResponse>(`/api/v1/mailboxes/${mailboxId}/hub/invites`, body),

	// AI — Workers AI text-generation model list (#64). Worker
	// read-through caches against KV with a static fallback, so this
	// endpoint always resolves to a usable list.
	getTextModels: (opts?: { signal?: AbortSignal }) =>
		get<{ models: string[] }>("/api/v1/ai/text-models", { signal: opts?.signal }),
};

export default api;
