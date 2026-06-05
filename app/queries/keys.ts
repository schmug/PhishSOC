// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/** Centralised query key factories for cache invalidation. */
export const queryKeys = {
	mailboxes: {
		all: ["mailboxes"] as const,
		detail: (id: string) => ["mailboxes", id] as const,
		acl: (id: string) => ["mailboxes", id, "acl"] as const,
	},
	emails: {
		list: (mailboxId: string, params: Record<string, string>) =>
			["emails", mailboxId, params] as const,
		detail: (mailboxId: string, emailId: string) =>
			["emails", mailboxId, emailId] as const,
		thread: (mailboxId: string, threadId: string) =>
			["emails", mailboxId, "thread", threadId] as const,
		urls: (mailboxId: string, emailId: string) =>
			["emails", mailboxId, emailId, "urls"] as const,
	},
	folders: {
		list: (mailboxId: string) => ["folders", mailboxId] as const,
	},
	search: {
		results: (mailboxId: string, query: string, page: number) =>
			["search", mailboxId, query, page] as const,
		orgResults: (query: string, page: number) =>
			["search", "_org", query, page] as const,
	},
	dashboard: (mailboxId: string) => ["dashboard", mailboxId] as const,
	org: {
		overview: ["org", "overview"] as const,
		settings: ["org", "settings"] as const,
	},
	effectiveMailboxSettings: (mailboxId: string) =>
		["mailboxes", mailboxId, "settings", "effective"] as const,
	domains: {
		list: ["domains"] as const,
		detail: (domain: string) => ["domains", domain] as const,
		settings: (domain: string) => ["domains", domain, "settings"] as const,
		catchallIntel: (domain: string) => ["domains", domain, "catchall-intel"] as const,
	},
	hub: {
		contributions: (mailboxId: string) => ["hub", mailboxId, "contributions"] as const,
		destroylist: (mailboxId: string) => ["hub", mailboxId, "destroylist"] as const,
		sharingGroups: (mailboxId: string) => ["hub", mailboxId, "sharing-groups"] as const,
	},
	config: ["config"] as const,
	textModels: ["ai", "text-models"] as const,
	me: ["me"] as const,
};
