// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// Shared factories for the queries `Shell` (`app/components/phishsoc/Shell.tsx`)
// consumes. Any test that renders Shell — directly or via a route element —
// must mock every one of these so the render doesn't fan out to the real
// fetcher. Today Shell calls `useMailbox`, `useMailboxes` (from
// `~/queries/mailboxes`), `useDashboardSummary` (from `~/queries/dashboard`),
// `useDomainStats` (from `~/queries/domains`), and `useFolders` (from
// `~/queries/folders`).
//
// **Adding a new query to Shell?** Update the matching factory below — every
// test that calls the factory in its `vi.mock(...)` body picks up the new
// export automatically. This was the gap that bit us in the May 2 sweep:
// PR #143 added `useDomainStats` to Shell, and PR #145 (developed in
// parallel) had to be patched after rebase because its `home.test.tsx` and
// `domains-list.test.tsx` mocked `~/queries/domains` without exposing the
// new hook.
//
// Usage:
//
//   vi.mock("~/queries/mailboxes", () => shellMailboxesMock());
//   vi.mock("~/queries/dashboard", () => shellDashboardMock());
//   vi.mock("~/queries/domains", () => shellDomainsMock({
//     // Per-test override — the route under test exercises this hook with
//     // varying state, so let the test thread the mutable closure in.
//     useDomainStats: () => ({ ...queryState, refetch }),
//   }));
//
// Each factory accepts an `overrides` object so individual tests can swap in
// per-case behavior (e.g. `home.test.tsx` varies `useDomains` per test) while
// keeping the Shell-baseline defaults for everything else.

import { vi } from "vitest";

/**
 * Minimal subset of `useQuery`'s return shape that the Shell-rendering
 * routes actually destructure. Helpers default these to "loading-resolved,
 * empty / undefined" so the Shell render path doesn't fan out, and tests
 * can override per-case.
 */
type QueryStub<T> = {
	data: T | undefined;
	isLoading?: boolean;
	isError?: boolean;
	refetch?: () => void;
	isFetched?: boolean;
};

export interface ShellMailboxesMockOverrides {
	useMailboxes?: () => QueryStub<unknown[]>;
	useMailbox?: () => QueryStub<unknown>;
	[key: string]: unknown;
}

/**
 * Factory for `~/queries/mailboxes`. Defaults: empty mailbox list, undefined
 * single mailbox. Pass extra exports through `overrides` if a route under
 * test consumes a hook (e.g. `useUpdateMailbox`) that Shell itself doesn't.
 */
export function shellMailboxesMock(
	overrides: ShellMailboxesMockOverrides = {},
): Record<string, unknown> {
	return {
		useMailboxes: () => ({ data: [], refetch: vi.fn(), isFetched: true }),
		useMailbox: () => ({ data: undefined }),
		...overrides,
	};
}

export interface ShellDashboardMockOverrides {
	useDashboardSummary?: () => QueryStub<unknown>;
	[key: string]: unknown;
}

/**
 * Factory for `~/queries/dashboard`. Defaults: undefined summary so the
 * pipeline pill renders the "No data" muted state.
 */
export function shellDashboardMock(
	overrides: ShellDashboardMockOverrides = {},
): Record<string, unknown> {
	return {
		useDashboardSummary: () => ({ data: undefined }),
		...overrides,
	};
}

export interface ShellDomainsMockOverrides {
	useDomainStats?: () => QueryStub<unknown>;
	useDomains?: () => QueryStub<unknown[]>;
	useAddDomain?: () => unknown;
	useRemoveDomain?: () => unknown;
	useRufRecords?: () => QueryStub<unknown>;
	useCatchallIntel?: () => QueryStub<unknown>;
	[key: string]: unknown;
}

/**
 * Factory for `~/queries/domains`. Defaults cover the Shell-consumed
 * `useDomainStats` hook. `useDomains` and `useRufRecords` are **not**
 * consumed by Shell directly — they're route-level concerns (home + domains-
 * list) — so they're omitted from the defaults. Tests that need them should
 * pass an override; tests that don't shouldn't have to think about them.
 *
 * `useAddDomain` and `useRemoveDomain` are domain-onboarding mutations (#181).
 * The defaults are no-op stubs so route tests that don't exercise the
 * add/remove flow don't need to configure them.
 */
export function shellDomainsMock(
	overrides: ShellDomainsMockOverrides = {},
): Record<string, unknown> {
	return {
		useDomainStats: () => ({ data: undefined, isLoading: false, isError: false }),
		useAddDomain: () => ({ mutateAsync: vi.fn(), isPending: false }),
		useRemoveDomain: () => ({ mutateAsync: vi.fn(), isPending: false }),
		useRufRecords: () => ({ data: undefined, isLoading: false, isError: false }),
		useCatchallIntel: () => ({ data: undefined, isLoading: false, isError: false }),
		...overrides,
	};
}

export interface ShellFoldersMockOverrides {
	useFolders?: () => QueryStub<unknown[]>;
	useCreateFolder?: () => unknown;
	useUpdateFolder?: () => unknown;
	useDeleteFolder?: () => unknown;
	[key: string]: unknown;
}

/**
 * Factory for `~/queries/folders`. Defaults: empty folder list (resolved,
 * not loading) so Shell renders without fetching. Pass `useFolders` override
 * per-test to exercise specific folder states.
 *
 * Shell uses `useFolders(mailboxId)` for the sidebar folder nav (#366).
 * Any test that renders Shell on a mailbox route must mock this module.
 */
export function shellFoldersMock(
	overrides: ShellFoldersMockOverrides = {},
): Record<string, unknown> {
	return {
		useFolders: () => ({ data: [] }),
		useCreateFolder: () => ({ mutateAsync: vi.fn(), isPending: false }),
		useUpdateFolder: () => ({ mutateAsync: vi.fn(), isPending: false }),
		useDeleteFolder: () => ({ mutateAsync: vi.fn(), isPending: false }),
		...overrides,
	};
}
