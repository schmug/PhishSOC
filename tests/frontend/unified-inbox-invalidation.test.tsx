// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("~/services/api", async () => {
	const actual = await vi.importActual<typeof import("~/services/api")>("~/services/api");
	return {
		...actual,
		default: {
			...actual.default,
			deleteEmail: vi.fn().mockResolvedValue(undefined),
			updateEmail: vi.fn().mockResolvedValue(undefined),
			markThreadRead: vi.fn().mockResolvedValue(undefined),
		},
	};
});

import { useDeleteEmail, useMarkThreadRead, useUpdateEmail } from "~/queries/emails";

function setup() {
	const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
	const spy = vi.spyOn(qc, "invalidateQueries");
	const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
	return { spy, wrapper };
}

const invalidatedUnified = (spy: ReturnType<typeof vi.spyOn>) =>
	spy.mock.calls.some(([arg]) => JSON.stringify((arg as { queryKey?: unknown })?.queryKey) === JSON.stringify(["unified-inbox"]));

describe("email mutations refresh All inboxes", () => {
	it.each([
		["delete", () => useDeleteEmail(), { mailboxId: "ops@a.test", id: "e1" }],
		["update", () => useUpdateEmail(), { mailboxId: "ops@a.test", id: "e1", data: { read: true } }],
		["mark thread read", () => useMarkThreadRead(), { mailboxId: "ops@a.test", threadId: "t1" }],
	])("%s invalidates the unified-inbox query", async (_label, hook, vars) => {
		const { spy, wrapper } = setup();
		const { result } = renderHook(hook as () => { mutateAsync: (v: unknown) => Promise<unknown> }, { wrapper });
		await act(async () => {
			await result.current.mutateAsync(vars);
		});
		expect(invalidatedUnified(spy)).toBe(true);
	});
});
