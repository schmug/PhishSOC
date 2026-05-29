// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// #211: `OrgSettingsRoute` previously returned its body without `<Shell>`,
// so production navigation to `/settings` dropped the user out of the
// topbar/sidebar/breadcrumb chrome and lost the org-scope "Ask co-pilot"
// button mounted by the Shell-level fallback added in #198.
//
// This smoke test mounts the actual route component at `/settings` and
// asserts the topbar "Ask co-pilot" button is present — i.e. Shell is
// wrapping the route.

import { screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

vi.mock("~/queries/org-settings", () => ({
	useOrgSettings: () => ({ data: { settings: {} }, isLoading: false }),
	useUpdateOrgSettings: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));

vi.mock("~/queries/text-models", () => ({
	useTextModels: () => ({ models: ["@cf/meta/llama-3.3-70b-instruct-fp8-fast"] }),
}));

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({ data: undefined }),
	useMailboxes: () => ({ data: [] }),
}));

vi.mock("~/queries/dashboard", () => ({
	useDashboardSummary: () => ({ data: undefined, isLoading: false, isError: false }),
}));

vi.mock("~/queries/domains", () => ({
	useDomainStats: () => ({ data: undefined, isLoading: false, isError: false }),
}));

vi.mock("~/queries/org", () => ({
	useOrgOverview: () => ({ data: undefined, isLoading: false, isError: false }),
}));

vi.mock("~/queries/folders", () => ({
	useFolders: () => ({ data: [] }),
}));

import OrgSettingsRoute from "~/routes/org-settings";
import { renderWithProviders } from "./test-utils";

describe("OrgSettingsRoute (#211)", () => {
	it("mounts inside <Shell> so /settings exposes the org-scope co-pilot trigger", () => {
		renderWithProviders(
			<Routes>
				<Route path="/settings" element={<OrgSettingsRoute />} />
			</Routes>,
			{ initialEntries: ["/settings"] },
		);

		// Shell topbar's "Ask co-pilot" button is the marker that Shell wraps
		// the route. Without #211's fix, the route rendered raw and this
		// button did not exist on /settings.
		const trigger = screen.getByRole("button", { name: /ask co-?pilot/i });
		expect(trigger).not.toBeDisabled();
	});
});
