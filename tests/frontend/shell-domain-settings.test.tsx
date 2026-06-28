// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// #547: `DomainSettingsRoute` previously returned its body without `<Shell>`,
// so navigation to `/domains/:domain/settings` dropped the user out of the
// topbar / sidebar / breadcrumb chrome and lost the "Ask co-pilot" button.
//
// This smoke test mounts the actual route at `/domains/acme.com/settings` and
// asserts Shell chrome is present — i.e. `<Shell>` now wraps the route.

import { screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

vi.mock("~/queries/domain-settings", () => ({
	useDomainSettings: () => ({ data: { settings: {} }, isLoading: false }),
	useUpdateDomainSettings: () => ({ mutateAsync: vi.fn(), isPending: false }),
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

vi.mock("~/queries/folders", () => ({
	useFolders: () => ({ data: [] }),
}));

import DomainSettingsRoute from "~/routes/domain-settings";
import { renderWithProviders } from "./test-utils";

describe("DomainSettingsRoute (#547)", () => {
	it("mounts inside <Shell> so /domains/:domain/settings exposes the co-pilot trigger", () => {
		renderWithProviders(
			<Routes>
				<Route
					path="/domains/:domain/settings"
					element={<DomainSettingsRoute />}
				/>
			</Routes>,
			{ initialEntries: ["/domains/acme.com/settings"] },
		);

		// Shell topbar's "Ask co-pilot" button is the marker that Shell wraps
		// the route. Without #547's fix this button was absent on the settings page.
		const trigger = screen.getByRole("button", { name: /ask co-?pilot/i });
		expect(trigger).not.toBeDisabled();
	});

	it("renders the domain settings heading for the matched domain", () => {
		renderWithProviders(
			<Routes>
				<Route
					path="/domains/:domain/settings"
					element={<DomainSettingsRoute />}
				/>
			</Routes>,
			{ initialEntries: ["/domains/acme.com/settings"] },
		);

		expect(
			screen.getByRole("heading", { name: /domain settings.*acme\.com/i }),
		).toBeInTheDocument();
	});
});
