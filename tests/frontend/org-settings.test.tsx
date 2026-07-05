// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Org settings PUT is full-replace. The save handler must spread the
// persisted blob so UI-added domains and intel.feeds are not wiped when
// an operator saves unrelated fields from /settings.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

const mutateAsync = vi.fn();
const updateOrgMock = {
	mutateAsync,
	isPending: false,
};

let orgSettingsFixture: { settings: Record<string, unknown> } = { settings: {} };

vi.mock("~/queries/org-settings", () => ({
	useOrgSettings: () => ({ data: orgSettingsFixture, isLoading: false }),
	useUpdateOrgSettings: () => updateOrgMock,
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

vi.mock("~/components/SecuritySettingsPanel", () => ({
	SecuritySettingsPanel: () => null,
}));
vi.mock("~/components/HubSettingsPanel", () => ({
	HubSettingsPanel: () => null,
	normalizeHubConfig: () => undefined,
	validateHubConfig: () => null,
}));

import OrgSettingsRoute from "~/routes/org-settings";
import { renderWithProviders } from "./test-utils";

function renderOrgSettings() {
	return renderWithProviders(
		<Routes>
			<Route path="/settings" element={<OrgSettingsRoute />} />
		</Routes>,
		{ initialEntries: ["/settings"] },
	);
}

describe("OrgSettings · full-replace save preserves unrelated fields", () => {
	beforeEach(() => {
		mutateAsync.mockReset();
		mutateAsync.mockResolvedValue(undefined);
		orgSettingsFixture = { settings: {} };
	});

	it("preserves UI-added domains when saving unrelated org fields", async () => {
		const user = userEvent.setup();
		orgSettingsFixture = {
			settings: {
				domains: ["added.example", "seed.example"],
				agentModel: "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
			},
		};
		renderOrgSettings();

		await screen.findByRole("button", { name: /save changes/i });
		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));

		const payload = mutateAsync.mock.calls[0][0] as Record<string, unknown>;
		expect(payload.domains).toEqual(["added.example", "seed.example"]);
	});

	it("preserves intel.feeds when saving without a hub override", async () => {
		const user = userEvent.setup();
		orgSettingsFixture = {
			settings: {
				intel: {
					feeds: [{ id: "custom-feed", url: "https://feeds.example.com/list" }],
				},
			},
		};
		renderOrgSettings();

		await screen.findByRole("button", { name: /save changes/i });
		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));

		const payload = mutateAsync.mock.calls[0][0] as Record<string, unknown>;
		expect((payload.intel as { feeds: unknown[] }).feeds).toHaveLength(1);
	});
});
