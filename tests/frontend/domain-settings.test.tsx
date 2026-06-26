// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Tests for the domain-settings route's Catch-all intel toggle (#521).
// Covers: load persisted value → toggle → save merges catchall_intel into
// existing settings without wiping other fields.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

const mutateAsync = vi.fn();
const updateDomainMock = {
	mutateAsync,
	isPending: false,
};

let domainSettingsFixture: { domain: string; settings: Record<string, unknown> };

vi.mock("~/queries/domain-settings", () => ({
	useDomainSettings: () => ({ data: domainSettingsFixture, isLoading: false }),
	useUpdateDomainSettings: () => updateDomainMock,
}));

vi.mock("~/queries/text-models", () => ({
	useTextModels: () => ({ models: ["@cf/meta/llama-3.3-70b-instruct-fp8-fast"] }),
}));

// SecuritySettingsPanel and HubSettingsPanel are heavy — stub them so the
// test doesn't pull in their full dependency trees.
vi.mock("~/components/SecuritySettingsPanel", () => ({
	SecuritySettingsPanel: () => null,
}));
vi.mock("~/components/HubSettingsPanel", () => ({
	HubSettingsPanel: () => null,
	normalizeHubConfig: () => undefined,
	validateHubConfig: () => null,
}));

import DomainSettingsRoute from "~/routes/domain-settings";
import { renderWithProviders } from "./test-utils";

function renderDomainSettings(domain = "acme.com") {
	return renderWithProviders(
		<Routes>
			<Route path="/domains/:domain/settings" element={<DomainSettingsRoute />} />
		</Routes>,
		{ initialEntries: [`/domains/${encodeURIComponent(domain)}/settings`] },
	);
}

describe("DomainSettings · Catch-all intel toggle (#521)", () => {
	beforeEach(() => {
		mutateAsync.mockReset();
		mutateAsync.mockResolvedValue(undefined);
		domainSettingsFixture = { domain: "acme.com", settings: {} };
	});

	it("renders the catch-all intel toggle unchecked when setting is absent", async () => {
		domainSettingsFixture = { domain: "acme.com", settings: {} };
		renderDomainSettings();
		const toggle = await screen.findByRole("checkbox", {
			name: /enable catch-all probe capture/i,
		});
		expect(toggle).not.toBeChecked();
	});

	it("renders the toggle checked when catchall_intel.enabled is true on load", async () => {
		domainSettingsFixture = {
			domain: "acme.com",
			settings: { catchall_intel: { enabled: true } },
		};
		renderDomainSettings();
		const toggle = await screen.findByRole("checkbox", {
			name: /enable catch-all probe capture/i,
		});
		expect(toggle).toBeChecked();
	});

	it("includes catchall_intel in the save payload after toggling on", async () => {
		const user = userEvent.setup();
		domainSettingsFixture = {
			domain: "acme.com",
			settings: {
				autoDraft: { enabled: false },
				agentModel: "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
			},
		};
		renderDomainSettings();

		const toggle = await screen.findByRole("checkbox", {
			name: /enable catch-all probe capture/i,
		});
		expect(toggle).not.toBeChecked();
		await user.click(toggle);
		expect(toggle).toBeChecked();

		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));

		const payload = mutateAsync.mock.calls[0][0] as Record<string, unknown>;
		expect((payload.catchall_intel as { enabled: boolean }).enabled).toBe(true);
	});

	it("save merges catchall_intel into existing settings — other fields are preserved", async () => {
		const user = userEvent.setup();
		domainSettingsFixture = {
			domain: "acme.com",
			settings: {
				autoDraft: { enabled: false },
				agentModel: "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
			},
		};
		renderDomainSettings();

		const toggle = await screen.findByRole("checkbox", {
			name: /enable catch-all probe capture/i,
		});
		await user.click(toggle);

		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));

		const payload = mutateAsync.mock.calls[0][0] as Record<string, unknown>;
		// catchall_intel is now set
		expect(payload.catchall_intel).toEqual({ enabled: true });
		// autoDraft is preserved from the loaded settings
		expect(payload.autoDraft).toEqual({ enabled: false });
		// agentModel is preserved
		expect((payload.agentModel as string)).toBe("@cf/meta/llama-3.3-70b-instruct-fp8-fast");
	});

	it("omits catchall_intel from the payload when the toggle is never touched", async () => {
		const user = userEvent.setup();
		domainSettingsFixture = { domain: "acme.com", settings: {} };
		renderDomainSettings();

		await screen.findByRole("checkbox", { name: /enable catch-all probe capture/i });
		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));

		const payload = mutateAsync.mock.calls[0][0] as Record<string, unknown>;
		// Never interacted — absent-key-inherits semantics: don't send it
		expect(payload.catchall_intel).toBeUndefined();
	});
});
