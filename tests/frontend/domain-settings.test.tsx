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
let orgSettingsFixture: { settings: Record<string, unknown> } = { settings: {} };

vi.mock("~/queries/domain-settings", () => ({
	useDomainSettings: () => ({ data: domainSettingsFixture, isLoading: false }),
	useUpdateDomainSettings: () => updateDomainMock,
}));

vi.mock("~/queries/org-settings", () => ({
	useOrgSettings: () => ({ data: orgSettingsFixture, isLoading: false }),
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
		orgSettingsFixture = { settings: {} };
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

	it("preserves catchall_intel sub-fields when saving with enabled already true", async () => {
		const user = userEvent.setup();
		domainSettingsFixture = {
			domain: "acme.com",
			settings: {
				catchall_intel: { enabled: true, retention_days: 14, sample_limit: 25 },
			},
		};
		renderDomainSettings();

		await screen.findByRole("checkbox", { name: /enable catch-all probe capture/i });
		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));

		const payload = mutateAsync.mock.calls[0][0] as Record<string, unknown>;
		expect(payload.catchall_intel).toEqual({
			enabled: true,
			retention_days: 14,
			sample_limit: 25,
		});
	});

	it("preserves intel.feeds when saving without a hub override", async () => {
		const user = userEvent.setup();
		domainSettingsFixture = {
			domain: "acme.com",
			settings: {
				intel: {
					feeds: [{ id: "custom-feed", url: "https://feeds.example.com/list" }],
				},
			},
		};
		renderDomainSettings();

		await screen.findByRole("button", { name: /save changes/i });
		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));

		const payload = mutateAsync.mock.calls[0][0] as Record<string, unknown>;
		expect((payload.intel as { feeds: unknown[] }).feeds).toHaveLength(1);
	});

	it("does not persist security when inheriting org policy and the panel is untouched", async () => {
		const user = userEvent.setup();
		orgSettingsFixture = {
			settings: {
				security: { enabled: true, allowlist_domains: ["trusted.example"] },
			},
		};
		domainSettingsFixture = { domain: "acme.com", settings: {} };
		renderDomainSettings();

		await screen.findByTestId("security-inheritance-badge");
		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));

		const payload = mutateAsync.mock.calls[0][0] as Record<string, unknown>;
		expect(payload.security).toBeUndefined();
	});

	it("drops intel.hub on save after reset to inherited while preserving feeds", async () => {
		const user = userEvent.setup();
		orgSettingsFixture = {
			settings: {
				intel: {
					hub: {
						url: "https://org-hub.example",
						org_uuid: "11111111-2222-3333-4444-555555555555",
						api_key_secret_name: "org-key",
					},
				},
			},
		};
		domainSettingsFixture = {
			domain: "acme.com",
			settings: {
				intel: {
					hub: {
						url: "https://domain-hub.example",
						org_uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
						api_key_secret_name: "domain-key",
					},
					feeds: [{ id: "custom-feed", url: "https://feeds.example.com/list" }],
				},
			},
		};
		renderDomainSettings();

		await user.click(await screen.findByTestId("reset-hub"));
		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));

		const payload = mutateAsync.mock.calls[0][0] as Record<string, unknown>;
		const intel = payload.intel as { hub?: unknown; feeds?: unknown[] };
		expect(intel.hub).toBeUndefined();
		expect(intel.feeds).toHaveLength(1);
	});
});
