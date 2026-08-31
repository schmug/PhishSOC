// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Domain- and org-tier "New mail webhook" sections (#694 UI) in
// `app/routes/domain-settings.tsx` and `app/routes/org-settings.tsx`.
//
// Same three-state contract as the mailbox tier (see
// tests/frontend/settings-new-email-webhook.test.tsx): inherit omits the key,
// mute writes `{enabled:false}` and survives a reload, configured writes
// `{enabled:true, urlSecret}`. Both PUTs are full-replace, so the assertions
// also pin that an unrelated persisted key survives the save.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

const domainMutateAsync = vi.fn();
const orgMutateAsync = vi.fn();

let domainSettingsFixture: { domain: string; settings: Record<string, unknown> } = {
	domain: "acme.com",
	settings: {},
};
let orgSettingsFixture: { settings: Record<string, unknown> } = { settings: {} };

vi.mock("~/queries/domain-settings", () => ({
	useDomainSettings: () => ({ data: domainSettingsFixture, isLoading: false }),
	useUpdateDomainSettings: () => ({ mutateAsync: domainMutateAsync, isPending: false }),
}));

vi.mock("~/queries/org-settings", () => ({
	useOrgSettings: () => ({ data: orgSettingsFixture, isLoading: false }),
	useUpdateOrgSettings: () => ({ mutateAsync: orgMutateAsync, isPending: false }),
}));

vi.mock("~/queries/text-models", () => ({
	useTextModels: () => ({ models: ["@cf/meta/llama-3.3-70b-instruct-fp8-fast"] }),
}));

// Shell fan-out — see tests/frontend/shell-mocks.ts for why every one of
// these must be stubbed when a route element renders Shell.
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

import DomainSettingsRoute from "~/routes/domain-settings";
import OrgSettingsRoute from "~/routes/org-settings";
import { renderWithProviders } from "./test-utils";

const save = () => screen.getByRole("button", { name: /save changes/i });
const inheritRadio = () => screen.getByRole("radio", { name: /inherit/i });
const muteRadio = () => screen.getByRole("radio", { name: /mute/i });
const configuredRadio = () => screen.getByRole("radio", { name: /send to a webhook/i });
const secretInput = () => screen.getByLabelText(/webhook secret name/i);

function renderDomainSettings() {
	return renderWithProviders(
		<Routes>
			<Route path="/domains/:domain/settings" element={<DomainSettingsRoute />} />
		</Routes>,
		{ initialEntries: ["/domains/acme.com/settings"] },
	);
}

function renderOrgSettings() {
	return renderWithProviders(
		<Routes>
			<Route path="/settings" element={<OrgSettingsRoute />} />
		</Routes>,
		{ initialEntries: ["/settings"] },
	);
}

async function lastCall(mock: typeof domainMutateAsync): Promise<Record<string, unknown>> {
	await waitFor(() => expect(mock).toHaveBeenCalledTimes(1));
	return mock.mock.calls[0][0] as Record<string, unknown>;
}

describe("DomainSettings · New mail webhook section (#694 UI)", () => {
	beforeEach(() => {
		domainMutateAsync.mockReset();
		domainMutateAsync.mockResolvedValue(undefined);
		domainSettingsFixture = { domain: "acme.com", settings: {} };
	});

	it("renders the section, defaulting to Inherit", async () => {
		renderDomainSettings();

		expect(await screen.findByText(/new mail webhook/i)).toBeInTheDocument();
		expect(inheritRadio()).toBeChecked();
	});

	it("omits the newEmailWebhook key when inheriting", async () => {
		const user = userEvent.setup();
		renderDomainSettings();

		await user.click(await save());

		const saved = await lastCall(domainMutateAsync);
		expect("newEmailWebhook" in saved).toBe(false);
	});

	it("drops a previously saved block back to absent when switched to Inherit", async () => {
		const user = userEvent.setup();
		domainSettingsFixture = {
			domain: "acme.com",
			settings: { newEmailWebhook: { enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_D" } },
		};
		renderDomainSettings();

		await user.click(await screen.findByRole("radio", { name: /inherit/i }));
		await user.click(save());

		const saved = await lastCall(domainMutateAsync);
		expect("newEmailWebhook" in saved).toBe(false);
	});

	it("persists {enabled:false} when muted", async () => {
		const user = userEvent.setup();
		renderDomainSettings();

		await user.click(await screen.findByRole("radio", { name: /mute/i }));
		await user.click(save());

		const saved = await lastCall(domainMutateAsync);
		expect(saved.newEmailWebhook).toEqual({ enabled: false });
	});

	it("re-renders a saved mute as muted after a reload", async () => {
		const user = userEvent.setup();
		const { unmount } = renderDomainSettings();

		await user.click(await screen.findByRole("radio", { name: /mute/i }));
		await user.click(save());
		const saved = await lastCall(domainMutateAsync);
		unmount();

		domainSettingsFixture = { domain: "acme.com", settings: saved };
		renderDomainSettings();

		expect(await screen.findByRole("radio", { name: /mute/i })).toBeChecked();
	});

	it("persists {enabled:true, urlSecret} when configured, preserving other keys", async () => {
		const user = userEvent.setup();
		domainSettingsFixture = {
			domain: "acme.com",
			settings: { intel: { feeds: [{ id: "f1" }] } },
		};
		renderDomainSettings();

		await user.click(await screen.findByRole("radio", { name: /send to a webhook/i }));
		await user.clear(secretInput());
		await user.type(secretInput(), "NEW_EMAIL_WEBHOOK_ACME");
		await user.click(save());

		const saved = await lastCall(domainMutateAsync);
		expect(saved.newEmailWebhook).toEqual({
			enabled: true,
			urlSecret: "NEW_EMAIL_WEBHOOK_ACME",
		});
		expect(saved.intel).toEqual({ feeds: [{ id: "f1" }] });
	});

	it("blocks the save when the secret name is missing the required prefix", async () => {
		const user = userEvent.setup();
		renderDomainSettings();

		await user.click(await screen.findByRole("radio", { name: /send to a webhook/i }));
		await user.clear(secretInput());
		await user.type(secretInput(), "RELAY_CREDS_ACME");
		await user.click(save());

		expect(domainMutateAsync).not.toHaveBeenCalled();
	});
});

describe("OrgSettings · New mail webhook section (#694 UI)", () => {
	beforeEach(() => {
		orgMutateAsync.mockReset();
		orgMutateAsync.mockResolvedValue(undefined);
		orgSettingsFixture = { settings: {} };
	});

	it("renders the section, defaulting to Inherit", async () => {
		renderOrgSettings();

		expect(await screen.findByText(/new mail webhook/i)).toBeInTheDocument();
		expect(inheritRadio()).toBeChecked();
	});

	it("omits the newEmailWebhook key when inheriting", async () => {
		const user = userEvent.setup();
		renderOrgSettings();

		await user.click(await save());

		const saved = await lastCall(orgMutateAsync);
		expect("newEmailWebhook" in saved).toBe(false);
	});

	it("persists {enabled:false} when muted", async () => {
		const user = userEvent.setup();
		renderOrgSettings();

		await user.click(await screen.findByRole("radio", { name: /mute/i }));
		await user.click(save());

		const saved = await lastCall(orgMutateAsync);
		expect(saved.newEmailWebhook).toEqual({ enabled: false });
	});

	it("re-renders a saved mute as muted after a reload", async () => {
		const user = userEvent.setup();
		const { unmount } = renderOrgSettings();

		await user.click(await screen.findByRole("radio", { name: /mute/i }));
		await user.click(save());
		const saved = await lastCall(orgMutateAsync);
		unmount();

		orgSettingsFixture = { settings: saved };
		renderOrgSettings();

		expect(await screen.findByRole("radio", { name: /mute/i })).toBeChecked();
	});

	it("persists {enabled:true, urlSecret} when configured, preserving org domains", async () => {
		const user = userEvent.setup();
		orgSettingsFixture = { settings: { domains: ["acme.com"] } };
		renderOrgSettings();

		await user.click(await screen.findByRole("radio", { name: /send to a webhook/i }));
		await user.clear(secretInput());
		await user.type(secretInput(), "NEW_EMAIL_WEBHOOK_SOC");
		await user.click(save());

		const saved = await lastCall(orgMutateAsync);
		expect(saved.newEmailWebhook).toEqual({
			enabled: true,
			urlSecret: "NEW_EMAIL_WEBHOOK_SOC",
		});
		expect(saved.domains).toEqual(["acme.com"]);
	});

	it("blocks the save when the secret name is missing the required prefix", async () => {
		const user = userEvent.setup();
		renderOrgSettings();

		await user.click(await screen.findByRole("radio", { name: /send to a webhook/i }));
		await user.clear(secretInput());
		await user.type(secretInput(), "nope");
		await user.click(save());

		expect(orgMutateAsync).not.toHaveBeenCalled();
	});
});
