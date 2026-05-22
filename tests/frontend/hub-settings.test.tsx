// Coverage for the new HubSettingsPanel (#97). Drives the form through
// the full settings save flow so we verify the merged settings payload
// that hits the PUT route, not just local component state.
//
// Mirrors `security-settings.test.tsx` — same mocking pattern for
// useMailbox / useUpdateMailbox so the assertions are about what gets
// persisted, not internal React state.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import type { HubConfigSettings, Mailbox, MailboxSettings } from "~/types";
import {
	normalizeHubConfig,
	validateHubConfig,
} from "~/components/HubSettingsPanel";

const mutateAsync = vi.fn();
const updateMailboxMock = {
	mutateAsync,
	isPending: false,
} as unknown as ReturnType<typeof import("~/queries/mailboxes").useUpdateMailbox>;

let mailboxFixture: Mailbox;

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({ data: mailboxFixture }),
	useUpdateMailbox: () => updateMailboxMock,
	useLockDownMailbox: () => ({ mutate: vi.fn(), isPending: false, isError: false }),
	useMailboxAcl: () => ({ data: undefined, isLoading: true }),
	useAddAclMember: () => ({ mutateAsync: vi.fn(), isPending: false }),
	useRemoveAclMember: () => ({ mutateAsync: vi.fn(), isPending: false }),
	useTransferAclOwnership: () => ({ mutateAsync: vi.fn(), isPending: false }),
	useAddAclGroup: () => ({ mutateAsync: vi.fn(), isPending: false }),
	useRemoveAclGroup: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));

// Per-mailbox settings page now also reads org settings to drive the
// inheritance affordance landed in PR #152. Returning an empty resolved
// blob keeps the form in "no org overrides" mode, so existing assertions
// about per-mailbox state survive unchanged.
vi.mock("~/queries/org-settings", () => ({
	useOrgSettings: () => ({ data: { settings: {} }, isLoading: false }),
}));

// Per-mailbox settings page also reads domain settings (#142). Returning
// an empty resolved blob keeps the form in "no domain overrides" mode so
// existing per-mailbox assertions hold.
vi.mock("~/queries/domain-settings", () => ({
	useDomainSettings: () => ({
		data: { domain: "example.com", settings: {} },
		isLoading: false,
	}),
}));

import SettingsRoute from "~/routes/settings";
import { renderWithProviders } from "./test-utils";

function renderSettings() {
	return renderWithProviders(
		<Routes>
			<Route path="/mailbox/:mailboxId/settings" element={<SettingsRoute />} />
		</Routes>,
		{ initialEntries: ["/mailbox/m1/settings"] },
	);
}

function makeMailbox(hub?: HubConfigSettings): Mailbox {
	return {
		id: "m1",
		email: "ops@example.com",
		name: "Ops",
		settings: {
			autoDraft: { enabled: true },
			agentModel: "@cf/moonshotai/kimi-k2.5",
			intel: hub ? { hub } : undefined,
		} as MailboxSettings,
	} as unknown as Mailbox;
}

async function lastSavedSettings(): Promise<MailboxSettings> {
	await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));
	const payload = mutateAsync.mock.calls[0][0] as {
		mailboxId: string;
		settings: MailboxSettings;
	};
	return payload.settings;
}

const VALID_ORG_UUID = "11111111-2222-3333-4444-555555555555";
const VALID_SHARING_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

describe("HubSettingsPanel · pure helpers", () => {
	it("validateHubConfig accepts a fully empty config (returns null)", () => {
		expect(validateHubConfig(undefined)).toBeNull();
		expect(validateHubConfig({})).toBeNull();
		expect(
			validateHubConfig({ url: "", org_uuid: "", api_key_secret_name: "" }),
		).toBeNull();
	});

	it("validateHubConfig requires all three core fields when any is set", () => {
		const errs = validateHubConfig({ url: "https://misp.example.org" });
		expect(errs).not.toBeNull();
		expect(errs?.org_uuid).toBeTruthy();
		expect(errs?.api_key_secret_name).toBeTruthy();
	});

	it("validateHubConfig rejects an invalid URL", () => {
		const errs = validateHubConfig({
			url: "not a url",
			org_uuid: VALID_ORG_UUID,
			api_key_secret_name: "HUB_KEY",
		});
		expect(errs?.url).toMatch(/valid http/i);
	});

	it("validateHubConfig rejects a non-UUID org_uuid", () => {
		const errs = validateHubConfig({
			url: "https://misp.example.org",
			org_uuid: "not-a-uuid",
			api_key_secret_name: "HUB_KEY",
		});
		expect(errs?.org_uuid).toMatch(/UUID/);
	});

	it("validateHubConfig accepts a fully valid config", () => {
		expect(
			validateHubConfig({
				url: "https://misp.example.org",
				org_uuid: VALID_ORG_UUID,
				api_key_secret_name: "HUB_KEY",
			}),
		).toBeNull();
	});

	it("normalizeHubConfig returns undefined for an empty config", () => {
		expect(normalizeHubConfig(undefined)).toBeUndefined();
		expect(normalizeHubConfig({})).toBeUndefined();
		expect(
			normalizeHubConfig({ url: "", org_uuid: "", api_key_secret_name: "" }),
		).toBeUndefined();
	});

	it("normalizeHubConfig trims whitespace and drops empty optionals", () => {
		const out = normalizeHubConfig({
			url: "  https://misp.example.org  ",
			org_uuid: ` ${VALID_ORG_UUID} `,
			api_key_secret_name: " HUB_KEY ",
			default_sharing_group_uuid: "  ",
			auto_report: false,
		});
		expect(out).toEqual({
			url: "https://misp.example.org",
			org_uuid: VALID_ORG_UUID,
			api_key_secret_name: "HUB_KEY",
		});
	});
});

describe("HubSettingsPanel · save flow", () => {
	beforeEach(() => {
		mutateAsync.mockReset();
		mutateAsync.mockResolvedValue(undefined);
	});

	it("does not persist intel.hub when the form is left empty", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox(); // no hub
		renderSettings();

		// No hub fields touched. Save should succeed and the saved payload
		// must NOT contain `intel.hub` — that's the regression guard for
		// "we wrote `{}` to R2".
		await user.click(await screen.findByRole("button", { name: /save changes/i }));

		const saved = await lastSavedSettings();
		expect(saved.intel).toBeUndefined();
	});

	it("round-trips a valid hub config through the save mutation", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox(); // start empty
		renderSettings();

		await user.type(await screen.findByLabelText(/hub url/i), "https://misp.example.org");
		await user.type(screen.getByLabelText(/organization uuid/i), VALID_ORG_UUID);
		await user.type(screen.getByLabelText(/worker secret name/i), "HUB_KEY");
		await user.type(
			screen.getByLabelText(/default sharing group uuid/i),
			VALID_SHARING_UUID,
		);

		await user.click(screen.getByRole("button", { name: /save changes/i }));

		const saved = await lastSavedSettings();
		expect(saved.intel?.hub).toEqual({
			url: "https://misp.example.org",
			org_uuid: VALID_ORG_UUID,
			api_key_secret_name: "HUB_KEY",
			default_sharing_group_uuid: VALID_SHARING_UUID,
		});
	});

	it("toggling auto_report persists when paired with the required core fields", async () => {
		const user = userEvent.setup();
		// Pre-seed the core fields so toggling auto_report alone is a valid
		// save (the backend requires url/org/secret to be set).
		mailboxFixture = makeMailbox({
			url: "https://misp.example.org",
			org_uuid: VALID_ORG_UUID,
			api_key_secret_name: "HUB_KEY",
		});
		renderSettings();

		const toggle = await screen.findByRole("switch", {
			name: /auto-report confirmed phishing/i,
		});
		await user.click(toggle);

		await user.click(screen.getByRole("button", { name: /save changes/i }));

		const saved = await lastSavedSettings();
		expect(saved.intel?.hub?.auto_report).toBe(true);
		expect(saved.intel?.hub?.url).toBe("https://misp.example.org");
	});

	it("surfaces inline validation for an invalid URL and refuses to save", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		await user.type(await screen.findByLabelText(/hub url/i), "not a url");
		await user.type(screen.getByLabelText(/organization uuid/i), VALID_ORG_UUID);
		await user.type(screen.getByLabelText(/worker secret name/i), "HUB_KEY");

		await user.click(screen.getByRole("button", { name: /save changes/i }));

		// Inline error is surfaced near the URL field…
		expect(await screen.findByText(/must be a valid http/i)).toBeInTheDocument();
		// …and the save mutation never fired.
		expect(mutateAsync).not.toHaveBeenCalled();
	});
});
