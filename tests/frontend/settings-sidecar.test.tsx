// Coverage for the per-mailbox "Workspace sidecar" section (#31, Task 10)
// in `app/routes/settings.tsx` / `app/components/SidecarSettingsCard.tsx`.
// Mirrors tests/frontend/settings-attachment-scanner.test.tsx (the closest
// existing "card toggles a settings block" coverage). Verifies:
//   - not-configured state shows the "Configure sidecar" enable affordance
//   - configuring shows the form, with mode select disabled pre-first-save
//   - saving with a configured block includes `sidecar` in the PUT payload
//   - saving with no block omits the `sidecar` key from the PUT payload
//   - removing an existing saved config deletes the `sidecar` key on save
//   - the secret-name prefix validation disables the Test button

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import type { Mailbox, MailboxSettings } from "~/types";

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

vi.mock("~/queries/org-settings", () => ({
	useOrgSettings: () => ({ data: { settings: {} }, isLoading: false }),
}));

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

function makeMailbox(overrides: Partial<MailboxSettings> = {}, extra: Partial<Mailbox> = {}): Mailbox {
	return {
		id: "m1",
		email: "ops@example.com",
		name: "Ops",
		settings: {
			autoDraft: { enabled: true },
			agentModel: "@cf/moonshotai/kimi-k2.5",
			...overrides,
		} as MailboxSettings,
		...extra,
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

describe("Settings · Workspace sidecar section (#31)", () => {
	beforeEach(() => {
		mutateAsync.mockReset();
		mutateAsync.mockResolvedValue(undefined);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("shows the enable affordance when no sidecar block is saved", async () => {
		mailboxFixture = makeMailbox();
		renderSettings();

		expect(await screen.findByText(/workspace sidecar/i)).toBeInTheDocument();
		expect(
			screen.getByRole("button", { name: /configure sidecar/i }),
		).toBeInTheDocument();
		expect(screen.queryByLabelText(/service-account secret name/i)).toBeNull();
	});

	it("shows the form (with defaults) after clicking Configure sidecar", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		await user.click(await screen.findByRole("button", { name: /configure sidecar/i }));

		expect(screen.getByLabelText(/service-account secret name/i)).toBeInTheDocument();
		expect(screen.getByLabelText(/^mode$/i)).toBeInTheDocument();
	});

	it("disables the mode select before the first save (no saved config yet)", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		await user.click(await screen.findByRole("button", { name: /configure sidecar/i }));

		expect(screen.getByLabelText(/^mode$/i)).toBeDisabled();
	});

	it("enables the mode select once the mailbox already has a saved sidecar block", async () => {
		mailboxFixture = makeMailbox({
			sidecar: {
				provider: "workspace",
				credentials_secret_name: "SIDECAR_SECRET_x",
				mode: "observe",
				quarantine_behavior: "label-only",
				retention_days: 7,
			},
		} as Record<string, unknown>);
		renderSettings();

		expect(await screen.findByLabelText(/^mode$/i)).not.toBeDisabled();
	});

	it("disables the Test connection button while the secret name is invalid", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		await user.click(await screen.findByRole("button", { name: /configure sidecar/i }));

		// Default value is the bare prefix "SIDECAR_SECRET_" which IS a valid
		// prefix match, so clear it to something invalid to exercise the gate.
		const secretInput = screen.getByLabelText(/service-account secret name/i);
		await user.clear(secretInput);
		await user.type(secretInput, "not-a-valid-name");

		expect(screen.getByRole("button", { name: /test connection/i })).toBeDisabled();
	});

	it("includes the sidecar block in the PUT payload when configured", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		await user.click(await screen.findByRole("button", { name: /configure sidecar/i }));
		const secretInput = screen.getByLabelText(/service-account secret name/i);
		await user.clear(secretInput);
		await user.type(secretInput, "SIDECAR_SECRET_myorg");

		await user.click(screen.getByRole("button", { name: /save changes/i }));

		const saved = await lastSavedSettings();
		expect((saved as Record<string, unknown>).sidecar).toEqual({
			provider: "workspace",
			credentials_secret_name: "SIDECAR_SECRET_myorg",
			mode: "observe",
			quarantine_behavior: "label-only",
			retention_days: 7,
		});
	});

	it("omits the sidecar key from the PUT payload when never configured", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		await screen.findByRole("button", { name: /configure sidecar/i });
		await user.click(screen.getByRole("button", { name: /save changes/i }));

		const saved = await lastSavedSettings();
		expect("sidecar" in (saved as Record<string, unknown>)).toBe(false);
	});

	it("deletes the sidecar key (not just sets it undefined) when removed after being saved", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox({
			sidecar: {
				provider: "workspace",
				credentials_secret_name: "SIDECAR_SECRET_x",
				mode: "observe",
				quarantine_behavior: "label-only",
				retention_days: 7,
			},
		} as Record<string, unknown>);
		renderSettings();

		await user.click(await screen.findByRole("button", { name: /remove sidecar config/i }));
		await user.click(screen.getByRole("button", { name: /save changes/i }));

		const saved = await lastSavedSettings();
		expect("sidecar" in (saved as Record<string, unknown>)).toBe(false);
	});

	it("restores the saved sidecar config into the form on load", async () => {
		mailboxFixture = makeMailbox({
			sidecar: {
				provider: "workspace",
				credentials_secret_name: "SIDECAR_SECRET_existing",
				mode: "active",
				quarantine_behavior: "label-and-archive",
				retention_days: 30,
			},
		} as Record<string, unknown>);
		renderSettings();

		expect(await screen.findByLabelText(/service-account secret name/i)).toHaveValue(
			"SIDECAR_SECRET_existing",
		);
		expect(screen.getByLabelText(/^mode$/i)).toHaveValue("active");
	});

	it("renders a health status line when sidecar_health is present", async () => {
		mailboxFixture = makeMailbox(
			{
				sidecar: {
					provider: "workspace",
					credentials_secret_name: "SIDECAR_SECRET_x",
					mode: "observe",
					quarantine_behavior: "label-only",
					retention_days: 7,
				},
			} as Record<string, unknown>,
			{ sidecar_health: { healthy: false, last_poll_at: null, last_error: "token exchange failed" } },
		);
		renderSettings();

		expect(await screen.findByText(/token exchange failed/i)).toBeInTheDocument();
	});

	it("runs the connection test and shows the result", async () => {
		const user = userEvent.setup();
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ ok: true, emailAddress: "ops@example.com" }),
		} as Response);
		vi.stubGlobal("fetch", fetchMock);

		mailboxFixture = makeMailbox({
			sidecar: {
				provider: "workspace",
				credentials_secret_name: "SIDECAR_SECRET_x",
				mode: "observe",
				quarantine_behavior: "label-only",
				retention_days: 7,
			},
		} as Record<string, unknown>);
		renderSettings();

		await user.click(await screen.findByRole("button", { name: /test connection/i }));

		expect(await screen.findByText(/connected as ops@example\.com/i)).toBeInTheDocument();
		expect(fetchMock).toHaveBeenCalledWith(
			"/api/v1/mailboxes/m1/sidecar/test",
			expect.objectContaining({ method: "POST" }),
		);
	});
});
