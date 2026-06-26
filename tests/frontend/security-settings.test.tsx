// Coverage for the new attachment-policy + folder-policy controls in
// `app/components/SecuritySettingsPanel.tsx`. Drives them through the full
// settings save flow so we verify the merged settings payload that hits the
// PUT route, not just the local component state.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import type { Mailbox, MailboxSettings, SecuritySettings } from "~/types";

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

function makeMailbox(security: SecuritySettings = { enabled: true }): Mailbox {
	return {
		id: "m1",
		email: "ops@example.com",
		name: "Ops",
		settings: {
			autoDraft: { enabled: true },
			agentModel: "@cf/moonshotai/kimi-k2.5",
			security,
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

describe("SecuritySettingsPanel · attachment + folder controls", () => {
	beforeEach(() => {
		mutateAsync.mockReset();
		mutateAsync.mockResolvedValue(undefined);
	});

	it("persists a changed executable_action through the save mutation", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox({ enabled: true });
		renderSettings();

		// Open the collapsible attachment-filtering section.
		await user.click(await screen.findByText(/attachment filtering/i));

		const group = await screen.findByRole("radiogroup", { name: /executable files/i });
		await user.click(within(group).getByRole("radio", { name: /score/i }));

		await user.click(screen.getByRole("button", { name: /save changes/i }));

		const saved = await lastSavedSettings();
		expect(saved.security?.attachment_policy?.executable_action).toBe("score");
	});

	it("persists a custom blocklist extension list", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox({ enabled: true });
		renderSettings();

		await user.click(await screen.findByText(/attachment filtering/i));

		const input = await screen.findByLabelText(/custom blocklist/i);
		await user.clear(input);
		// Type one character at a time. The previous controlled-input pattern
		// would collapse partial entries before the next comma was reached
		// (typing `dmg, rtf, ace` produced a single `dmgrtface` entry); the
		// `<ListInput>` adopted from #95 holds the raw draft locally so each
		// keystroke survives. Typing here is the regression guard — pasting
		// would mask the bug because the parser sees the full string in one go.
		await user.type(input, "dmg, .rtf, ACE");

		await user.click(screen.getByRole("button", { name: /save changes/i }));

		const saved = await lastSavedSettings();
		// Lowercased + leading-dot stripped (matches the consumer's
		// normalisation in workers/security/settings.ts so the round-trip is
		// idempotent).
		expect(saved.security?.attachment_policy?.custom_blocklist_extensions).toEqual([
			"dmg",
			"rtf",
			"ace",
		]);
	});

	it("persists a folder skip_classifier toggle", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox({ enabled: true });
		renderSettings();

		await user.click(await screen.findByText(/folder rules/i));

		const archiveSkipClassifier = await screen.findByTestId("skip-classifier-archive");
		await user.click(archiveSkipClassifier);

		await user.click(screen.getByRole("button", { name: /save changes/i }));

		const saved = await lastSavedSettings();
		expect(saved.security?.folder_policies?.archive?.mode).toBe("skip_classifier");
	});

	it("persists a treat_as_verified toggle for a folder", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox({ enabled: true });
		renderSettings();

		await user.click(await screen.findByText(/folder rules/i));

		const inboxVerified = await screen.findByTestId("treat-verified-inbox");
		await user.click(inboxVerified);

		await user.click(screen.getByRole("button", { name: /save changes/i }));

		const saved = await lastSavedSettings();
		expect(saved.security?.folder_policies?.inbox?.treat_as_verified).toBe(true);
	});
});

describe("SecuritySettingsPanel · mitigations toggle", () => {
	beforeEach(() => {
		mutateAsync.mockReset();
		mutateAsync.mockResolvedValue(undefined);
	});

	it("defaults to checked (true) when mitigations key is absent", async () => {
		mailboxFixture = makeMailbox({ enabled: true });
		renderSettings();

		const toggle = await screen.findByRole("switch", {
			name: /DMARC=pass cancels per-method SPF\/DKIM fail contributions/i,
		});
		expect(toggle).toBeChecked();
	});

	it("reflects persisted false value when mitigations.dmarc_pass_compensates_method_fail is false", async () => {
		mailboxFixture = makeMailbox({
			enabled: true,
			mitigations: { dmarc_pass_compensates_method_fail: false },
		});
		renderSettings();

		const toggle = await screen.findByRole("switch", {
			name: /DMARC=pass cancels per-method SPF\/DKIM fail contributions/i,
		});
		expect(toggle).not.toBeChecked();
	});

	it("persists dmarc_pass_compensates_method_fail=false without clobbering other security fields", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox({
			enabled: true,
			ruf_ingestion: { enabled: true, retain_raw: false },
		});
		renderSettings();

		const toggle = await screen.findByRole("switch", {
			name: /DMARC=pass cancels per-method SPF\/DKIM fail contributions/i,
		});
		// Default is on (true when absent) — click once to turn it off.
		await user.click(toggle);

		await user.click(screen.getByRole("button", { name: /save changes/i }));

		const saved = await lastSavedSettings();
		expect(saved.security?.mitigations?.dmarc_pass_compensates_method_fail).toBe(false);
		// Sibling fields must survive the save.
		expect(saved.security?.ruf_ingestion?.enabled).toBe(true);
	});
});
