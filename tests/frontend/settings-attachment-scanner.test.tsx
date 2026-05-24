// Coverage for the per-mailbox "Attachment scanner" section (#258 / #256)
// in `app/routes/settings.tsx`. Verifies the yaramail sidecar toggle:
//   - off by default (no pre-populated URL)
//   - enabling shows the endpoint URL input
//   - disabling hides the endpoint URL input
//   - saving with toggle on includes yaramail_scanner in PUT payload
//   - saving with toggle off omits yaramail_scanner from PUT payload

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
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

function makeMailbox(overrides: Partial<MailboxSettings> = {}): Mailbox {
	return {
		id: "m1",
		email: "ops@example.com",
		name: "Ops",
		settings: {
			autoDraft: { enabled: true },
			agentModel: "@cf/moonshotai/kimi-k2.5",
			...overrides,
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

describe("Settings · Attachment scanner section (#258)", () => {
	beforeEach(() => {
		mutateAsync.mockReset();
		mutateAsync.mockResolvedValue(undefined);
	});

	it("renders the toggle off by default (no saved config)", async () => {
		mailboxFixture = makeMailbox();
		renderSettings();

		const toggle = await screen.findByRole("switch", {
			name: /enable attachment scanner/i,
		});
		expect(toggle).not.toBeChecked();
	});

	it("does not show the endpoint URL input when toggle is off", async () => {
		mailboxFixture = makeMailbox();
		renderSettings();

		await screen.findByRole("switch", { name: /enable attachment scanner/i });
		expect(screen.queryByLabelText(/sidecar endpoint url/i)).toBeNull();
	});

	it("shows the endpoint URL input when the toggle is enabled", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		const toggle = await screen.findByRole("switch", {
			name: /enable attachment scanner/i,
		});
		await user.click(toggle);

		expect(screen.getByLabelText(/sidecar endpoint url/i)).toBeInTheDocument();
	});

	it("hides the endpoint URL input when the toggle is disabled after being on", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		const toggle = await screen.findByRole("switch", {
			name: /enable attachment scanner/i,
		});
		// Enable then disable.
		await user.click(toggle);
		expect(screen.getByLabelText(/sidecar endpoint url/i)).toBeInTheDocument();
		await user.click(toggle);
		expect(screen.queryByLabelText(/sidecar endpoint url/i)).toBeNull();
	});

	it("includes yaramail_scanner in the PUT payload when toggle is on", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		const toggle = await screen.findByRole("switch", {
			name: /enable attachment scanner/i,
		});
		await user.click(toggle);

		const urlInput = screen.getByLabelText(/sidecar endpoint url/i);
		await user.type(urlInput, "https://yaramail.internal/scan");

		await user.click(screen.getByRole("button", { name: /save changes/i }));

		const saved = await lastSavedSettings();
		expect((saved as Record<string, unknown>).yaramail_scanner).toEqual({
			enabled: true,
			endpoint_url: "https://yaramail.internal/scan",
		});
	});

	it("omits yaramail_scanner from the PUT payload when toggle is off", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		await screen.findByRole("switch", { name: /enable attachment scanner/i });
		// Do NOT enable the toggle — leave it off.
		await user.click(screen.getByRole("button", { name: /save changes/i }));

		const saved = await lastSavedSettings();
		// undefined is dropped by JSON.stringify, consistent with absent-key semantics.
		expect((saved as Record<string, unknown>).yaramail_scanner).toBeUndefined();
	});

	it("restores saved config when mailbox has yaramail_scanner.enabled=true", async () => {
		mailboxFixture = makeMailbox({
			yaramail_scanner: { enabled: true, endpoint_url: "https://sidecar.example.com/scan" },
		} as Record<string, unknown>);
		renderSettings();

		const toggle = await screen.findByRole("switch", {
			name: /enable attachment scanner/i,
		});
		expect(toggle).toBeChecked();
		expect(screen.getByLabelText(/sidecar endpoint url/i)).toHaveValue(
			"https://sidecar.example.com/scan",
		);
	});
});
