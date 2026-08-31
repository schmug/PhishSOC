// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Per-mailbox "New mail webhook" section (#694 UI) in `app/routes/settings.tsx`.
// The motivating case: route one mailbox to its own bot without clobbering the
// org-wide SOC channel.
//
// Covers the three-state contract end to end through the real PUT payload:
//   - inherit   → the `newEmailWebhook` key is OMITTED (not `{enabled:false}`)
//   - muted     → `{enabled:false}` is written and survives a reload, proving
//                 `stripDefaultEqual` did not eat it
//   - configured→ `{enabled:true, urlSecret}` is written
//   - a badly-prefixed secret name blocks the save
//
// Mock shape mirrors tests/frontend/settings-sidecar.test.tsx.

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

function makeMailbox(overrides: Record<string, unknown> = {}): Mailbox {
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

async function lastSavedSettings(): Promise<Record<string, unknown>> {
	await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));
	const payload = mutateAsync.mock.calls[0][0] as {
		mailboxId: string;
		settings: Record<string, unknown>;
	};
	return payload.settings;
}

const save = () => screen.getByRole("button", { name: /save changes/i });
const inheritRadio = () => screen.getByRole("radio", { name: /inherit/i });
const muteRadio = () => screen.getByRole("radio", { name: /mute/i });
const configuredRadio = () => screen.getByRole("radio", { name: /send to a webhook/i });
const secretInput = () => screen.getByLabelText(/webhook secret name/i);

describe("Settings · New mail webhook section (#694 UI)", () => {
	beforeEach(() => {
		mutateAsync.mockReset();
		mutateAsync.mockResolvedValue(undefined);
	});

	it("renders the section, defaulting to Inherit when nothing is saved", async () => {
		mailboxFixture = makeMailbox();
		renderSettings();

		expect(await screen.findByText(/new mail webhook/i)).toBeInTheDocument();
		expect(inheritRadio()).toBeChecked();
	});

	it("omits the newEmailWebhook key entirely when inheriting", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		await user.click(await save());

		const saved = await lastSavedSettings();
		expect("newEmailWebhook" in saved).toBe(false);
	});

	it("drops a previously saved block back to absent when switched to Inherit", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox({
			newEmailWebhook: { enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_BOT" },
		});
		renderSettings();

		await user.click(await screen.findByRole("radio", { name: /inherit/i }));
		await user.click(save());

		const saved = await lastSavedSettings();
		expect("newEmailWebhook" in saved).toBe(false);
	});

	it("persists {enabled:false} when muted — stripDefaultEqual must not eat it", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		await user.click(await screen.findByRole("radio", { name: /mute/i }));
		await user.click(save());

		const saved = await lastSavedSettings();
		expect(saved.newEmailWebhook).toEqual({ enabled: false });
	});

	it("re-renders a saved mute as muted after a reload", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		const { unmount } = renderSettings();

		await user.click(await screen.findByRole("radio", { name: /mute/i }));
		await user.click(save());
		const saved = await lastSavedSettings();
		unmount();

		// Reload: the server round-trips exactly what the PUT wrote.
		mailboxFixture = makeMailbox({ newEmailWebhook: saved.newEmailWebhook });
		renderSettings();

		expect(await screen.findByRole("radio", { name: /mute/i })).toBeChecked();
		expect(inheritRadio()).not.toBeChecked();
	});

	it("persists {enabled:true, urlSecret} when configured", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		await user.click(await screen.findByRole("radio", { name: /send to a webhook/i }));
		await user.clear(secretInput());
		await user.type(secretInput(), "NEW_EMAIL_WEBHOOK_OPSBOT");
		await user.click(save());

		const saved = await lastSavedSettings();
		expect(saved.newEmailWebhook).toEqual({
			enabled: true,
			urlSecret: "NEW_EMAIL_WEBHOOK_OPSBOT",
		});
	});

	it("restores a saved configured block into the form", async () => {
		mailboxFixture = makeMailbox({
			newEmailWebhook: { enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_EXISTING" },
		});
		renderSettings();

		expect(await screen.findByRole("radio", { name: /send to a webhook/i })).toBeChecked();
		expect(secretInput()).toHaveValue("NEW_EMAIL_WEBHOOK_EXISTING");
	});

	it("blocks the save when the secret name is missing the required prefix", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		renderSettings();

		await user.click(await screen.findByRole("radio", { name: /send to a webhook/i }));
		await user.clear(secretInput());
		await user.type(secretInput(), "HUB_API_KEY");
		await user.click(save());

		expect(mutateAsync).not.toHaveBeenCalled();
	});

	it("leaves unrelated settings untouched when the webhook block changes", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox({ fromName: "Ops Desk" });
		renderSettings();

		await user.click(await screen.findByRole("radio", { name: /mute/i }));
		await user.click(save());

		const saved = await lastSavedSettings();
		expect(saved.fromName).toBe("Ops Desk");
	});

	it("has no control that accepts a raw webhook URL", async () => {
		const user = userEvent.setup();
		mailboxFixture = makeMailbox();
		const { container } = renderSettings();

		await user.click(await screen.findByRole("radio", { name: /send to a webhook/i }));

		// The attachment-scanner endpoint field is the page's only type="url"
		// input and is hidden while that scanner is off — the webhook section
		// contributes none.
		expect(container.querySelectorAll('input[type="url"]')).toHaveLength(0);
	});
});
