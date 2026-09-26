// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// "Hide from All inboxes" toggle in the per-mailbox Account card.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import type { Mailbox } from "~/types";

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
	useDomainSettings: () => ({ data: { domain: "example.com", settings: {} }, isLoading: false }),
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

function fixture(settings: Record<string, unknown>): Mailbox {
	return { id: "m1", email: "ops@example.com", name: "Ops", settings } as unknown as Mailbox;
}

describe("Settings · Hide from All inboxes", () => {
	beforeEach(() => {
		mutateAsync.mockReset();
		mutateAsync.mockResolvedValue(undefined);
	});

	it("is off when the setting is absent", async () => {
		mailboxFixture = fixture({});
		renderSettings();
		expect(await screen.findByRole("switch", { name: /hide from all inboxes/i })).not.toBeChecked();
	});

	it("is on when saved as true", async () => {
		mailboxFixture = fixture({ hideFromAllInboxes: true });
		renderSettings();
		expect(await screen.findByRole("switch", { name: /hide from all inboxes/i })).toBeChecked();
	});

	it("saves true when switched on", async () => {
		mailboxFixture = fixture({});
		const user = userEvent.setup();
		renderSettings();
		await user.click(await screen.findByRole("switch", { name: /hide from all inboxes/i }));
		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));
		expect(mutateAsync.mock.calls[0][0].settings.hideFromAllInboxes).toBe(true);
	});

	it("drops the key when switched off", async () => {
		mailboxFixture = fixture({ hideFromAllInboxes: true });
		const user = userEvent.setup();
		renderSettings();
		await user.click(await screen.findByRole("switch", { name: /hide from all inboxes/i }));
		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));
		expect(mutateAsync.mock.calls[0][0].settings.hideFromAllInboxes).toBeUndefined();
	});
});
