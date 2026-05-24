// Behavior card from `app/routes/settings.tsx` — verifies the auto-draft
// toggle and agent-model picker render the saved settings, persist user
// edits via the update mutation, and surface validation errors via toasts.
// Also covers the per-mailbox inheritance affordance landed in PR #152.

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
let orgSettingsFixture: { settings: Record<string, unknown> } = { settings: {} };
let domainSettingsFixture: { domain: string; settings: Record<string, unknown> } = {
	domain: "example.com",
	settings: {},
};

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
	useOrgSettings: () => ({ data: orgSettingsFixture, isLoading: false }),
}));

vi.mock("~/queries/domain-settings", () => ({
	useDomainSettings: () => ({ data: domainSettingsFixture, isLoading: false }),
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

describe("Settings · Behavior card", () => {
	beforeEach(() => {
		mutateAsync.mockReset();
		mutateAsync.mockResolvedValue(undefined);
		orgSettingsFixture = { settings: {} };
		mailboxFixture = {
			id: "m1",
			email: "ops@example.com",
			name: "Ops",
			settings: {
				autoDraft: { enabled: true },
				agentModel: "@cf/moonshotai/kimi-k2.5",
			},
		} as unknown as Mailbox;
	});

	it("renders auto-draft toggle reflecting the saved value", async () => {
		renderSettings();
		const toggle = await screen.findByRole("checkbox", { name: /auto-draft replies/i });
		expect(toggle).toBeChecked();
	});

	it("persists auto-draft off and the chosen model on save", async () => {
		const user = userEvent.setup();
		renderSettings();

		const toggle = await screen.findByRole("checkbox", { name: /auto-draft replies/i });
		await user.click(toggle);

		const select = screen.getByLabelText(/agent model/i);
		await user.selectOptions(select, "@cf/meta/llama-3.3-70b-instruct-fp8-fast");

		await user.click(screen.getByRole("button", { name: /save changes/i }));

		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));
		const payload = mutateAsync.mock.calls[0][0] as {
			mailboxId: string;
			settings: { autoDraft: { enabled: boolean }; agentModel: string };
		};
		expect(payload.mailboxId).toBe("m1");
		expect(payload.settings.autoDraft).toEqual({ enabled: false });
		expect(payload.settings.agentModel).toBe(
			"@cf/meta/llama-3.3-70b-instruct-fp8-fast",
		);
	});

	it("surfaces an error toast when a custom model is empty", async () => {
		const user = userEvent.setup();
		renderSettings();

		await user.selectOptions(
			await screen.findByLabelText(/agent model/i),
			"__custom__",
		);
		await user.click(screen.getByRole("button", { name: /save changes/i }));

		expect(await screen.findByText(/custom model cannot be empty/i)).toBeInTheDocument();
		expect(mutateAsync).not.toHaveBeenCalled();
	});

	it("surfaces an error toast when a custom model is missing the @cf/ prefix", async () => {
		const user = userEvent.setup();
		renderSettings();

		await user.selectOptions(
			await screen.findByLabelText(/agent model/i),
			"__custom__",
		);
		const customInput = await screen.findByPlaceholderText("@cf/your/model");
		await user.type(customInput, "not-a-cf-model");
		await user.click(screen.getByRole("button", { name: /save changes/i }));

		expect(await screen.findByText(/must start with @cf\//i)).toBeInTheDocument();
		expect(mutateAsync).not.toHaveBeenCalled();
	});
});

describe("Settings · per-mailbox inheritance affordance (#106)", () => {
	beforeEach(() => {
		mutateAsync.mockReset();
		mutateAsync.mockResolvedValue(undefined);
		// Default to no domain overrides; individual tests set as needed.
		domainSettingsFixture = { domain: "example.com", settings: {} };
	});

	it("renders 'Inherited from org' for fields the mailbox does not set", async () => {
		// Mailbox has NO autoDraft, NO agentModel, NO security, NO intel.hub —
		// only the per-mailbox identity field. The org tier supplies values.
		mailboxFixture = {
			id: "m1",
			email: "ops@example.com",
			name: "Ops",
			settings: { fromName: "Ops" },
		} as unknown as Mailbox;
		orgSettingsFixture = {
			settings: {
				agentSystemPrompt: "Be terse.",
				agentModel: "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
				autoDraft: { enabled: false },
			},
		};

		renderSettings();
		const inheritedBadges = await screen.findAllByTestId("inherited-badge");
		// Five inheritable surfaces: prompt, autoDraft, agentModel, security,
		// intel.hub. All inherited because mailbox tier is empty.
		expect(inheritedBadges.length).toBe(5);
		// Reset buttons should NOT render when nothing is overridden.
		expect(screen.queryByTestId("reset-prompt")).toBeNull();
		expect(screen.queryByTestId("reset-model")).toBeNull();
	});

	it("promotes a field to override when the user edits it, and a save omits other fields", async () => {
		mailboxFixture = {
			id: "m1",
			email: "ops@example.com",
			name: "Ops",
			settings: { fromName: "Ops" },
		} as unknown as Mailbox;
		orgSettingsFixture = {
			settings: {
				agentModel: "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
				autoDraft: { enabled: true },
			},
		};

		const user = userEvent.setup();
		renderSettings();
		// Edit only the auto-draft toggle. Everything else must continue to
		// inherit, so the PUT payload sends `undefined` for them — which the
		// worker's stripDefaultEqual then drops, preserving the inheritance
		// chain for the next read.
		const toggle = await screen.findByRole("checkbox", { name: /auto-draft replies/i });
		await user.click(toggle);

		await user.click(screen.getByRole("button", { name: /save changes/i }));

		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));
		const payload = mutateAsync.mock.calls[0][0] as {
			settings: Record<string, unknown>;
		};
		expect(payload.settings.autoDraft).toEqual({ enabled: false });
		expect(payload.settings.agentSystemPrompt).toBeUndefined();
		expect(payload.settings.agentModel).toBeUndefined();
		expect(payload.settings.security).toBeUndefined();
	});

	it("PUT payload omits inherited keys on the wire (JSON.stringify drops undefined values)", async () => {
		// Regression guard: the save handler builds the settings object with
		// `key: override ? value : undefined` for every inheritable field.
		// JSON.stringify drops undefined values, so the on-the-wire payload
		// has no key at all for inherited fields — which is what the worker's
		// stripDefaultEqual + the resolver's absent-key-inherits semantics
		// rely on. A future "improvement" that replaces undefined with null
		// would silently break the inheritance chain (null IS sent and
		// deserialises as an explicit null mailbox value).
		mailboxFixture = {
			id: "m1",
			email: "ops@example.com",
			name: "Ops",
			settings: { fromName: "Ops" },
		} as unknown as Mailbox;
		orgSettingsFixture = { settings: { agentModel: "@cf/org/value" } };

		const user = userEvent.setup();
		renderSettings();
		await user.click(await screen.findByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));
		const settings = (mutateAsync.mock.calls[0][0] as { settings: Record<string, unknown> }).settings;
		const wire = JSON.parse(JSON.stringify(settings)) as Record<string, unknown>;
		expect(Object.keys(wire)).not.toContain("agentSystemPrompt");
		expect(Object.keys(wire)).not.toContain("agentModel");
		expect(Object.keys(wire)).not.toContain("autoDraft");
		expect(Object.keys(wire)).not.toContain("security");
	});

	it("'Reset to inherited' on the prompt clears the override and re-renders the inherited badge", async () => {
		mailboxFixture = {
			id: "m1",
			email: "ops@example.com",
			name: "Ops",
			settings: {
				agentSystemPrompt: "mailbox-specific voice",
			},
		} as unknown as Mailbox;
		orgSettingsFixture = {
			settings: { agentSystemPrompt: "org default voice" },
		};

		const user = userEvent.setup();
		renderSettings();
		// Initial state: prompt is the only override; the other four
		// inheritable surfaces (autoDraft, agentModel, security, intel.hub)
		// are inherited because the mailbox fixture only sets the prompt.
		await screen.findByTestId("reset-prompt");
		expect(screen.getAllByTestId("override-badge")).toHaveLength(1);
		expect(screen.getAllByTestId("inherited-badge")).toHaveLength(4);

		await user.click(screen.getByTestId("reset-prompt"));

		// After reset: every inheritable surface inherits → 5 inherited
		// badges, 0 overrides, reset-prompt button is hidden.
		await waitFor(() => {
			expect(screen.queryAllByTestId("override-badge")).toHaveLength(0);
		});
		expect(screen.getAllByTestId("inherited-badge")).toHaveLength(5);
		expect(screen.queryByTestId("reset-prompt")).toBeNull();

		// Save and confirm the prompt field is omitted from the PUT payload.
		await user.click(screen.getByRole("button", { name: /save changes/i }));
		await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1));
		const payload = mutateAsync.mock.calls[0][0] as {
			settings: Record<string, unknown>;
		};
		expect(payload.settings.agentSystemPrompt).toBeUndefined();
	});
});

describe("Settings · per-mailbox inheritance composition with domain tier (#142)", () => {
	beforeEach(() => {
		mutateAsync.mockReset();
		mutateAsync.mockResolvedValue(undefined);
	});

	it("renders 'Inherited from domain' when the domain tier supplies the value", async () => {
		// Mailbox sets nothing; domain sets the prompt; org has its own.
		// Domain wins over org per the resolver chain — the badge must say
		// "Inherited from domain", not "Inherited from org".
		mailboxFixture = {
			id: "user@example.com",
			email: "user@example.com",
			name: "User",
			settings: {},
		} as unknown as Mailbox;
		orgSettingsFixture = { settings: { agentSystemPrompt: "org voice" } };
		domainSettingsFixture = {
			domain: "example.com",
			settings: { agentSystemPrompt: "domain voice" },
		};

		renderWithProviders(
			<Routes>
				<Route path="/mailbox/:mailboxId/settings" element={<SettingsRoute />} />
			</Routes>,
			{ initialEntries: ["/mailbox/user@example.com/settings"] },
		);

		// At least one "Inherited from domain" badge should render — the
		// prompt picks up the domain value (not the org value).
		const domainBadges = await screen.findAllByTestId("inherited-domain-badge");
		expect(domainBadges.length).toBeGreaterThanOrEqual(1);
	});

	it("falls back to 'Inherited from org' when neither mailbox nor domain set a field", async () => {
		mailboxFixture = {
			id: "user@example.com",
			email: "user@example.com",
			name: "User",
			settings: {},
		} as unknown as Mailbox;
		orgSettingsFixture = { settings: { agentSystemPrompt: "org voice" } };
		domainSettingsFixture = { domain: "example.com", settings: {} };

		renderWithProviders(
			<Routes>
				<Route path="/mailbox/:mailboxId/settings" element={<SettingsRoute />} />
			</Routes>,
			{ initialEntries: ["/mailbox/user@example.com/settings"] },
		);

		// No "Inherited from domain" badges at all (domain has nothing) →
		// every inheritable surface shows "Inherited from org".
		await screen.findAllByTestId("inherited-badge");
		expect(screen.queryAllByTestId("inherited-domain-badge")).toHaveLength(0);
	});
});
