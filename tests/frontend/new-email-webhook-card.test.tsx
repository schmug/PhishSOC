// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Unit coverage for the shared `NewEmailWebhookCard`
// (`app/components/NewEmailWebhookCard.tsx`), the settings control for the
// per-tier new-mail webhook shipped in #694.
//
// The block is deliberately THREE-state, unlike every other settings toggle:
//
//   inherit    key absent      fall through to the next tier, else the global
//                              NEW_EMAIL_WEBHOOK_URL fallback
//   muted      {enabled:false} this scope stays silent — no inherit, no fallback
//   configured {enabled:true,  post to the named Worker Secret's URL
//               urlSecret:...}
//
// A boolean control (the `relay` pattern) collapses inherit and muted into one
// state and makes muting unreachable, so the control here is a radio group.
//
// Security invariant: `urlSecret` is the NAME of a Worker Secret, never a URL.
// Settings blobs are returned to any Access-authenticated client, and a chat
// webhook URL is a bearer credential.

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";
import { NEW_EMAIL_WEBHOOK_SECRET_PREFIX } from "shared/mailbox-settings";
import type { NewEmailWebhookSettings } from "shared/mailbox-settings";

import {
	NewEmailWebhookCard,
	isNewEmailWebhookValid,
	newEmailWebhookMode,
} from "~/components/NewEmailWebhookCard";
import { renderWithProviders } from "./test-utils";

/** Controlled harness — mirrors how each settings route drives the card. */
function Harness({
	initial,
	tier = "mailbox",
}: {
	initial?: NewEmailWebhookSettings;
	tier?: "mailbox" | "domain" | "org";
}) {
	const [value, setValue] = useState<NewEmailWebhookSettings | undefined>(initial);
	return (
		<>
			<NewEmailWebhookCard value={value} onChange={setValue} tier={tier} />
			<pre data-testid="emitted">{JSON.stringify(value ?? null)}</pre>
		</>
	);
}

function emitted(): unknown {
	return JSON.parse(screen.getByTestId("emitted").textContent ?? "null");
}

const inheritRadio = () => screen.getByRole("radio", { name: /inherit/i });
const muteRadio = () => screen.getByRole("radio", { name: /mute/i });
const configuredRadio = () => screen.getByRole("radio", { name: /send to a webhook/i });
const secretInput = () => screen.getByLabelText(/webhook secret name/i);

describe("NewEmailWebhookCard · three-state control (#694 UI)", () => {
	it("renders a 'New mail webhook' section with all three states", () => {
		renderWithProviders(<Harness />);

		expect(screen.getByText(/new mail webhook/i)).toBeInTheDocument();
		expect(inheritRadio()).toBeInTheDocument();
		expect(muteRadio()).toBeInTheDocument();
		expect(configuredRadio()).toBeInTheDocument();
	});

	it("selects Inherit when no block is saved", () => {
		renderWithProviders(<Harness />);

		expect(inheritRadio()).toBeChecked();
		expect(muteRadio()).not.toBeChecked();
		expect(configuredRadio()).not.toBeChecked();
	});

	it("selects Mute when the saved block is {enabled:false}", () => {
		renderWithProviders(<Harness initial={{ enabled: false }} />);

		expect(muteRadio()).toBeChecked();
		expect(inheritRadio()).not.toBeChecked();
	});

	it("selects Configured and restores the saved secret name", () => {
		renderWithProviders(
			<Harness initial={{ enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_SOC" }} />,
		);

		expect(configuredRadio()).toBeChecked();
		expect(secretInput()).toHaveValue("NEW_EMAIL_WEBHOOK_SOC");
	});

	it("emits {enabled:false} — not undefined — when Mute is picked", async () => {
		const user = userEvent.setup();
		renderWithProviders(<Harness />);

		await user.click(muteRadio());

		expect(emitted()).toEqual({ enabled: false });
	});

	it("emits undefined (key omitted) when Inherit is picked", async () => {
		const user = userEvent.setup();
		renderWithProviders(<Harness initial={{ enabled: false }} />);

		await user.click(inheritRadio());

		expect(emitted()).toBeNull();
	});

	it("prefills the secret name with the required prefix when Configured is picked", async () => {
		const user = userEvent.setup();
		renderWithProviders(<Harness />);

		await user.click(configuredRadio());

		expect(secretInput()).toHaveValue(NEW_EMAIL_WEBHOOK_SECRET_PREFIX);
		expect(emitted()).toEqual({
			enabled: true,
			urlSecret: NEW_EMAIL_WEBHOOK_SECRET_PREFIX,
		});
	});

	it("hides the secret name input unless Configured is selected", async () => {
		const user = userEvent.setup();
		renderWithProviders(<Harness />);

		expect(screen.queryByLabelText(/webhook secret name/i)).toBeNull();

		await user.click(configuredRadio());
		expect(secretInput()).toBeInTheDocument();

		await user.click(muteRadio());
		expect(screen.queryByLabelText(/webhook secret name/i)).toBeNull();
	});

	it("round-trips inherit → mute → configured → inherit", async () => {
		const user = userEvent.setup();
		renderWithProviders(<Harness />);

		expect(emitted()).toBeNull();

		await user.click(muteRadio());
		expect(emitted()).toEqual({ enabled: false });

		await user.click(configuredRadio());
		await user.clear(secretInput());
		await user.type(secretInput(), "NEW_EMAIL_WEBHOOK_TEAM");
		expect(emitted()).toEqual({ enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_TEAM" });

		await user.click(inheritRadio());
		expect(emitted()).toBeNull();
	});

	it("flags a secret name that does not start with NEW_EMAIL_WEBHOOK_", async () => {
		const user = userEvent.setup();
		renderWithProviders(<Harness />);

		await user.click(configuredRadio());
		await user.clear(secretInput());
		await user.type(secretInput(), "HUB_API_KEY");

		expect(secretInput()).toHaveAttribute("aria-invalid", "true");
		expect(await screen.findByRole("alert")).toHaveTextContent(
			NEW_EMAIL_WEBHOOK_SECRET_PREFIX,
		);
	});

	it("flags a pasted webhook URL — settings hold secret names, never URLs", async () => {
		const user = userEvent.setup();
		const { container } = renderWithProviders(<Harness />);

		await user.click(configuredRadio());
		await user.clear(secretInput());
		await user.type(secretInput(), "https://chat.googleapis.com/v1/spaces/X?key=k&token=t");

		expect(secretInput()).toHaveAttribute("aria-invalid", "true");
		expect(screen.getByRole("alert")).toBeInTheDocument();
		// No control anywhere in the card accepts a URL directly.
		expect(container.querySelector('input[type="url"]')).toBeNull();
	});

	it("clears the invalid flag once a well-prefixed name is entered", async () => {
		const user = userEvent.setup();
		renderWithProviders(<Harness />);

		await user.click(configuredRadio());
		await user.clear(secretInput());
		await user.type(secretInput(), "OOPS");
		expect(screen.getByRole("alert")).toBeInTheDocument();

		await user.clear(secretInput());
		await user.type(secretInput(), "NEW_EMAIL_WEBHOOK_OK");
		expect(screen.queryByRole("alert")).toBeNull();
		expect(secretInput()).not.toHaveAttribute("aria-invalid", "true");
	});

	it("explains the tier precedence so a narrow override reads as routing", () => {
		renderWithProviders(<Harness />);

		expect(
			screen.getByText(/mailbox\s*>\s*domain\s*>\s*org\s*>\s*global/i),
		).toBeInTheDocument();
	});
});

describe("newEmailWebhookMode", () => {
	it("maps an absent block to inherit", () => {
		expect(newEmailWebhookMode(undefined)).toBe("inherit");
	});

	it("maps an empty object to inherit (stripDefaultEqual strips {} only)", () => {
		expect(newEmailWebhookMode({})).toBe("inherit");
	});

	it("maps {enabled:false} to muted", () => {
		expect(newEmailWebhookMode({ enabled: false })).toBe("muted");
	});

	it("maps {enabled:true,urlSecret} to configured", () => {
		expect(
			newEmailWebhookMode({ enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_A" }),
		).toBe("configured");
	});

	it("maps a half-written block with no explicit enable to muted, matching resolveNewEmailWebhook", () => {
		expect(newEmailWebhookMode({ urlSecret: "NEW_EMAIL_WEBHOOK_A" })).toBe("muted");
	});
});

describe("isNewEmailWebhookValid", () => {
	it("accepts inherit and mute", () => {
		expect(isNewEmailWebhookValid(undefined)).toBe(true);
		expect(isNewEmailWebhookValid({ enabled: false })).toBe(true);
	});

	it("accepts a correctly prefixed secret name", () => {
		expect(
			isNewEmailWebhookValid({ enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_SOC" }),
		).toBe(true);
	});

	it("rejects an unprefixed secret name — the confused-deputy hole #615 closed", () => {
		expect(
			isNewEmailWebhookValid({ enabled: true, urlSecret: "CONFIRMATION_TOKEN_SECRET" }),
		).toBe(false);
	});

	it("rejects an empty secret name", () => {
		expect(isNewEmailWebhookValid({ enabled: true, urlSecret: "" })).toBe(false);
		expect(isNewEmailWebhookValid({ enabled: true })).toBe(false);
	});
});

// `format` (#563 follow-up): `chat` posts Slack/Google-Chat-shaped
// `{"text": "..."}` prose; `json` posts the structured event for consumers
// that want fields rather than a sentence to regex.
describe("NewEmailWebhookCard — payload format", () => {
	it("offers no format control until the tier is actually configured", () => {
		render(<Harness initial={{ enabled: false }} />);
		expect(screen.queryByLabelText(/structured json/i)).not.toBeInTheDocument();
	});

	it("defaults a newly configured tier to chat, emitting no explicit format", async () => {
		const user = userEvent.setup();
		render(<Harness />);

		await user.click(screen.getByRole("radio", { name: /send to a webhook/i }));

		// Absent, not `format: "chat"` — absent-key-inherits keeps stored blobs
		// minimal and lets the default move later without a migration.
		expect(emitted()).not.toHaveProperty("format");
	});

	it("emits format json when the operator picks structured output", async () => {
		const user = userEvent.setup();
		render(
			<Harness initial={{ enabled: true, urlSecret: `${NEW_EMAIL_WEBHOOK_SECRET_PREFIX}BOT` }} />,
		);

		await user.click(screen.getByLabelText(/structured json/i));

		expect(emitted()).toMatchObject({
			enabled: true,
			urlSecret: `${NEW_EMAIL_WEBHOOK_SECRET_PREFIX}BOT`,
			format: "json",
		});
	});

	it("keeps the chosen format when the secret name is edited afterwards", async () => {
		const user = userEvent.setup();
		render(
			<Harness
				initial={{
					enabled: true,
					urlSecret: `${NEW_EMAIL_WEBHOOK_SECRET_PREFIX}BOT`,
					format: "json",
				}}
			/>,
		);

		await user.type(screen.getByLabelText(/secret name/i), "2");

		// The secret-name handler replaces the whole block; without an explicit
		// spread it silently drops `format` and the tier reverts to chat prose.
		expect(emitted()).toMatchObject({ format: "json" });
	});
})


/**
 * "Send test" (the button next to the secret name).
 *
 * Every failure path in `dispatchNewEmailNotification` is silent by design, so
 * a typo'd secret name or a receiver that rejects the HMAC is otherwise
 * invisible until real mail arrives. The button posts the DRAFT block, so a
 * name can be verified before it is saved — which is when the typo happens.
 */
describe("NewEmailWebhookCard — send test", () => {
	afterEach(() => vi.unstubAllGlobals());

	/**
	 * A real Response, not a duck-typed stub: the call goes through
	 * `api.testNewEmailWebhook`, and `app/services/api.ts` reads `res.ok` and
	 * `res.headers.get("content-type")` before parsing.
	 */
	const jsonResponse = (body: unknown) =>
		new Response(JSON.stringify(body), {
			status: 200,
			headers: { "content-type": "application/json" },
		});

	const testButton = () => screen.getByRole("button", { name: /send test/i });

	it("offers no test button while the scope is inheriting", () => {
		render(<Harness />);

		expect(screen.queryByRole("button", { name: /send test/i })).toBeNull();
	});

	it("offers no test button while the scope is muted", () => {
		render(<Harness initial={{ enabled: false }} />);

		expect(screen.queryByRole("button", { name: /send test/i })).toBeNull();
	});

	it("disables the test button while the secret name fails the prefix guard", () => {
		render(<Harness initial={{ enabled: true, urlSecret: "HUB_API_KEY" }} />);

		expect(testButton()).toBeDisabled();
	});

	it("posts the draft block and its tier, then reports delivery", async () => {
		const user = userEvent.setup();
		const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ ok: true, status: 200 }));
		vi.stubGlobal("fetch", fetchMock);

		render(
			<Harness
				initial={{
					enabled: true,
					urlSecret: `${NEW_EMAIL_WEBHOOK_SECRET_PREFIX}SOC`,
					format: "json",
				}}
				tier="org"
			/>,
		);

		await user.click(testButton());

		expect(await screen.findByRole("status")).toHaveTextContent(/delivered/i);
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("/api/v1/new-email-webhook/test");
		expect(JSON.parse(init.body as string)).toMatchObject({
			urlSecret: `${NEW_EMAIL_WEBHOOK_SECRET_PREFIX}SOC`,
			format: "json",
			tier: "org",
		});
	});

	it("shows the stage-prefixed error as an alert when the endpoint reports a failure", async () => {
		const user = userEvent.setup();
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(
				jsonResponse({
					ok: false,
					stage: "secret",
					error: "new-email webhook secret NEW_EMAIL_WEBHOOK_SOC is not configured; sending nothing",
				}),
			),
		);

		render(
			<Harness initial={{ enabled: true, urlSecret: `${NEW_EMAIL_WEBHOOK_SECRET_PREFIX}SOC` }} />,
		);

		await user.click(testButton());

		expect(await screen.findByRole("alert")).toHaveTextContent(/secret:/i);
	});

	it("clears a stale result when the secret name is edited afterwards", async () => {
		// A "Delivered" left sitting next to an edited name reads as a pass for
		// a configuration that was never actually tested.
		const user = userEvent.setup();
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(jsonResponse({ ok: true, status: 200 })),
		);

		render(
			<Harness initial={{ enabled: true, urlSecret: `${NEW_EMAIL_WEBHOOK_SECRET_PREFIX}SOC` }} />,
		);

		await user.click(testButton());
		expect(await screen.findByRole("status")).toBeInTheDocument();

		await user.type(secretInput(), "2");

		expect(screen.queryByRole("status")).toBeNull();
	});

	it("clears a stale result when the payload format is changed afterwards", async () => {
		const user = userEvent.setup();
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(jsonResponse({ ok: true, status: 200 })),
		);

		render(
			<Harness initial={{ enabled: true, urlSecret: `${NEW_EMAIL_WEBHOOK_SECRET_PREFIX}SOC` }} />,
		);

		await user.click(testButton());
		expect(await screen.findByRole("status")).toBeInTheDocument();

		await user.click(screen.getByLabelText(/structured json/i));

		expect(screen.queryByRole("status")).toBeNull();
	});

	it("shows the thrown message as an alert when the request itself fails", async () => {
		const user = userEvent.setup();
		vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network unreachable")));

		render(
			<Harness initial={{ enabled: true, urlSecret: `${NEW_EMAIL_WEBHOOK_SECRET_PREFIX}SOC` }} />,
		);

		await user.click(testButton());

		expect(await screen.findByRole("alert")).toHaveTextContent(/network unreachable/i);
	});
});
