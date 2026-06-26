// Catch-all intel section of `app/routes/domain-settings.tsx` (#521).
//
// Verifies the `enabled` toggle reflects the persisted value on load and that
// saving merges the new `catchall_intel` block into the existing loaded
// settings rather than replacing the whole tier with `catchall_intel` alone
// (whole-object replace per tier — wiping auto-draft / agent-model would be a
// regression). Exercises the real `useDomainSettings` / `useUpdateDomainSettings`
// hooks against a global-fetch mock dispatched by `new URL(url).pathname`
// (app/CLAUDE.md test convention).

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

// Static text-model list so the agent-model dropdown doesn't need a fetch.
vi.mock("~/queries/text-models", () => ({
	useTextModels: () => ({ models: ["@cf/meta/llama-3.3-70b-instruct-fp8-fast"] }),
}));

import DomainSettingsRoute from "~/routes/domain-settings";
import { renderWithProviders } from "./test-utils";

const SETTINGS_PATH = "/api/v1/domains/example.com/settings";

let stored: Record<string, unknown>;
let putBodies: Array<Record<string, unknown>>;

function jsonResponse(data: unknown) {
	return new Response(JSON.stringify(data), {
		status: 200,
		headers: { "content-type": "application/json" },
	});
}

beforeEach(() => {
	putBodies = [];
	stored = {
		autoDraft: { enabled: false },
		agentModel: "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
		catchall_intel: { enabled: false },
	};
	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === "string" ? input : input.toString();
			const { pathname } = new URL(url, "http://localhost");
			if (pathname === SETTINGS_PATH) {
				if (init?.method === "PUT") {
					const body = JSON.parse(init.body as string) as {
						settings: Record<string, unknown>;
					};
					putBodies.push(body.settings);
					// Whole-object replace per tier — mirror the worker.
					stored = body.settings;
					return jsonResponse({ domain: "example.com", settings: stored });
				}
				return jsonResponse({ domain: "example.com", settings: stored });
			}
			throw new Error(`unexpected fetch: ${pathname}`);
		}),
	);
});

afterEach(() => {
	vi.unstubAllGlobals();
});

function renderDomainSettings() {
	return renderWithProviders(
		<Routes>
			<Route
				path="/domains/:domain/settings"
				element={<DomainSettingsRoute />}
			/>
		</Routes>,
		{ initialEntries: ["/domains/example.com/settings"] },
	);
}

describe("Domain settings · Catch-all intel section (#521)", () => {
	it("renders the enabled toggle reflecting the persisted value (off)", async () => {
		renderDomainSettings();
		const toggle = await screen.findByRole("checkbox", {
			name: /catch-all/i,
		});
		expect(toggle).not.toBeChecked();
	});

	it("renders the enabled toggle checked when persisted on", async () => {
		stored = { ...stored, catchall_intel: { enabled: true } };
		renderDomainSettings();
		const toggle = await screen.findByRole("checkbox", {
			name: /catch-all/i,
		});
		expect(toggle).toBeChecked();
	});

	it("saving with the toggle on merges catchall_intel into existing settings", async () => {
		const user = userEvent.setup();
		renderDomainSettings();

		const toggle = await screen.findByRole("checkbox", {
			name: /catch-all/i,
		});
		await user.click(toggle);

		await user.click(screen.getByRole("button", { name: /save changes/i }));

		await waitFor(() => expect(putBodies).toHaveLength(1));
		const saved = putBodies[0];
		// The new catchall_intel block is persisted...
		expect(saved.catchall_intel).toMatchObject({ enabled: true });
		// ...and the previously-set domain settings are preserved.
		expect(saved.autoDraft).toEqual({ enabled: false });
		expect(saved.agentModel).toBe(
			"@cf/meta/llama-3.3-70b-instruct-fp8-fast",
		);
	});
});
