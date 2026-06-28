// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for honeypot inbound IOC publishing (issue #24).
 *
 * Covers:
 *   - buildHoneypotMispEvent stamps elevated trust (threat_level_id "1") + tag
 *   - reportHoneypotInbound posts to the hub /events with that elevated event
 *   - reportHoneypotInbound is gated on auto_report and a non-empty sender
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	buildHoneypotMispEvent,
	reportHoneypotInbound,
} from "../../workers/intel/honeypot-report";
import type { HubConfig } from "../../workers/lib/hub-config";
import type { Email } from "postal-mime";

const fetchMock = vi.fn();
beforeEach(() => {
	fetchMock.mockReset();
	vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
	vi.unstubAllGlobals();
});

const hub: HubConfig = {
	url: "https://hub.example.com",
	org_uuid: "aaaaaaaa-0000-0000-0000-000000000001",
	api_key_secret_name: "HUB_SECRET_MAIN",
	default_sharing_group_uuid: "bbbbbbbb-0000-0000-0000-000000000002",
	auto_report: true,
};

function makeEmail(over: Partial<Email> = {}): Email {
	return {
		from: { address: "attacker@evil.example", name: "" },
		to: [{ address: "hp-abc@acme.example", name: "" }],
		subject: "You won a prize",
		text: "Click http://phish.example/login now",
		html: null,
		headers: [],
		attachments: [],
		...over,
	} as unknown as Email;
}

describe("buildHoneypotMispEvent", () => {
	it("stamps elevated trust (threat_level_id 1) and a honeypot tag", async () => {
		const event = await buildHoneypotMispEvent({
			info: "Honeypot capture",
			observedAt: "2026-06-05T00:00:00Z",
			sender: "attacker@evil.example",
			subject: "hi",
			bodyText: "body",
			urls: [{ url: "http://phish.example/x", hostname: "phish.example" }],
		});
		expect(event.Event.threat_level_id).toBe("1");
		expect(event.Event.Tag.map((t) => t.name)).toContain("honeypot");
		// Reuses the report.ts attribute policy: URL + domain present, recipients absent.
		const types = event.Event.Attribute.map((a) => a.type);
		expect(types).toContain("url");
		expect(types).toContain("domain");
		expect(types).not.toContain("email-dst");
	});
});

describe("reportHoneypotInbound", () => {
	function jsonResponse(body: unknown) {
		return new Response(JSON.stringify(body), {
			status: 200,
			headers: { "Content-Type": "application/json" },
		});
	}

	it("posts an elevated-trust event to the hub /events when auto_report is on", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse({ Event: { uuid: "posted-uuid" } }));

		const result = await reportHoneypotInbound({
			hubConfig: hub,
			apiKey: "live-key",
			mailboxId: "hp-abc@acme.example",
			parsedEmail: makeEmail(),
		});

		expect(result.posted).toBe(true);
		expect(result.uuid).toBe("posted-uuid");
		expect(fetchMock).toHaveBeenCalledOnce();
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(new URL(url).hostname).toBe("hub.example.com");
		expect(new URL(url).pathname).toBe("/events");
		expect((init.headers as Record<string, string>).Authorization).toBe("live-key");
		const body = JSON.parse(init.body as string) as { Event: { threat_level_id: string; Tag: { name: string }[] } };
		expect(body.Event.threat_level_id).toBe("1");
		expect(body.Event.Tag.map((t) => t.name)).toContain("honeypot");
	});

	it("does not post when auto_report is off", async () => {
		const result = await reportHoneypotInbound({
			hubConfig: { ...hub, auto_report: false },
			apiKey: "live-key",
			mailboxId: "hp-abc@acme.example",
			parsedEmail: makeEmail(),
		});
		expect(result.posted).toBe(false);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("does not post when the message has no sender", async () => {
		const result = await reportHoneypotInbound({
			hubConfig: hub,
			apiKey: "live-key",
			mailboxId: "hp-abc@acme.example",
			parsedEmail: makeEmail({ from: undefined }),
		});
		expect(result.posted).toBe(false);
		expect(fetchMock).not.toHaveBeenCalled();
	});
});
