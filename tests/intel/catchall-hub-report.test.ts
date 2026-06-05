// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	buildCatchallMispEvent,
	reportCatchallProbes,
	type CatchallSummaryForReport,
	type CatchallTopSource,
} from "../../workers/intel/catchall-hub-report";
import type { HubConfig } from "../../workers/lib/hub-config";

const fetchMock = vi.fn();

beforeEach(() => {
	fetchMock.mockReset();
	vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
	vi.unstubAllGlobals();
});

function jsonResponse(body: unknown, init: ResponseInit = {}) {
	return new Response(JSON.stringify(body), {
		status: 200,
		headers: { "Content-Type": "application/json" },
		...init,
	});
}

const optedInHub: HubConfig = {
	url: "https://hub.example.com",
	org_uuid: "aaaaaaaa-0000-0000-0000-000000000001",
	api_key_secret_name: "HUB_API_KEY",
	default_sharing_group_uuid: "bbbbbbbb-0000-0000-0000-000000000002",
	auto_report: true,
};

const optedOutHub: HubConfig = {
	...optedInHub,
	auto_report: false,
};

const noAutoReportHub: HubConfig = {
	url: "https://hub.example.com",
	org_uuid: "aaaaaaaa-0000-0000-0000-000000000001",
	api_key_secret_name: "HUB_API_KEY",
};

const sampleSource: CatchallTopSource = {
	source_ip: "10.0.0.1",
	sender_domain: "attacker.example",
	count: 47,
	first_seen: "2026-06-01T00:00:00Z",
	last_seen: "2026-06-05T23:59:00Z",
};

const sampleSummary: CatchallSummaryForReport = {
	topSources: [sampleSource],
};

// ---------------------------------------------------------------------------
// buildCatchallMispEvent
// ---------------------------------------------------------------------------

describe("buildCatchallMispEvent", () => {
	it("produces ip-src and domain attributes for each source", async () => {
		const event = await buildCatchallMispEvent({
			domain: "target.example",
			sources: [sampleSource],
		});

		const attrs = event.Event.Attribute;
		const types = attrs.map((a) => a.type);
		expect(types).toContain("ip-src");
		expect(types).toContain("domain");

		const ipAttr = attrs.find((a) => a.type === "ip-src");
		expect(ipAttr?.value).toBe("10.0.0.1");
		expect(ipAttr?.to_ids).toBe(true);

		const domAttr = attrs.find((a) => a.type === "domain");
		expect(domAttr?.value).toBe("attacker.example");
		expect(domAttr?.to_ids).toBe(true);
	});

	it("event info contains the domain name", async () => {
		const event = await buildCatchallMispEvent({
			domain: "acme.com",
			sources: [sampleSource],
		});
		expect(event.Event.info).toContain("acme.com");
	});

	it("sets distribution=4 and sharing_group_uuid when a sharing group is given", async () => {
		const event = await buildCatchallMispEvent({
			domain: "d.example",
			sources: [sampleSource],
			sharingGroupUuid: "sg-uuid",
		});
		expect(event.Event.distribution).toBe("4");
		expect(event.Event.sharing_group_uuid).toBe("sg-uuid");
	});

	it("sets distribution=1 when no sharing group is given", async () => {
		const event = await buildCatchallMispEvent({
			domain: "d.example",
			sources: [sampleSource],
		});
		expect(event.Event.distribution).toBe("1");
	});

	it("includes catchall-probe tag", async () => {
		const event = await buildCatchallMispEvent({
			domain: "d.example",
			sources: [sampleSource],
		});
		const tagNames = event.Event.Tag.map((t) => t.name);
		expect(tagNames).toContain("catchall-probe");
	});

	it("never emits email-src, email-subject, or sha256 attributes (no PII)", async () => {
		const event = await buildCatchallMispEvent({
			domain: "target.example",
			sources: [sampleSource],
		});
		const forbidden = new Set(["email-src", "email-subject", "sha256", "email-dst"]);
		for (const attr of event.Event.Attribute) {
			expect(forbidden).not.toContain(attr.type);
		}
	});

	it("attribute values never contain the localpart portion of an address", async () => {
		const sourceWithRichDomain: CatchallTopSource = {
			source_ip: "192.0.2.1",
			sender_domain: "probe.example",
			count: 5,
			first_seen: "2026-06-01T00:00:00Z",
			last_seen: "2026-06-01T01:00:00Z",
		};
		const event = await buildCatchallMispEvent({
			domain: "victim.example",
			sources: [sourceWithRichDomain],
		});
		for (const attr of event.Event.Attribute) {
			// A localpart would be the part before '@'; sender domain never starts
			// with a localpart so this checks that no full address slipped through.
			expect(attr.value).not.toMatch(/@/);
		}
	});

	it("produces no attributes when sources array is empty", async () => {
		const event = await buildCatchallMispEvent({ domain: "d.example", sources: [] });
		expect(event.Event.Attribute).toHaveLength(0);
	});
});

// ---------------------------------------------------------------------------
// reportCatchallProbes — consent gate
// ---------------------------------------------------------------------------

describe("reportCatchallProbes — consent gate", () => {
	it("posts to the hub when auto_report is true", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse({ Event: { uuid: "posted-uuid-1234" } }),
		);

		const result = await reportCatchallProbes({
			hubConfig: optedInHub,
			apiKey: "live-key",
			domain: "acme.com",
			summary: sampleSummary,
		});

		expect(result.posted).toBe(true);
		expect(result.uuid).toBe("posted-uuid-1234");
		expect(fetchMock).toHaveBeenCalledOnce();

		// Verify request goes to hub /events endpoint
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		const parsedUrl = new URL(url);
		expect(parsedUrl.hostname).toBe("hub.example.com");
		expect(parsedUrl.pathname).toBe("/events");
		expect((init.headers as Record<string, string>).Authorization).toBe("live-key");
	});

	it("does not post when auto_report is false (opted-out)", async () => {
		const result = await reportCatchallProbes({
			hubConfig: optedOutHub,
			apiKey: "live-key",
			domain: "acme.com",
			summary: sampleSummary,
		});

		expect(result.posted).toBe(false);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("does not post when auto_report is absent (default opt-out)", async () => {
		const result = await reportCatchallProbes({
			hubConfig: noAutoReportHub,
			apiKey: "live-key",
			domain: "acme.com",
			summary: sampleSummary,
		});

		expect(result.posted).toBe(false);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("does not post when topSources is empty", async () => {
		const result = await reportCatchallProbes({
			hubConfig: optedInHub,
			apiKey: "live-key",
			domain: "acme.com",
			summary: { topSources: [] },
		});

		expect(result.posted).toBe(false);
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// reportCatchallProbes — posted event shape (no PII)
// ---------------------------------------------------------------------------

describe("reportCatchallProbes — posted event shape", () => {
	it("posted event contains only ip-src and domain attribute types", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse({ Event: { uuid: "uuid-shape-check" } }),
		);

		await reportCatchallProbes({
			hubConfig: optedInHub,
			apiKey: "key",
			domain: "target.example",
			summary: sampleSummary,
		});

		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		const body = JSON.parse(init.body as string) as {
			Event: { Attribute: Array<{ type: string; value: string }> };
		};

		const allowedTypes = new Set(["ip-src", "domain"]);
		for (const attr of body.Event.Attribute) {
			expect(allowedTypes).toContain(attr.type);
		}
	});

	it("posted event attribute values never include '@' (no full email addresses)", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse({ Event: { uuid: "uuid-pii-check" } }),
		);

		await reportCatchallProbes({
			hubConfig: optedInHub,
			apiKey: "key",
			domain: "target.example",
			summary: {
				topSources: [
					{
						source_ip: "203.0.113.5",
						sender_domain: "scan.example",
						count: 100,
						first_seen: "2026-06-01T00:00:00Z",
						last_seen: "2026-06-05T00:00:00Z",
					},
				],
			},
		});

		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		const body = JSON.parse(init.body as string) as {
			Event: { Attribute: Array<{ value: string }> };
		};

		for (const attr of body.Event.Attribute) {
			expect(attr.value).not.toMatch(/@/);
		}
	});

	it("forwards sharing_group_uuid from the hub config", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse({ Event: { uuid: "uuid-sg-check" } }),
		);

		await reportCatchallProbes({
			hubConfig: optedInHub,
			apiKey: "key",
			domain: "d.example",
			summary: sampleSummary,
		});

		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		const body = JSON.parse(init.body as string) as {
			Event: { sharing_group_uuid?: string; distribution: string };
		};

		expect(body.Event.sharing_group_uuid).toBe(optedInHub.default_sharing_group_uuid);
		expect(body.Event.distribution).toBe("4");
	});
});

// ---------------------------------------------------------------------------
// reportCatchallProbes — failure handling
// ---------------------------------------------------------------------------

describe("reportCatchallProbes — failure handling", () => {
	it("returns { posted: false } when the hub returns 5xx", async () => {
		fetchMock.mockResolvedValueOnce(new Response("error", { status: 500 }));

		const result = await reportCatchallProbes({
			hubConfig: optedInHub,
			apiKey: "key",
			domain: "acme.com",
			summary: sampleSummary,
		});

		expect(result.posted).toBe(false);
		expect(result.uuid).toBeUndefined();
	});

	it("returns { posted: false } when fetch throws (network error)", async () => {
		fetchMock.mockRejectedValueOnce(new Error("network failure"));

		const result = await reportCatchallProbes({
			hubConfig: optedInHub,
			apiKey: "key",
			domain: "acme.com",
			summary: sampleSummary,
		});

		expect(result.posted).toBe(false);
	});

	it("returns { posted: false } when hub response is missing Event.uuid", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse({ Event: {} }));

		const result = await reportCatchallProbes({
			hubConfig: optedInHub,
			apiKey: "key",
			domain: "acme.com",
			summary: sampleSummary,
		});

		expect(result.posted).toBe(false);
	});
});
