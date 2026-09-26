// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * `assessSendRisk` / `gatherSendContext` — the stateful wrapper shared by the
 * preflight endpoint and the send gate. Settings and feed lookups are mocked;
 * the DO is a fake `getSendContext`.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const settings = vi.hoisted(() => ({ security: {} as Record<string, unknown> }));

vi.mock("../../workers/lib/mailbox-settings", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/mailbox-settings")>();
	return { ...original, resolveMailboxSettings: vi.fn(async () => ({ security: settings.security })) };
});

vi.mock("../../workers/intel/feeds", async (orig) => {
	const original = await orig<typeof import("../../workers/intel/feeds")>();
	return {
		...original,
		checkUrlsAgainstFeeds: vi.fn(async (_env: unknown, _mb: string, urls: string[]) =>
			urls.map((u) =>
				new URL(u).hostname === "evil.example"
					? { matched: true as const, feedId: "openphish", value: u, confirmed: true }
					: null,
			),
		),
	};
});

import { assessSendRisk, gatherSendContext, type SendContextStub } from "../../workers/lib/send-risk-assess";
import type { SendContextRows } from "../../workers/durableObject/recipient-graph";

const MAILBOX_ID = "operator@internal.example";
const OLD = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString();
const RECENT = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
const env = { BLOOM_KV: {} as KVNamespace };

function stubReturning(rows: Partial<SendContextRows>) {
	const calls: Array<{ addresses: string[]; originalRef?: string | null }> = [];
	const stub: SendContextStub = {
		async getSendContext(args) {
			calls.push(args);
			return { recipients: [], domainSendCounts: {}, knownDomains: [], originalVerdict: null, ...rows };
		},
	};
	return { stub, calls };
}

const knownVendor: Partial<SendContextRows> = {
	recipients: [{ address: "vendor@acme.example", send_count: 4, first_sent: OLD, last_sent: RECENT }],
	domainSendCounts: { "acme.example": 4 },
	knownDomains: ["acme.example"],
};

beforeEach(() => {
	settings.security = {};
});

describe("gatherSendContext", () => {
	it("asks the DO for every recipient and the original message", async () => {
		const { stub, calls } = stubReturning({});
		await gatherSendContext(env, stub, {
			mailboxId: MAILBOX_ID,
			to: "Vendor@Acme.example",
			cc: ["a@internal.example"],
			bcc: "b@else.example",
			originalRef: "orig-1",
		});
		expect(calls).toEqual([
			{ addresses: ["vendor@acme.example", "a@internal.example", "b@else.example"], originalRef: "orig-1" },
		]);
	});

	it("parses the original verdict and collects feed hits", async () => {
		const { stub } = stubReturning({
			originalVerdict: JSON.stringify({ action: "quarantine", classification: { label: "bec" } }),
		});
		const ctx = await gatherSendContext(env, stub, {
			mailboxId: MAILBOX_ID,
			to: "vendor@acme.example",
			body: '<a href="https://evil.example/pay">pay</a> and https://fine.example/',
		});
		expect(ctx.thread).toEqual({ action: "quarantine", label: "bec" });
		expect(ctx.feedHits).toEqual([{ host: "evil.example", feedId: "openphish", confirmed: true }]);
	});

	it("degrades to the stateless rules when the DO read fails", async () => {
		const stub: SendContextStub = { getSendContext: async () => { throw new Error("DO unavailable"); } };
		const ctx = await gatherSendContext(env, stub, { mailboxId: MAILBOX_ID, to: "vendor@acme.example" });
		expect(ctx.recipientHistory).toBeUndefined();
		expect(ctx.thread).toBeNull();
	});

	it("passes the custom attachment blocklist through", async () => {
		settings.security = { attachment_policy: { custom_blocklist_extensions: ["zip"] } };
		const ctx = await gatherSendContext(env, undefined, { mailboxId: MAILBOX_ID, to: "a@internal.example" });
		expect(ctx.customBlockedExtensions).toEqual(["zip"]);
	});
});

describe("assessSendRisk — established-correspondent trust", () => {
	const input = { mailboxId: MAILBOX_ID, to: "vendor@acme.example", subject: "Invoice", body: "Attached." };

	it("applies only when the setting is on and the send comes from the API", async () => {
		settings.security = { send_risk: { trust_known_recipients: true } };
		expect((await assessSendRisk(env, stubReturning(knownVendor).stub, { ...input, channel: "api" })).tier).toBe(0);
		expect((await assessSendRisk(env, stubReturning(knownVendor).stub, { ...input, channel: "mcp" })).tier).toBe(1);
		expect((await assessSendRisk(env, stubReturning(knownVendor).stub, input)).tier).toBe(1);
	});

	it("is off by default", async () => {
		expect((await assessSendRisk(env, stubReturning(knownVendor).stub, { ...input, channel: "api" })).tier).toBe(1);
	});

	it("is unavailable when the history read fails", async () => {
		settings.security = { send_risk: { trust_known_recipients: true } };
		const stub: SendContextStub = { getSendContext: async () => { throw new Error("boom"); } };
		expect((await assessSendRisk(env, stub, { ...input, channel: "api" })).tier).toBe(1);
	});
});

describe("assessSendRisk — flagged thread", () => {
	it("raises a reply to a quarantined message to tier 2", async () => {
		const { stub } = stubReturning({ originalVerdict: JSON.stringify({ action: "quarantine" }) });
		const risk = await assessSendRisk(env, stub, {
			mailboxId: MAILBOX_ID,
			to: "asker@external.example",
			subject: "Re: Question",
			body: "Sure",
			originalRef: "orig-1",
			channel: "api",
		});
		expect(risk.tier).toBe(2);
		expect(risk.reasons).toContain("Reply or forward of a message flagged as quarantined");
	});
});
