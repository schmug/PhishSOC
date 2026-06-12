// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for the catch-all dispatch seam (issue #426).
 *
 * Covers:
 *   - catchall_intel defaults to disabled; round-trips through parse + strip
 *   - normalizeInbound returns MailboxInbound for a registered address
 *   - normalizeInbound returns CatchallInbound for an unregistered address
 *     on an owned+enabled domain
 *   - normalizeInbound returns null for an owned+disabled domain
 *   - normalizeInbound returns null for an unowned domain
 *   - With multiple recipients, the first owned+enabled one is selected
 *   - email() handler routes to receiveCatchall; no mailbox INBOX row; no AI
 */

import { describe, expect, it, vi } from "vitest";
import { parseDomainSettings } from "../../shared/domain-settings";
import { stripDefaultEqual } from "../../workers/lib/mailbox-settings";

// ---------------------------------------------------------------------------
// 1. catchall_intel schema round-trip
// ---------------------------------------------------------------------------

describe("catchall_intel — schema round-trip", () => {
	it("parses an absent catchall_intel as undefined", () => {
		const result = parseDomainSettings({});
		expect(result?.catchall_intel).toBeUndefined();
	});

	it("parses a valid enabled block", () => {
		const result = parseDomainSettings({
			catchall_intel: { enabled: true, retention_days: 14, sample_limit: 25 },
		});
		expect(result?.catchall_intel).toEqual({ enabled: true, retention_days: 14, sample_limit: 25 });
	});

	it("parses a disabled block", () => {
		const result = parseDomainSettings({
			catchall_intel: { enabled: false, retention_days: 30, sample_limit: 50 },
		});
		expect(result?.catchall_intel?.enabled).toBe(false);
	});
});

describe("catchall_intel — stripDefaultEqual", () => {
	it("strips the default-off full block", () => {
		const result = stripDefaultEqual({
			catchall_intel: { enabled: false, retention_days: 30, sample_limit: 50 },
		});
		expect(result).not.toHaveProperty("catchall_intel");
	});

	it("strips enabled:false shorthand", () => {
		const result = stripDefaultEqual({ catchall_intel: { enabled: false } });
		expect(result).not.toHaveProperty("catchall_intel");
	});

	it("preserves an enabled block", () => {
		const result = stripDefaultEqual({
			catchall_intel: { enabled: true, retention_days: 7, sample_limit: 20 },
		});
		expect(result.catchall_intel).toEqual({ enabled: true, retention_days: 7, sample_limit: 20 });
	});
});

// ---------------------------------------------------------------------------
// 2. normalizeInbound — discriminated union
// ---------------------------------------------------------------------------

// Minimal PostalMime-shaped email builder
function rawEmailBytes(to: string[], from = "sender@attacker.example"): Uint8Array {
	const toHeader = to.map((a) => `To: ${a}`).join("\r\n");
	const raw = [
		`From: ${from}`,
		toHeader,
		"Subject: test",
		"MIME-Version: 1.0",
		"Content-Type: text/plain",
		"",
		"body",
	].join("\r\n");
	return new TextEncoder().encode(raw);
}

function makeStream(bytes: Uint8Array): ReadableStream {
	return new ReadableStream({
		start(controller) {
			controller.enqueue(bytes);
			controller.close();
		},
	});
}

interface FakeR2 {
	_store: Record<string, string>;
	head(key: string): Promise<{ key: string } | null>;
	get(key: string): Promise<{ json<T>(): Promise<T>; etag: string } | null>;
	put(key: string, val: string): Promise<void>;
}

function makeR2(initial: Record<string, string> = {}): FakeR2 {
	const store = { ...initial };
	return {
		_store: store,
		async head(key) { return key in store ? { key } : null; },
		async get(key) {
			const val = store[key];
			if (!val) return null;
			return { json: async <T>() => JSON.parse(val) as T, etag: "etag" };
		},
		async put(key, val) { store[key] = val; },
	};
}

async function runNormalize(
	toAddresses: string[],
	opts: {
		emailAddresses?: string[];
		domains?: string;
		ownedDomains?: string[];
		mailboxes?: string[];
		domainSettings?: Record<string, unknown>;
	} = {},
) {
	const { normalizeInbound } = await import("../../workers/providers/cf-routing");

	const bucket = makeR2();
	for (const m of opts.mailboxes ?? []) {
		bucket._store[`mailboxes/${m}.json`] = JSON.stringify({ id: m });
	}
	if (opts.domainSettings) {
		for (const [domain, settings] of Object.entries(opts.domainSettings)) {
			bucket._store[`domains/${domain}.json`] = JSON.stringify(settings);
		}
	}
	// Clear the domain settings cache between test runs
	const { clearDomainSettingsCache } = await import("../../workers/lib/domain-settings");
	clearDomainSettingsCache();

	const orgDomains = opts.ownedDomains ?? [];
	bucket._store["org/settings.json"] = JSON.stringify({ domains: orgDomains });
	// Clear org settings cache too
	const { clearOrgSettingsCache } = await import("../../workers/lib/org-settings");
	clearOrgSettingsCache();

	const bytes = rawEmailBytes(toAddresses);
	const event = { raw: makeStream(bytes), rawSize: bytes.byteLength };
	const env = {
		EMAIL_ADDRESSES: opts.emailAddresses ?? [],
		DOMAINS: opts.domains ?? "",
		BUCKET: bucket,
	} as unknown as Parameters<typeof normalizeInbound>[1];

	return normalizeInbound(event, env);
}

describe("normalizeInbound — mailbox path", () => {
	it("returns MailboxInbound for a registered address with existing mailbox", async () => {
		const result = await runNormalize(
			["alice@acme.example"],
			{ emailAddresses: ["alice@acme.example"], mailboxes: ["alice@acme.example"] },
		);
		expect(result?.kind).toBe("mailbox");
		if (result?.kind === "mailbox") {
			expect(result.mailboxId).toBe("alice@acme.example");
		}
	});

	it("returns null when registered address has no mailbox JSON", async () => {
		const result = await runNormalize(
			["alice@acme.example"],
			{ emailAddresses: ["alice@acme.example"], mailboxes: [] },
		);
		expect(result).toBeNull();
	});
});

describe("normalizeInbound — catch-all path", () => {
	it("returns CatchallInbound for unregistered recipient on owned+enabled domain", async () => {
		const result = await runNormalize(
			["catchall@acme.example"],
			{
				emailAddresses: ["alice@acme.example"],
				mailboxes: [],
				ownedDomains: ["acme.example"],
				domainSettings: {
					"acme.example": { catchall_intel: { enabled: true, retention_days: 14, sample_limit: 25 } },
				},
			},
		);
		expect(result?.kind).toBe("catchall");
		if (result?.kind === "catchall") {
			expect(result.domain).toBe("acme.example");
			expect(result.retentionDays).toBe(14);
			expect(result.sampleLimit).toBe(25);
		}
	});

	it("returns null for owned+disabled domain", async () => {
		const result = await runNormalize(
			["catchall@acme.example"],
			{
				emailAddresses: ["alice@acme.example"],
				mailboxes: [],
				ownedDomains: ["acme.example"],
				domainSettings: {
					"acme.example": { catchall_intel: { enabled: false, retention_days: 30, sample_limit: 50 } },
				},
			},
		);
		expect(result).toBeNull();
	});

	it("returns null for an unowned domain", async () => {
		const result = await runNormalize(
			["catchall@notowned.example"],
			{
				emailAddresses: ["alice@acme.example"],
				mailboxes: [],
				ownedDomains: ["acme.example"],
				domainSettings: {},
			},
		);
		expect(result).toBeNull();
	});

	it("with empty EMAIL_ADDRESSES: falls through to catch-all when first recipient has no mailbox", async () => {
		const result = await runNormalize(
			["catchall@unowned.example", "probe@acme.example"],
			{
				emailAddresses: [],
				mailboxes: [],
				domains: "acme.example",
				domainSettings: {
					"acme.example": { catchall_intel: { enabled: true, retention_days: 30, sample_limit: 50 } },
				},
			},
		);
		expect(result?.kind).toBe("catchall");
		if (result?.kind === "catchall") {
			expect(result.domain).toBe("acme.example");
		}
	});

	it("with empty EMAIL_ADDRESSES: routes probe on owned+enabled domain to catch-all", async () => {
		const result = await runNormalize(
			["probe@acme.example"],
			{
				emailAddresses: [],
				mailboxes: [],
				domains: "acme.example",
				domainSettings: {
					"acme.example": { catchall_intel: { enabled: true, retention_days: 30, sample_limit: 50 } },
				},
			},
		);
		expect(result?.kind).toBe("catchall");
		if (result?.kind === "catchall") {
			expect(result.domain).toBe("acme.example");
		}
	});

	it("with EMAIL_ADDRESSES set: picks first owned+enabled among non-registered recipients", async () => {
		const result = await runNormalize(
			["other@notowned.example", "probe@acme.example"],
			{
				emailAddresses: ["alice@acme.example"],
				mailboxes: [],
				ownedDomains: ["acme.example"],
				domainSettings: {
					"acme.example": { catchall_intel: { enabled: true, retention_days: 30, sample_limit: 50 } },
				},
			},
		);
		expect(result?.kind).toBe("catchall");
		if (result?.kind === "catchall") {
			expect(result.domain).toBe("acme.example");
		}
	});
});

// ---------------------------------------------------------------------------
// 3. receiveCatchall — best-effort: no mailbox row, no AI
// ---------------------------------------------------------------------------

describe("receiveCatchall — best-effort dispatch", () => {
	it("calls DO.recordCatchallProbe and does not call env.AI", async () => {
		const { receiveCatchall } = await import("../../workers/index");
		const { clearDomainSettingsCache } = await import("../../workers/lib/domain-settings");
		clearDomainSettingsCache();

		const probeStub = { recordCatchallProbe: vi.fn().mockResolvedValue(undefined) };
		const mailboxStub = { createEmail: vi.fn() };

		const env = {
			AI: new Proxy({}, {
				get() { throw new Error("env.AI must not be called from receiveCatchall"); },
			}),
			CATCHALL_INTEL: {
				idFromName: () => "stub-id",
				get: () => probeStub,
			},
			MAILBOX: {
				idFromName: () => "stub-id",
				get: () => mailboxStub,
			},
			BUCKET: { head: vi.fn().mockResolvedValue(null) },
		} as unknown as Parameters<typeof receiveCatchall>[1];

		const bytes = rawEmailBytes(["probe@acme.example"]);
		const parsedEmail = {
			to: [{ address: "probe@acme.example", name: "" }],
			from: { address: "attacker@evil.example", name: "" },
			subject: "Test catch-all",
			text: "body",
			html: null,
			headers: [],
			attachments: [],
		};

		const normalized = {
			kind: "catchall" as const,
			rawEmail: bytes.buffer as ArrayBuffer,
			parsedEmail: parsedEmail as unknown as import("postal-mime").Email,
			domain: "acme.example",
			retentionDays: 30,
			sampleLimit: 50,
		};

		const ctx = { waitUntil: vi.fn() } as unknown as ExecutionContext;
		await receiveCatchall(normalized, env, ctx);

		expect(probeStub.recordCatchallProbe).toHaveBeenCalledOnce();
		expect(mailboxStub.createEmail).not.toHaveBeenCalled();
	});

	it("does not throw when DO.recordCatchallProbe rejects (best-effort)", async () => {
		const { receiveCatchall } = await import("../../workers/index");
		const { clearDomainSettingsCache } = await import("../../workers/lib/domain-settings");
		clearDomainSettingsCache();

		const probeStub = { recordCatchallProbe: vi.fn().mockRejectedValue(new Error("DO unavailable")) };

		const env = {
			AI: {} as unknown,
			CATCHALL_INTEL: {
				idFromName: () => "stub-id",
				get: () => probeStub,
			},
		} as unknown as Parameters<typeof receiveCatchall>[1];

		const parsedEmail = {
			to: [{ address: "probe@acme.example", name: "" }],
			from: { address: "attacker@evil.example", name: "" },
			subject: "test", text: "body", html: null, headers: [], attachments: [],
		};

		const normalized = {
			kind: "catchall" as const,
			rawEmail: new ArrayBuffer(0),
			parsedEmail: parsedEmail as unknown as import("postal-mime").Email,
			domain: "acme.example",
			retentionDays: 30,
			sampleLimit: 50,
		};

		await expect(
			receiveCatchall(normalized, env, {} as ExecutionContext),
		).resolves.toBeUndefined();
	});
});
