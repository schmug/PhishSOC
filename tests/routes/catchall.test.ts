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

// Minimal PostalMime-shaped email builder.
//
// `receivedLines` (full `Received:` header values, top-first) and the
// `receivedFor` convenience let a test reproduce the per-RCPT delivery that
// Cloudflare Email Routing performs: a `Received: ... for <addr>;` line stamped
// at the trust boundary. `cc` addresses land in `parsedEmail.cc`, NOT
// `parsedEmail.to`, mirroring how a cc/bcc copy carries no `To:`-header trace
// of its real envelope recipient.
function rawEmailBytes(
	to: string[],
	from = "sender@attacker.example",
	opts: { cc?: string[]; receivedFor?: string; receivedLines?: string[] } = {},
): Uint8Array {
	const received = opts.receivedLines
		? [...opts.receivedLines]
		: opts.receivedFor
			? [`from mx.example by route.mx.cloudflare.net with ESMTPS id deadbeef for <${opts.receivedFor}>; Wed, 18 Jun 2026 12:00:00 +0000`]
			: [];
	const lines: string[] = [];
	// Received headers are prepended at each hop; the FIRST line is the
	// most-recent (top) hop — the one Cloudflare stamps for this delivery.
	for (const r of received) lines.push(`Received: ${r}`);
	lines.push(`From: ${from}`);
	for (const a of to) lines.push(`To: ${a}`);
	for (const a of opts.cc ?? []) lines.push(`Cc: ${a}`);
	lines.push("Subject: test", "MIME-Version: 1.0", "Content-Type: text/plain", "", "body");
	return new TextEncoder().encode(lines.join("\r\n"));
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
		/** SMTP envelope recipient (RCPT TO) Cloudflare matched the routing rule on. */
		envelopeTo?: string;
		/** Cc addresses (land in parsedEmail.cc, not .to). */
		cc?: string[];
		/** Convenience: a CF-style top `Received: ... for <receivedFor>;` line. */
		receivedFor?: string;
		/** Full `Received:` header values, top-first, for multi-hop scenarios. */
		receivedLines?: string[];
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

	const bytes = rawEmailBytes(toAddresses, undefined, {
		cc: opts.cc,
		receivedFor: opts.receivedFor,
		receivedLines: opts.receivedLines,
	});
	const event = {
		raw: makeStream(bytes),
		rawSize: bytes.byteLength,
		...(opts.envelopeTo ? { to: opts.envelopeTo } : {}),
	};
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

describe("normalizeInbound — envelope recipient resolution", () => {
	// Regression: a message delivered to consulting@cortech.online (envelope
	// RCPT TO) whose visible `To:` header lists a different address first must
	// still be routed to the consulting mailbox. Previously the mailbox was
	// resolved from `To[0]` only, so any multi-recipient / bcc / list message
	// where the real recipient was not the first `To:` was silently dropped.
	it("delivers to the envelope recipient's mailbox even when it is not the first To: address", async () => {
		const result = await runNormalize(
			["someone-else@external.example", "consulting@cortech.online"],
			{
				emailAddresses: [],
				domains: "cortech.online",
				mailboxes: ["consulting@cortech.online"],
				envelopeTo: "consulting@cortech.online",
			},
		);
		expect(result?.kind).toBe("mailbox");
		if (result?.kind === "mailbox") {
			expect(result.mailboxId).toBe("consulting@cortech.online");
		}
	});

	it("delivers to the envelope recipient even when it is absent from the To: header (bcc)", async () => {
		const result = await runNormalize(
			["public-list@external.example"],
			{
				emailAddresses: [],
				domains: "cortech.online",
				mailboxes: ["consulting@cortech.online"],
				envelopeTo: "consulting@cortech.online",
			},
		);
		expect(result?.kind).toBe("mailbox");
		if (result?.kind === "mailbox") {
			expect(result.mailboxId).toBe("consulting@cortech.online");
		}
	});

	it("normalises envelope recipient casing/whitespace before the mailbox lookup", async () => {
		const result = await runNormalize(
			["someone-else@external.example"],
			{
				emailAddresses: [],
				domains: "cortech.online",
				mailboxes: ["consulting@cortech.online"],
				envelopeTo: "  Consulting@Cortech.Online ",
			},
		);
		expect(result?.kind).toBe("mailbox");
		if (result?.kind === "mailbox") {
			expect(result.mailboxId).toBe("consulting@cortech.online");
		}
	});

	it("falls through to catch-all when the envelope recipient has no mailbox", async () => {
		const result = await runNormalize(
			["whoever@external.example"],
			{
				emailAddresses: [],
				domains: "acme.example",
				mailboxes: [],
				envelopeTo: "probe@acme.example",
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

	it("with EMAIL_ADDRESSES set: matches the envelope recipient against the allow-list", async () => {
		const result = await runNormalize(
			["someone-else@external.example"],
			{
				emailAddresses: ["consulting@cortech.online"],
				mailboxes: ["consulting@cortech.online"],
				envelopeTo: "consulting@cortech.online",
			},
		);
		expect(result?.kind).toBe("mailbox");
		if (result?.kind === "mailbox") {
			expect(result.mailboxId).toBe("consulting@cortech.online");
		}
	});
});

describe("normalizeInbound — per-RCPT delivery via top Received header (GHSA-6jgg-fp96-7x3x)", () => {
	// Cloudflare Email Routing invokes email() once per SMTP envelope recipient
	// (RCPT TO). On the CF Email Sending → CF Email Routing cc/bcc/multi-recipient
	// path, event.to is NOT the distinct envelope recipient and collapses to the
	// To: header's first address, so a copy delivered for B was misfiled into A
	// (cc/bcc/secondary recipients silently lost mail; the bcc copy landing in A
	// is a cross-mailbox disclosure). The authoritative per-copy RCPT survives in
	// the TOP `Received: ... for <addr>` header Cloudflare stamps.

	it("To: A, Cc: B — the copy delivered for B is filed to B, not A", async () => {
		const result = await runNormalize(
			["support@cortech.online"],
			{
				emailAddresses: [],
				domains: "cortech.online",
				mailboxes: ["support@cortech.online", "inbox@cortech.online"],
				cc: ["inbox@cortech.online"],
				receivedFor: "inbox@cortech.online",
				// event.to collapses to the To: header's first address on this path.
				envelopeTo: "support@cortech.online",
			},
		);
		expect(result?.kind).toBe("mailbox");
		if (result?.kind === "mailbox") {
			expect(result.mailboxId).toBe("inbox@cortech.online");
		}
	});

	it("To: A, Cc: B — the copy delivered for A is still filed to A", async () => {
		const result = await runNormalize(
			["support@cortech.online"],
			{
				emailAddresses: [],
				domains: "cortech.online",
				mailboxes: ["support@cortech.online", "inbox@cortech.online"],
				cc: ["inbox@cortech.online"],
				receivedFor: "support@cortech.online",
				envelopeTo: "support@cortech.online",
			},
		);
		expect(result?.kind).toBe("mailbox");
		if (result?.kind === "mailbox") {
			expect(result.mailboxId).toBe("support@cortech.online");
		}
	});

	it("To: A, Bcc: C — the copy delivered for C is filed to C; A never receives it", async () => {
		// The bcc recipient is absent from To:/Cc: entirely; the only signal that
		// this copy belongs to C is the top Received header.
		const result = await runNormalize(
			["support@cortech.online"],
			{
				emailAddresses: [],
				domains: "cortech.online",
				mailboxes: ["support@cortech.online", "gh4all@cortech.online"],
				receivedFor: "gh4all@cortech.online",
				envelopeTo: "support@cortech.online",
			},
		);
		expect(result?.kind).toBe("mailbox");
		if (result?.kind === "mailbox") {
			expect(result.mailboxId).toBe("gh4all@cortech.online");
		}
	});

	it("To: [A, B] — the copy delivered for the second To address is filed to it", async () => {
		const result = await runNormalize(
			["support@cortech.online", "steptest@cortech.online"],
			{
				emailAddresses: [],
				domains: "cortech.online",
				mailboxes: ["support@cortech.online", "steptest@cortech.online"],
				receivedFor: "steptest@cortech.online",
				envelopeTo: "support@cortech.online",
			},
		);
		expect(result?.kind).toBe("mailbox");
		if (result?.kind === "mailbox") {
			expect(result.mailboxId).toBe("steptest@cortech.online");
		}
	});

	it("files into the envelope recipient (top Received) even when the To: header names a different provisioned mailbox", async () => {
		const result = await runNormalize(
			["x@cortech.online"],
			{
				emailAddresses: [],
				domains: "cortech.online",
				mailboxes: ["x@cortech.online", "y@cortech.online"],
				receivedFor: "y@cortech.online",
				envelopeTo: "x@cortech.online",
			},
		);
		expect(result?.kind).toBe("mailbox");
		if (result?.kind === "mailbox") {
			expect(result.mailboxId).toBe("y@cortech.online");
		}
	});

	it("fails closed (drops) when the envelope recipient has no mailbox even though the To: header names one", async () => {
		// Delivered for y@ (no mailbox, catch-all disabled); To: x@ (provisioned).
		// Must NOT misfile into x@.
		const result = await runNormalize(
			["x@cortech.online"],
			{
				emailAddresses: [],
				domains: "cortech.online",
				mailboxes: ["x@cortech.online"],
				receivedFor: "y@cortech.online",
				envelopeTo: "x@cortech.online",
				domainSettings: { "cortech.online": {} },
			},
		);
		expect(result).toBeNull();
	});

	it("EMAIL_ADDRESSES allow-list: the copy for B is matched against B, not the To: header A", async () => {
		const result = await runNormalize(
			["support@cortech.online"],
			{
				emailAddresses: ["support@cortech.online", "inbox@cortech.online"],
				mailboxes: ["support@cortech.online", "inbox@cortech.online"],
				cc: ["inbox@cortech.online"],
				receivedFor: "inbox@cortech.online",
				envelopeTo: "support@cortech.online",
			},
		);
		expect(result?.kind).toBe("mailbox");
		if (result?.kind === "mailbox") {
			expect(result.mailboxId).toBe("inbox@cortech.online");
		}
	});

	it("uses only the TOP Received header's for-clause; a forged lower Received cannot redirect delivery", async () => {
		const result = await runNormalize(
			["x@cortech.online"],
			{
				emailAddresses: [],
				domains: "cortech.online",
				mailboxes: ["x@cortech.online", "real@cortech.online", "attacker@cortech.online"],
				receivedLines: [
					// TOP — stamped by Cloudflare for the actual RCPT.
					"from mx by route.mx.cloudflare.net with ESMTPS id aa for <real@cortech.online>; Wed, 18 Jun 2026 12:00:00 +0000",
					// LOWER — forged upstream to try to grab attacker@'s mailbox.
					"from evil by relay.example with ESMTP id bb for <attacker@cortech.online>; Wed, 18 Jun 2026 11:59:00 +0000",
				],
				envelopeTo: "x@cortech.online",
			},
		);
		expect(result?.kind).toBe("mailbox");
		if (result?.kind === "mailbox") {
			expect(result.mailboxId).toBe("real@cortech.online");
		}
	});

	it("falls back to event.to when the top Received has no for-clause, ignoring a lower Received for-clause", async () => {
		const result = await runNormalize(
			["x@cortech.online"],
			{
				emailAddresses: [],
				domains: "cortech.online",
				mailboxes: ["x@cortech.online", "attacker@cortech.online"],
				receivedLines: [
					// TOP — no `for` clause (some CF paths omit it).
					"from mx by route.mx.cloudflare.net with ESMTPS id aa; Wed, 18 Jun 2026 12:00:00 +0000",
					// LOWER — forged for attacker@.
					"from evil by relay.example with ESMTP id bb for <attacker@cortech.online>; Wed, 18 Jun 2026 11:59:00 +0000",
				],
				envelopeTo: "x@cortech.online",
			},
		);
		expect(result?.kind).toBe("mailbox");
		if (result?.kind === "mailbox") {
			expect(result.mailboxId).toBe("x@cortech.online");
		}
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
