// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Stateful send-risk rules (follow-up to #15): attachment classes, recipient
 * history, opt-in established-correspondent trust, lookalike recipient
 * domains, flagged-thread replies, and link checks. `classifySend` stays
 * pure — each case hands it a precomputed `context`.
 */

import { describe, expect, it } from "vitest";
import {
	classifySend,
	lookalikeAnchor,
	type ClassifySendInput,
	type SendRiskContext,
} from "../../workers/security/send-risk";

const NOW = Date.parse("2026-09-26T12:00:00.000Z");
const DAY = 24 * 60 * 60 * 1000;
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString();

function make(overrides: Partial<ClassifySendInput> = {}, context?: SendRiskContext): ClassifySendInput {
	return {
		to: "vendor@acme.example",
		mailboxId: "operator@internal.example",
		subject: "Invoice",
		body: "Attached is the invoice.",
		...overrides,
		...(context ? { context: { now: NOW, ...context } } : {}),
	};
}

/** History for an address that satisfies every established-correspondent threshold. */
const established = { send_count: 5, first_sent: iso(90 * DAY), last_sent: iso(2 * DAY) };

describe("attachments reuse the inbound extension classes", () => {
	it.each([
		["setup.exe", 2],
		["invoice.pdf.exe", 2],
		["payroll.xlsm", 1],
		["disk.iso", 1],
		["report.pdf", 0],
	] as const)("%s → tier %i", (filename, tier) => {
		const r = classifySend(make({ to: "colleague@internal.example", attachments: [{ filename }] }));
		expect(r.tier).toBe(tier);
	});

	it("treats the operator's custom blocklist as executable", () => {
		const r = classifySend(
			make({ to: "colleague@internal.example", attachments: [{ filename: "tool.zip" }] }, { customBlockedExtensions: [".ZIP"] }),
		);
		expect(r.tier).toBe(2);
		expect(r.reasons).toContain('Suspicious attachment extension: "tool.zip"');
	});
});

describe("recipient history", () => {
	it("names first-time external recipients without changing the tier", () => {
		const r = classifySend(make({}, { recipientHistory: {} }));
		expect(r.tier).toBe(1);
		expect(r.reasons).toContain("First-time recipient(s): vendor@acme.example");
	});

	it("does not call a previously sent-to recipient first-time", () => {
		const r = classifySend(make({}, { recipientHistory: { "vendor@acme.example": established } }));
		expect(r.reasons.some((x) => x.startsWith("First-time"))).toBe(false);
	});

	it("makes no first-time claim when history is unavailable", () => {
		const r = classifySend(make({}, {}));
		expect(r.reasons.some((x) => x.startsWith("First-time"))).toBe(false);
	});
});

describe("established-correspondent trust (opt-in)", () => {
	const trustCtx = (history: SendRiskContext["recipientHistory"]): SendRiskContext => ({
		recipientHistory: history,
		trustKnownRecipients: true,
	});

	it("lets an established external recipient through at tier 0 and records why", () => {
		const r = classifySend(make({}, trustCtx({ "vendor@acme.example": established })));
		expect(r.tier).toBe(0);
		expect(r.reasons).toEqual(["External recipient(s) are established correspondents: vendor@acme.example"]);
	});

	it("does nothing unless the setting is on", () => {
		const r = classifySend(make({}, { recipientHistory: { "vendor@acme.example": established } }));
		expect(r.tier).toBe(1);
	});

	it("never applies to agent-authored drafts", () => {
		const r = classifySend(make({ createdBy: "agent" }, trustCtx({ "vendor@acme.example": established })));
		expect(r.tier).toBe(2);
	});

	it("requires every external recipient to be established", () => {
		const r = classifySend(
			make({ to: ["vendor@acme.example", "new@other.example"] }, trustCtx({ "vendor@acme.example": established })),
		);
		expect(r.tier).toBe(1);
	});

	it.each([
		["only one prior send", { ...established, send_count: 1 }],
		["first send under 7 days ago", { ...established, first_sent: iso(3 * DAY) }],
		["not written to for over a year", { ...established, last_sent: iso(400 * DAY) }],
		["unparseable dates", { ...established, first_sent: "garbage" }],
	])("is withheld with %s", (_label, history) => {
		expect(classifySend(make({}, trustCtx({ "vendor@acme.example": history }))).tier).toBe(1);
	});

	it("still applies every other rule", () => {
		const r = classifySend(make({ body: "Please update the bank details" }, trustCtx({ "vendor@acme.example": established })));
		expect(r.tier).toBe(2);
	});
});

describe("lookalike recipient domains", () => {
	const ctx = (extra: Partial<SendRiskContext> = {}): SendRiskContext => ({
		domainSendCounts: {},
		knownDomains: ["acme-corp.com"],
		...extra,
	});

	it("flags a one-character swap of a known correspondent's domain", () => {
		const r = classifySend(make({ to: "ap@acme-c0rp.com" }, ctx()));
		expect(r.tier).toBe(2);
		expect(r.reasons).toContain('Recipient domain "acme-c0rp.com" resembles "acme-corp.com"');
	});

	it("flags an rn→m confusable", () => {
		expect(classifySend(make({ to: "ap@acrne-corp.com" }, ctx())).tier).toBe(2);
	});

	it("flags the mailbox's own name under another suffix", () => {
		const r = classifySend(
			make({ to: "principal@riverdaleschools.com", mailboxId: "office@riverdaleschools.org" }, ctx({ knownDomains: [] })),
		);
		expect(r.tier).toBe(2);
		expect(r.reasons).toContain('Recipient domain "riverdaleschools.com" resembles "riverdaleschools.org"');
	});

	it("does not re-flag a domain the mailbox has already sent to", () => {
		const r = classifySend(make({ to: "ap@acme-c0rp.com" }, ctx({ domainSendCounts: { "acme-c0rp.com": 1 } })));
		expect(r.tier).toBe(1);
	});

	it.each([
		["an unrelated domain", "someone@vendor.example"],
		["a subdomain of a known domain", "ap@billing.acme-corp.com"],
	])("leaves %s alone", (_label, to) => {
		expect(classifySend(make({ to }, ctx())).tier).toBe(1);
	});

	it("does not run without history", () => {
		expect(classifySend(make({ to: "ap@acme-c0rp.com" })).tier).toBe(1);
	});
});

describe("lookalikeAnchor", () => {
	it("ignores near-misses between short domains", () => {
		expect(lookalikeAnchor("ac.io", ["ab.io"], "internal.example")).toBeNull();
	});

	it("allows distance 2 only for long domains", () => {
		expect(lookalikeAnchor("contoso-bnak.com", ["contoso-bank.com"], "x.example")).toBe("contoso-bank.com");
		expect(lookalikeAnchor("abcd.com", ["abxy.com"], "x.example")).toBeNull();
	});

	it("catches confusables that edit distance alone would miss on a short domain", () => {
		// "acrne.io" is distance 2 from "acme.io" — below the long-domain bar.
		expect(lookalikeAnchor("acrne.io", ["acme.io"], "x.example")).toBe("acme.io");
		expect(lookalikeAnchor("g00gle.io", ["google.io"], "x.example")).toBe("google.io");
	});
});

describe("replying to or forwarding a flagged message", () => {
	it.each([
		[{ action: "quarantine" }, "quarantined"],
		[{ action: "block" }, "blocked"],
		[{ action: "tag", label: "bec" }, "bec"],
		[{ action: "allow", label: "phishing" }, "phishing"],
	])("%o with an external recipient → tier 2", (thread, flaggedAs) => {
		const r = classifySend(make({}, { thread }));
		expect(r.tier).toBe(2);
		expect(r.reasons).toContain(`Reply or forward of a message flagged as ${flaggedAs}`);
	});

	it("is tier 1 when every recipient is internal", () => {
		expect(classifySend(make({ to: "soc@internal.example" }, { thread: { action: "quarantine" } })).tier).toBe(1);
	});

	it("a tagged thread keeps an external send at tier 1 even for trusted correspondents", () => {
		const r = classifySend(
			make({}, {
				thread: { action: "tag", label: "suspicious" },
				recipientHistory: { "vendor@acme.example": established },
				trustKnownRecipients: true,
			}),
		);
		expect(r.tier).toBe(1);
		expect(r.reasons).toContain("Reply or forward of a message tagged suspicious");
	});

	it("ignores a tagged thread for internal-only sends and a clean verdict entirely", () => {
		expect(classifySend(make({ to: "soc@internal.example" }, { thread: { action: "tag" } })).tier).toBe(0);
		expect(classifySend(make({ to: "soc@internal.example" }, { thread: { action: "allow", label: "safe" } })).reasons).toEqual([]);
	});
});

describe("links", () => {
	it("a confirmed threat-intel hit is tier 2, a bloom-only hit tier 1", () => {
		const internal = { to: "soc@internal.example" };
		expect(
			classifySend(make(internal, { feedHits: [{ host: "evil.example", feedId: "openphish", confirmed: true }] })),
		).toEqual({ tier: 2, reasons: ["Link on threat-intel feed: evil.example (openphish)"] });
		expect(
			classifySend(make(internal, { feedHits: [{ host: "evil.example", feedId: "openphish", confirmed: false }] })).tier,
		).toBe(1);
	});

	it("a lookalike link is tier 1 even without context", () => {
		const r = classifySend(make({ to: "soc@internal.example", body: '<a href="https://paypa1.com/login">PayPal</a>' }));
		expect(r.tier).toBe(1);
		expect(r.reasons).toContain("Lookalike or internationalized link: paypa1.com");
	});
});
