// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it, vi } from "vitest";
import {
	applyBlockedOutcome,
	matchBlocklist,
	normalizeSenderAddress,
	ruleMatches,
	safeMatchBlocklist,
	type TierInputs,
} from "../../workers/security/blocklist";

const rule = (id: string, match: string, action: "drop" | "reject" | "spam") => ({ id, match, action, created_at: "t" });

describe("normalizeSenderAddress", () => {
	it("lowercases, trims and A-labels the domain", () => {
		expect(normalizeSenderAddress(" Noreply@RES.PodView.com ")).toBe("noreply@res.podview.com");
		expect(normalizeSenderAddress("a@bücher.example")).toBe("a@xn--bcher-kva.example");
	});
	it("returns null for missing or malformed", () => {
		expect(normalizeSenderAddress(undefined)).toBeNull();
		expect(normalizeSenderAddress("")).toBeNull();
		expect(normalizeSenderAddress("no-at-sign")).toBeNull();
	});
});

describe("ruleMatches", () => {
	it("matches address exactly and domain + subdomains, never parents", () => {
		expect(ruleMatches("noreply@res.podview.com", "noreply@res.podview.com")).toBe("address");
		expect(ruleMatches("podview.com", "noreply@res.podview.com")).toBe("domain");
		expect(ruleMatches("res.podview.com", "x@podview.com")).toBeNull();
		expect(ruleMatches("podview.com", "x@notpodview.com")).toBeNull();
	});
});

describe("matchBlocklist", () => {
	it("returns null with no rules or no sender", () => {
		expect(matchBlocklist({}, "a@b.com")).toBeNull();
		expect(matchBlocklist({ mailbox: { blocklist: [rule("1", "b.com", "drop")] } }, undefined)).toBeNull();
	});
	it("most specific tier wins", () => {
		const tiers: TierInputs = {
			org: { blocklist: [rule("o", "podview.com", "reject")] },
			mailbox: { blocklist: [rule("m", "podview.com", "spam")] },
		};
		expect(matchBlocklist(tiers, "x@podview.com")).toMatchObject({ tier: "mailbox", rule: { id: "m" } });
	});
	it("address beats domain within a tier, then strictest action", () => {
		const tiers: TierInputs = {
			mailbox: { blocklist: [rule("d", "podview.com", "reject"), rule("a", "x@podview.com", "spam")] },
		};
		expect(matchBlocklist(tiers, "x@podview.com")?.rule.id).toBe("a");
		const tie: TierInputs = { mailbox: { blocklist: [rule("s", "podview.com", "spam"), rule("r", "podview.com", "reject")] } };
		expect(matchBlocklist(tie, "x@podview.com")?.rule.id).toBe("r");
	});
	it("an allowlist entry suppresses only from a strictly more specific tier", () => {
		const orgBlock = { blocklist: [rule("o", "podview.com", "drop")] };
		expect(matchBlocklist({ org: orgBlock, mailbox: { allowlist_senders: ["x@podview.com"] } }, "x@podview.com")).toBeNull();
		expect(matchBlocklist({ org: { ...orgBlock, allowlist_domains: ["podview.com"] } }, "x@podview.com")?.rule.id).toBe("o");
		expect(matchBlocklist({ mailbox: { blocklist: [rule("m", "podview.com", "drop")] }, org: { allowlist_domains: ["podview.com"] } }, "x@podview.com")?.rule.id).toBe("m");
	});
	it("matches mixed-case and Unicode senders", () => {
		const tiers: TierInputs = { mailbox: { blocklist: [rule("1", "xn--bcher-kva.example", "drop"), rule("2", "noreply@res.podview.com", "drop")] } };
		expect(matchBlocklist(tiers, "Sales@BÜCHER.example")?.rule.id).toBe("1");
		expect(matchBlocklist(tiers, "NoReply@Res.PodView.com ")?.rule.id).toBe("2");
	});
});

describe("safeMatchBlocklist", () => {
	it("reads tiers off resolved settings and tolerates missing tiers", () => {
		expect(safeMatchBlocklist({ raw: {} }, "a@b.com")).toBeNull();
		expect(safeMatchBlocklist({ raw: { blocklist: [rule("1", "b.com", "drop")] } }, "a@b.com")).toMatchObject({ tier: "mailbox" });
	});
	it("fails open on malformed settings", () => {
		expect(safeMatchBlocklist({ raw: { blocklist: "nope" } }, "a@b.com")).toBeNull();
	});
});

describe("applyBlockedOutcome", () => {
	it("calls setReject once for reject and never otherwise", () => {
		const setReject = vi.fn();
		applyBlockedOutcome({ setReject }, { blocked: { action: "reject", ruleId: "r", tier: "mailbox", reason: "Go away" } });
		expect(setReject).toHaveBeenCalledExactlyOnceWith("Go away");
		setReject.mockClear();
		applyBlockedOutcome({ setReject }, { blocked: { action: "drop", ruleId: "r", tier: "mailbox" } });
		applyBlockedOutcome({ setReject }, null);
		expect(setReject).not.toHaveBeenCalled();
	});
});
