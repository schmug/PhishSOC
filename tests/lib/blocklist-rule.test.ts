// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	DEFAULT_REJECT_REASON,
	isPublicSuffix,
	normalizeMatch,
	registrableDomain,
	sanitizeRejectReason,
	validateBlockRuleInput,
} from "../../shared/blocklist";

describe("normalizeMatch", () => {
	it("lowercases and trims an address", () => {
		expect(normalizeMatch("  Noreply@RES.PodView.com ")).toEqual({ kind: "address", value: "noreply@res.podview.com" });
	});
	it("treats a bare host as a domain", () => {
		expect(normalizeMatch("PodView.com")).toEqual({ kind: "domain", value: "podview.com" });
	});
	it("converts a Unicode domain to its A-label", () => {
		expect(normalizeMatch("bücher.example")).toEqual({ kind: "domain", value: "xn--bcher-kva.example" });
		expect(normalizeMatch("a@bücher.example")).toEqual({ kind: "address", value: "a@xn--bcher-kva.example" });
	});
	it("rejects garbage", () => {
		for (const bad of ["", "@", "a@", "@x.com", "a b@x.com", "x.com/path", "a@@x.com", "http://x.com"]) {
			expect(normalizeMatch(bad), bad).toBeNull();
		}
	});
});

describe("isPublicSuffix / registrableDomain", () => {
	it("flags single labels and multi-label suffixes", () => {
		expect(isPublicSuffix("com")).toBe(true);
		expect(isPublicSuffix("co.uk")).toBe(true);
		expect(isPublicSuffix("podview.com")).toBe(false);
	});
	it("returns the registrable domain", () => {
		expect(registrableDomain("res.podview.com")).toBe("podview.com");
		expect(registrableDomain("mail.foo.co.uk")).toBe("foo.co.uk");
		expect(registrableDomain("podview.com")).toBe("podview.com");
	});
});

describe("sanitizeRejectReason", () => {
	it("defaults when empty", () => {
		expect(sanitizeRejectReason(undefined)).toBe(DEFAULT_REJECT_REASON);
		expect(sanitizeRejectReason("   ")).toBe(DEFAULT_REJECT_REASON);
	});
	it("strips CR/LF and control chars, drops non-ASCII, caps at 200", () => {
		expect(sanitizeRejectReason("Stop\r\n250 OK\tnow")).toBe("Stop250 OKnow");
		expect(sanitizeRejectReason("héllo")).toBe("hllo");
		expect(sanitizeRejectReason("x".repeat(300))).toHaveLength(200);
	});
});

describe("validateBlockRuleInput", () => {
	it("accepts an address rule", () => {
		const r = validateBlockRuleInput({ match: "noreply@res.podview.com", action: "spam" });
		expect(r).toEqual({ ok: true, rule: { match: "noreply@res.podview.com", action: "spam" } });
	});
	it("sanitizes the reason only for reject", () => {
		const r = validateBlockRuleInput({ match: "podview.com", action: "reject", reason: "Go away\r\n" });
		expect(r).toEqual({ ok: true, rule: { match: "podview.com", action: "reject", reason: "Go away" } });
		const s = validateBlockRuleInput({ match: "podview.com", action: "drop", reason: "ignored" });
		expect(s).toEqual({ ok: true, rule: { match: "podview.com", action: "drop" } });
	});
	it("refuses a public suffix", () => {
		expect(validateBlockRuleInput({ match: "co.uk", action: "drop" })).toMatchObject({ ok: false, code: "public_suffix" });
	});
	it("requires confirmation for a shared domain but not for an address on it", () => {
		expect(validateBlockRuleInput({ match: "gmail.com", action: "drop" })).toMatchObject({ ok: false, code: "shared_domain_unconfirmed" });
		expect(validateBlockRuleInput({ match: "gmail.com", action: "drop", confirm_shared_domain: true })).toMatchObject({ ok: true });
		expect(validateBlockRuleInput({ match: "spammer@gmail.com", action: "drop" })).toMatchObject({ ok: true });
	});
	it("refuses an unknown action", () => {
		expect(validateBlockRuleInput({ match: "a@b.com", action: "nuke" as never })).toMatchObject({ ok: false, code: "invalid_action" });
	});
});
