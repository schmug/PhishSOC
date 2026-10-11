// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, it, expect, afterEach } from "vitest";
import {
	OWN_DOMAIN_LOOKALIKE_MAX_SCORE,
	scoreOwnDomainLookalike,
} from "../../workers/security/own-domain-lookalike";
import { runSecurityPipeline } from "../../workers/security/index";
import { __setClassifier } from "../../workers/security/classification";
import { createFakeMailboxStub, makeFakeEnv } from "./fakes";

afterEach(() => {
	__setClassifier(null);
});

const score = (senderDomain: string, linkHosts: string[] = []) =>
	scoreOwnDomainLookalike({
		senderDomains: [senderDomain],
		linkHosts,
		anchors: ["acme.com"],
		mailboxDomain: "acme.com",
	});

describe("scoreOwnDomainLookalike — sender", () => {
	it.each([
		["acme-hr.com", "acme-hr.com"],
		["acrne.com", "acrne.com"],
		["acme.co", "acme.co"],
		["Cyrillic а", "аcme.com"],
		["punycode Cyrillic а", "xn--cme-5cd.com"],
	])("flags %s", (_label, domain) => {
		const r = score(domain);
		expect(r.score).toBeGreaterThan(0);
		expect(r.score).toBeLessThanOrEqual(OWN_DOMAIN_LOOKALIKE_MAX_SCORE);
		expect(r.reason).toBe(`Sender domain "${domain}" resembles your domain "acme.com"`);
	});

	it.each(["acme.com", "mail.acme.com", "vendor-unrelated.org"])("does not flag %s", (domain) => {
		expect(score(domain)).toEqual({ score: 0 });
	});

	it("does not flag a subdomain of another configured org domain", () => {
		const r = scoreOwnDomainLookalike({
			senderDomains: ["mail.acme-group.com"],
			linkHosts: [],
			anchors: ["acme.com", "acme-group.com"],
			mailboxDomain: "acme.com",
		});
		expect(r.score).toBe(0);
	});

	it("matches against any configured org domain, not only the mailbox's", () => {
		const r = scoreOwnDomainLookalike({
			senderDomains: ["contoso-bnak.com"],
			linkHosts: [],
			anchors: ["acme.com", "contoso-bank.com"],
			mailboxDomain: "acme.com",
		});
		expect(r.reason).toBe('Sender domain "contoso-bnak.com" resembles your domain "contoso-bank.com"');
	});
});

describe("scoreOwnDomainLookalike — links", () => {
	it("flags a lookalike link host with the link reason", () => {
		const r = score("vendor.example", ["login.acrne.com"]);
		expect(r.score).toBeGreaterThan(0);
		expect(r.score).toBeLessThanOrEqual(OWN_DOMAIN_LOOKALIKE_MAX_SCORE);
		expect(r.reason).toBe('Link domain "login.acrne.com" resembles your domain "acme.com"');
	});

	it("ignores links to the org's own domain and unrelated hosts", () => {
		expect(score("vendor.example", ["acme.com", "portal.acme.com", "example.org"]).score).toBe(0);
	});
});

// ── Pipeline integration ─────────────────────────────────────────────────────

const MAILBOX = "soc@acme.com";

function email(address: string, html = "<p>Hello</p>") {
	return {
		subject: "Hi",
		from: { address, name: "Someone" },
		html,
		headers: {},
		attachments: [],
	};
}

async function run(
	address: string,
	opts: { html?: string; detectors?: Record<string, unknown> } = {},
) {
	__setClassifier(async () => ({ label: "safe" as const, confidence: 0.9, reasoning: "stubbed" }));
	const { stub } = createFakeMailboxStub();
	const env = makeFakeEnv({
		mailboxId: MAILBOX,
		stub,
		settings: { enabled: true, ...(opts.detectors ? { detectors: opts.detectors } : {}) },
	});
	return runSecurityPipeline({
		env,
		mailboxId: MAILBOX,
		messageId: `m-${address}`,
		targetFolder: "inbox",
		parsedEmail: email(address, opts.html),
	});
}

describe("runSecurityPipeline — own-domain lookalike", () => {
	it.each(["ceo@acme-hr.com", "ceo@acrne.com", "ceo@acme.co", "ceo@аcme.com"])(
		"flags sender %s",
		async (address) => {
			const r = await run(address);
			expect(r.verdict?.signals.join(" ")).toMatch(/Sender domain ".+" resembles your domain "acme.com"/);
			const url = r.stageTrace.find((s) => s.stage === "url");
			expect(url?.score_contrib).toBeGreaterThan(0);
			expect(url?.score_contrib).toBeLessThanOrEqual(OWN_DOMAIN_LOOKALIKE_MAX_SCORE);
		},
	);

	it.each(["ceo@acme.com", "ceo@mail.acme.com", "ceo@unrelated-vendor.org"])(
		"does not flag sender %s",
		async (address) => {
			const r = await run(address);
			expect(r.verdict?.signals.join(" ")).not.toMatch(/resembles your domain/);
		},
	);

	it("flags a lookalike link in the body", async () => {
		const r = await run("ceo@unrelated-vendor.org", {
			html: '<a href="https://acme-hr.com/login">Sign in</a>',
		});
		expect(r.verdict?.signals.join(" ")).toMatch(/Link domain "acme-hr.com" resembles your domain "acme.com"/);
	});

	it("fires nothing when the detector is toggled off", async () => {
		const r = await run("ceo@acrne.com", {
			html: '<a href="https://acme-hr.com/login">Sign in</a>',
			detectors: { own_domain_lookalike: { enabled: false } },
		});
		expect(r.verdict?.signals.join(" ")).not.toMatch(/resembles your domain/);
	});
});
