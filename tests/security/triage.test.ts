import { describe, expect, it } from "vitest";
import PostalMime from "postal-mime";
import { evaluateTriage } from "../../workers/security/triage";
import { DEFAULT_SECURITY_SETTINGS } from "../../workers/security/settings";
import { parseAuthResults, type AuthVerdict } from "../../workers/security/auth";

// A DMARC pass from a trusted authserv-id (verdict.trusted set by
// parseAuthResults when a configured allowlist matched). Hard-allow requires
// this; see the F-004 regression test below.
const dmarcPass: AuthVerdict = { spf: "pass", dkim: "pass", dmarc: "pass", trusted: true };
// A trusted DMARC pass that also reports the evaluated From domain — what
// Cloudflare Email Routing emits on every dmarc=pass. Hard-allow now requires
// header.from (fail closed), so allowlist tests must carry the domain they match.
const dmarcPassFrom = (headerFrom: string): AuthVerdict => ({ ...dmarcPass, headerFrom });
// A DMARC pass that is NOT from a trusted authserv-id (e.g. a forged header on
// a deployment with no trustedAuthservIds configured).
const dmarcPassUntrusted: AuthVerdict = { spf: "pass", dkim: "pass", dmarc: "pass" };
const dmarcFail: AuthVerdict = { spf: "fail", dkim: "fail", dmarc: "fail" };

const baseSettings = {
	...DEFAULT_SECURITY_SETTINGS,
	enabled: true,
	trusted_auto_allow: true,
	intel_auto_block: true,
};

const baseInputs = {
	urls: [],
	targetFolder: "INBOX",
	attachments: [],
};

describe("evaluateTriage — hard block", () => {
	it("quarantines on confirmed intel hit regardless of sender trust", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "ceo@trusted.com",
			auth: dmarcPass,
			reputation: null,
			intelMatch: { matched: true, feedId: "urlhaus", value: "bad.example", confirmed: true },
			settings: { ...baseSettings, allowlist_senders: ["ceo@trusted.com"] },
		});
		expect(r.shortcircuit?.tier).toBe("hard_block");
		expect(r.shortcircuit?.verdict.action).toBe("quarantine");
	});

	it("does NOT hard-block on unconfirmed (bloom-only) intel hit", () => {
		// Bloom FPR is ~1% — we never act on an unconfirmed hit alone.
		const r = evaluateTriage({
			...baseInputs,
			sender: "x@y.com",
			auth: dmarcFail,
			reputation: null,
			intelMatch: { matched: true, feedId: "f", value: "v", confirmed: false },
			settings: baseSettings,
		});
		expect(r.shortcircuit).toBeUndefined();
	});

	it("does NOT hard-block on a derived intel match", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "x@y.com",
			auth: dmarcFail,
			reputation: null,
			intelMatch: { matched: true, feedId: "f", value: "https://phish.example/login", confirmed: false, derived: true },
			settings: baseSettings,
		});
		expect(r.shortcircuit).toBeUndefined();
	});

	it("hard-blocks a sender that's been flagged on this mailbox", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "x@y.com",
			auth: dmarcPass,
			reputation: {
				sender: "x@y.com",
				first_seen: "",
				last_seen: "",
				message_count: 2,
				avg_score: 40,
				flagged: true,
			},
			intelMatch: null,
			settings: baseSettings,
		});
		expect(r.shortcircuit?.tier).toBe("hard_block");
	});

	it("is disabled when intel_auto_block is off", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "x@y.com",
			auth: dmarcFail,
			reputation: null,
			intelMatch: { matched: true, feedId: "urlhaus", value: "v", confirmed: true },
			settings: { ...baseSettings, intel_auto_block: false },
		});
		expect(r.shortcircuit).toBeUndefined();
	});
});

describe("evaluateTriage — hard allow", () => {
	it("requires DMARC pass even for an explicit allowlist match", () => {
		// Critical invariant: allowlist alone is insufficient.
		const r = evaluateTriage({
			...baseInputs,
			sender: "ceo@trusted.com",
			auth: dmarcFail,
			reputation: null,
			intelMatch: null,
			settings: { ...baseSettings, allowlist_senders: ["ceo@trusted.com"] },
		});
		expect(r.shortcircuit).toBeUndefined();
	});

	it("allows on explicit sender allowlist + DMARC pass", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "ceo@trusted.com",
			auth: dmarcPassFrom("trusted.com"),
			reputation: null,
			intelMatch: null,
			settings: { ...baseSettings, allowlist_senders: ["ceo@trusted.com"] },
		});
		expect(r.shortcircuit?.tier).toBe("hard_allow");
		expect(r.shortcircuit?.verdict.action).toBe("allow");
	});

	it("does NOT hard-allow a forged/untrusted DMARC pass, even with an allowlist match", () => {
		// F-004: with no trustedAuthservIds configured, parseAuthResults leaves
		// verdict.trusted falsy. A forged Authentication-Results header claiming
		// dmarc=pass must not reach hard-allow and skip the rest of the pipeline.
		const r = evaluateTriage({
			...baseInputs,
			sender: "ceo@trusted.com",
			auth: dmarcPassUntrusted,
			reputation: null,
			intelMatch: null,
			settings: { ...baseSettings, allowlist_senders: ["ceo@trusted.com"] },
		});
		expect(r.shortcircuit).toBeUndefined();
	});

	it("allows on explicit domain allowlist + DMARC pass (exact)", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "anyone@trusted.com",
			auth: dmarcPassFrom("trusted.com"),
			reputation: null,
			intelMatch: null,
			settings: { ...baseSettings, allowlist_domains: ["trusted.com"] },
		});
		expect(r.shortcircuit?.tier).toBe("hard_allow");
	});

	it("allows subdomains of allowlisted domains", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "bot@mail.trusted.com",
			auth: dmarcPassFrom("mail.trusted.com"),
			reputation: null,
			intelMatch: null,
			settings: { ...baseSettings, allowlist_domains: ["trusted.com"] },
		});
		expect(r.shortcircuit?.tier).toBe("hard_allow");
	});

	it("allows on history-based trust when min_messages threshold met", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "colleague@work.com",
			auth: dmarcPassFrom("work.com"),
			reputation: {
				sender: "colleague@work.com",
				first_seen: "",
				last_seen: "",
				message_count: 50,
				avg_score: 5,
				flagged: false,
			},
			intelMatch: null,
			settings: { ...baseSettings, trusted_auto_allow_min_messages: 10 },
		});
		expect(r.shortcircuit?.tier).toBe("hard_allow");
	});

	it("does not history-allow a flagged sender even if message_count is high", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "colleague@work.com",
			auth: dmarcPass,
			reputation: {
				sender: "colleague@work.com",
				first_seen: "",
				last_seen: "",
				message_count: 100,
				avg_score: 80,
				flagged: true,
			},
			intelMatch: null,
			settings: { ...baseSettings, trusted_auto_allow_min_messages: 10 },
		});
		// hard_block tier (because flagged) trumps hard_allow
		expect(r.shortcircuit?.tier).toBe("hard_block");
	});

	it("returns no short-circuit when neither tier applies", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "stranger@nowhere.com",
			auth: dmarcPass,
			reputation: null,
			intelMatch: null,
			settings: baseSettings,
		});
		expect(r.shortcircuit).toBeUndefined();
	});
});

// Hard-allow must only trust the domain that DMARC actually evaluated. These
// run real MIME through postal-mime + parseAuthResults (the pipeline's own
// path) so the From-parsing behaviour is pinned, not assumed.
describe("evaluateTriage — hard allow binds to the DMARC-evaluated From domain", () => {
	const trusted = ["mx.cloudflare.net"];
	const ar = (headerFrom: string | null) =>
		`Authentication-Results: mx.cloudflare.net; dkim=pass header.d=sender.example header.s=s1; dmarc=pass${headerFrom ? ` header.from=${headerFrom}` : ""}; spf=pass smtp.mailfrom=b@sender.example\r\n`;

	async function triageRaw(
		fromHeaders: string,
		opts: { headerFrom?: string | null; settings?: Partial<typeof baseSettings>; historyCount?: number } = {},
	) {
		const raw = `${ar(opts.headerFrom === undefined ? "sender.example" : opts.headerFrom)}${fromHeaders}To: me@mailbox.example\r\nSubject: t\r\n\r\nbody\r\n`;
		const parsed = await PostalMime.parse(raw);
		const sender = (parsed.from?.address || "").toLowerCase();
		const auth = parseAuthResults(parsed.headers, { trustedAuthservIds: trusted });
		return evaluateTriage({
			...baseInputs,
			sender,
			auth,
			reputation: opts.historyCount
				? { sender, first_seen: "", last_seen: "", message_count: opts.historyCount, avg_score: 0, flagged: false }
				: null,
			intelMatch: null,
			settings: { ...baseSettings, allowlist_domains: ["allowed.example"], ...opts.settings },
		});
	}

	it.each([
		['From: "ceo@allowed.example"@sender.example\r\n'],
		["From: Name <a@allowed.example> <b@sender.example>\r\n"],
		["From: a@allowed.example, b@sender.example\r\n"],
		["From: b@sender.example\r\nFrom: a@allowed.example\r\n"],
		["From: <ceo@allowed.example>@sender.example\r\n"],
	])("does not hard-allow %j when DMARC evaluated a different domain", async (from) => {
		const r = await triageRaw(from);
		expect(r.shortcircuit).toBeUndefined();
	});

	it("does not sender-allowlist an address whose domain DMARC did not evaluate", async () => {
		const r = await triageRaw("From: Name <a@allowed.example> <b@sender.example>\r\n", {
			settings: { allowlist_domains: [], allowlist_senders: ["a@allowed.example"] },
		});
		expect(r.shortcircuit).toBeUndefined();
	});

	it("does not history-allow an address whose domain DMARC did not evaluate", async () => {
		const r = await triageRaw("From: Name <a@allowed.example> <b@sender.example>\r\n", {
			settings: { allowlist_domains: [], trusted_auto_allow_min_messages: 10 },
			historyCount: 50,
		});
		expect(r.shortcircuit).toBeUndefined();
	});

	it("does not hard-allow a multi-@ address when the authserv reports no header.from", async () => {
		const r = await triageRaw('From: "ceo@allowed.example"@sender.example\r\n', { headerFrom: null });
		expect(r.shortcircuit).toBeUndefined();
	});

	it("still hard-allows an allowlisted sender whose domain DMARC evaluated", async () => {
		const r = await triageRaw("From: Someone <user@allowed.example>\r\n", { headerFrom: "allowed.example" });
		expect(r.shortcircuit?.tier).toBe("hard_allow");
	});

	it("still hard-allows a subdomain of an allowlisted domain", async () => {
		const r = await triageRaw("From: user@mail.allowed.example\r\n", { headerFrom: "mail.allowed.example" });
		expect(r.shortcircuit?.tier).toBe("hard_allow");
	});
});

describe("evaluateTriage — attachment block", () => {
	it("quarantines on an executable attachment under the default policy", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "whoever@example.com",
			auth: dmarcFail,
			reputation: null,
			intelMatch: null,
			settings: baseSettings,
			attachments: [{ filename: "invoice.exe", mimetype: "application/pdf" }],
		});
		expect(r.shortcircuit?.tier).toBe("attachment_block");
		expect(r.shortcircuit?.verdict.action).toBe("quarantine");
		expect(r.shortcircuit?.verdict.score).toBe(100);
		expect(r.shortcircuit?.reason).toContain(".exe");
	});

	it("preserves the double-extension trick: invoice.pdf.exe blocks on .exe", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "x@y.com",
			auth: dmarcPass,
			reputation: null,
			intelMatch: null,
			settings: baseSettings,
			attachments: [{ filename: "invoice.pdf.exe", mimetype: "application/pdf" }],
		});
		expect(r.shortcircuit?.tier).toBe("attachment_block");
	});

	it("runs BEFORE hard-allow: allowlisted + DMARC-pass sender with .exe is still blocked", () => {
		// Design invariant: account takeover or auto-forwarded malware should
		// not be papered over by allowlist membership.
		const r = evaluateTriage({
			...baseInputs,
			sender: "ceo@trusted.com",
			auth: dmarcPass,
			reputation: null,
			intelMatch: null,
			settings: { ...baseSettings, allowlist_senders: ["ceo@trusted.com"] },
			attachments: [{ filename: "payroll.exe", mimetype: "application/octet-stream" }],
		});
		expect(r.shortcircuit?.tier).toBe("attachment_block");
	});

	it("does NOT short-circuit on safe attachments", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "x@y.com",
			auth: dmarcFail,
			reputation: null,
			intelMatch: null,
			settings: baseSettings,
			attachments: [{ filename: "invoice.pdf", mimetype: "application/pdf" }],
		});
		expect(r.shortcircuit).toBeUndefined();
	});

	it("does NOT short-circuit on container/macro attachments (those only score)", () => {
		// Default policy: container_action="score", macro_office_action="score".
		// Neither category should cause a triage-level short-circuit.
		const r = evaluateTriage({
			...baseInputs,
			sender: "x@y.com",
			auth: dmarcFail,
			reputation: null,
			intelMatch: null,
			settings: baseSettings,
			attachments: [
				{ filename: "report.iso", mimetype: "application/octet-stream" },
				{ filename: "report.docm", mimetype: "application/vnd.ms-word.document.macroenabled.12" },
			],
		});
		expect(r.shortcircuit).toBeUndefined();
	});

	it("custom_blocklist_extensions extends the block set (e.g. .ace)", () => {
		const r = evaluateTriage({
			...baseInputs,
			sender: "x@y.com",
			auth: dmarcFail,
			reputation: null,
			intelMatch: null,
			settings: {
				...baseSettings,
				attachment_policy: {
					...baseSettings.attachment_policy,
					custom_blocklist_extensions: ["ace"],
				},
			},
			attachments: [{ filename: "malware.ace", mimetype: "application/octet-stream" }],
		});
		expect(r.shortcircuit?.tier).toBe("attachment_block");
		expect(r.shortcircuit?.reason).toContain(".ace");
	});
});
