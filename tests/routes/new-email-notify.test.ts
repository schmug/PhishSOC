// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * receiveEmail-level regression for the ops-visibility "new mail" webhook
 * (issue #563): `dispatchNewEmailNotification` must fire exactly once per
 * non-honeypot, non-report-ingested inbound email when NEW_EMAIL_WEBHOOK_URL
 * is configured, must never block or fail email receipt when the webhook is
 * unset/down/slow/erroring, and must stay silent for honeypot mail and
 * successfully-ingested DMARC/TLS-RPT/RUF report mail.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Email } from "postal-mime";
import type { MailboxInbound } from "../../workers/providers/types";
import type { Env } from "../../workers/types";

vi.mock("../../workers/lib/mailbox-settings", () => ({
	resolveMailboxSettings: vi.fn(),
	stripDefaultEqual: <T>(x: T) => x,
	YaraMailScannerSettings: { parse: (x: unknown) => x },
}));

vi.mock("../../workers/security", () => ({
	runSecurityPipeline: vi.fn(),
}));

vi.mock("../../workers/dmarc/ingest", () => ({
	isDmarcReport: vi.fn().mockReturnValue(false),
	ingestDmarcReport: vi.fn(),
	isDmarcRuf: vi.fn().mockReturnValue(false),
	ingestDmarcRuf: vi.fn(),
}));

vi.mock("../../workers/tlsrpt/ingest", () => ({
	isTlsRptReport: vi.fn().mockReturnValue(false),
	ingestTlsRptReport: vi.fn(),
}));

vi.mock("../../workers/intel/deep-scan", () => ({
	runDeepScan: vi.fn().mockResolvedValue({ added_score: 0, final_action: "allow", reasons: [] }),
}));

vi.mock("../../workers/security/yaramail-signal", () => ({
	fireYaraScan: vi.fn().mockResolvedValue(undefined),
}));

import { receiveEmail } from "../../workers/index";
import { resolveMailboxSettings } from "../../workers/lib/mailbox-settings";
import { runSecurityPipeline } from "../../workers/security";
import { isDmarcReport, ingestDmarcReport, isDmarcRuf, ingestDmarcRuf } from "../../workers/dmarc/ingest";
import { isTlsRptReport, ingestTlsRptReport } from "../../workers/tlsrpt/ingest";

const mockedResolve = vi.mocked(resolveMailboxSettings);
const mockedPipeline = vi.mocked(runSecurityPipeline);
const mockedIsDmarcReport = vi.mocked(isDmarcReport);
const mockedIngestDmarcReport = vi.mocked(ingestDmarcReport);
const mockedIsDmarcRuf = vi.mocked(isDmarcRuf);
const mockedIngestDmarcRuf = vi.mocked(ingestDmarcRuf);
const mockedIsTlsRptReport = vi.mocked(isTlsRptReport);
const mockedIngestTlsRptReport = vi.mocked(ingestTlsRptReport);

const MAILBOX_ID = "inbox@example.com";
const WEBHOOK_URL = "https://chat.googleapis.com/v1/spaces/AAA/messages?key=k&token=t";
const RP_ORIGIN = "https://inbox.cortech.online";

function makeEmail(overrides: Partial<{ subject: string; from: { address: string; name: string } }> = {}): Email {
	return {
		subject: overrides.subject ?? "Invoice attached",
		from: overrides.from ?? { address: "alice@example.com", name: "Alice" },
		to: [{ address: MAILBOX_ID, name: "" }],
		headers: [],
		attachments: [],
	} as unknown as Email;
}

function makeNormalized(email: Email): MailboxInbound {
	return { kind: "mailbox", rawEmail: new ArrayBuffer(0), parsedEmail: email, mailboxId: MAILBOX_ID };
}

function makeMailboxStub() {
	return {
		createEmail: vi.fn().mockResolvedValue(undefined),
		moveEmail: vi.fn().mockResolvedValue(undefined),
		detachEmailFromThread: vi.fn().mockResolvedValue(undefined),
		findThreadBySubject: vi.fn().mockResolvedValue(null),
		countEmails: vi.fn().mockResolvedValue(0),
		recordPipelineRunStart: vi.fn().mockResolvedValue(undefined),
		recordPipelineRunComplete: vi.fn().mockResolvedValue(undefined),
		notifyNewEmail: vi.fn().mockResolvedValue(undefined),
	};
}

function makeEnv(
	stub: ReturnType<typeof makeMailboxStub>,
	envOverrides: Partial<Env> & Record<string, unknown> = {},
): Env {
	return {
		BUCKET: { head: vi.fn().mockResolvedValue({ key: `mailboxes/${MAILBOX_ID}.json` }), put: vi.fn() },
		MAILBOX: { idFromName: vi.fn().mockReturnValue("do-id"), get: vi.fn().mockReturnValue(stub) },
		EMAIL_AGENT: {
			idFromName: vi.fn().mockReturnValue("agent-id"),
			get: vi.fn().mockReturnValue({ fetch: vi.fn().mockResolvedValue(new Response("ok")) }),
		},
		RP_ORIGIN,
		...envOverrides,
	} as unknown as Env;
}

/** Real `ExecutionContext.waitUntil` semantics: collect scheduled promises so
 *  a test can await them before asserting on the fire-and-forget dispatch. */
function makeCtx() {
	const scheduled: Promise<unknown>[] = [];
	const ctx = {
		waitUntil: (p: Promise<unknown>) => {
			scheduled.push(Promise.resolve(p));
		},
	} as unknown as ExecutionContext;
	return { ctx, settle: () => Promise.allSettled(scheduled) };
}

function makeSettings(overrides: { raw?: unknown; domain?: unknown; org?: unknown } = {}) {
	return {
		security: { enabled: true, ruf_ingestion: { enabled: false, retain_raw: false }, thresholds: {} },
		autoDraft: { enabled: false },
		raw: overrides.raw,
		domain: overrides.domain,
		org: overrides.org,
	} as unknown as Awaited<ReturnType<typeof resolveMailboxSettings>>;
}

describe("receiveEmail — new-mail ops-visibility webhook (issue #563)", () => {
	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		vi.clearAllMocks();
		mockedResolve.mockResolvedValue(makeSettings());
		mockedPipeline.mockResolvedValue({
			verdict: { action: "allow", score: 12, signals: [], explanation: "" },
			skipped: false,
		} as never);
		mockedIsDmarcReport.mockReturnValue(false);
		mockedIsDmarcRuf.mockReturnValue(false);
		mockedIsTlsRptReport.mockReturnValue(false);
		fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("posts exactly one {text} message with sender, subject, folder, verdict, and deep link", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		await receiveEmail(makeNormalized(makeEmail()), makeEnv(stub, { NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL }), ctx);
		await settle();

		expect(fetchSpy).toHaveBeenCalledOnce();
		const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
		expect(url).toBe(WEBHOOK_URL);
		expect(init.method).toBe("POST");
		const body = JSON.parse(String(init.body)) as { text: string };
		expect(body.text).toContain(MAILBOX_ID);
		expect(body.text).toContain("[inbox]");
		expect(body.text).toContain("alice@example.com");
		expect(body.text).toContain("Invoice attached");
		expect(body.text).toContain("verdict: allow (12)");
		expect(body.text).toContain(`${RP_ORIGIN}/mailbox/${encodeURIComponent(MAILBOX_ID)}/emails/inbox?email=`);
	});

	it("secret unset: no outbound fetch; email receipt still succeeds", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		await receiveEmail(makeNormalized(makeEmail()), makeEnv(stub), ctx);
		await settle();

		expect(fetchSpy).not.toHaveBeenCalled();
		expect(stub.createEmail).toHaveBeenCalledOnce();
	});

	it("webhook returns 500: email receipt, storage, and pipeline all still succeed", async () => {
		fetchSpy.mockResolvedValue(new Response(null, { status: 500 }));
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		await expect(
			receiveEmail(makeNormalized(makeEmail()), makeEnv(stub, { NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL }), ctx),
		).resolves.not.toBeNull();
		await settle();

		expect(stub.createEmail).toHaveBeenCalledOnce();
		expect(mockedPipeline).toHaveBeenCalledOnce();
	});

	it("webhook throws (network failure): email receipt, storage, and pipeline all still succeed", async () => {
		fetchSpy.mockRejectedValue(new Error("network down"));
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		await expect(
			receiveEmail(makeNormalized(makeEmail()), makeEnv(stub, { NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL }), ctx),
		).resolves.not.toBeNull();
		await settle();

		expect(stub.createEmail).toHaveBeenCalledOnce();
		expect(mockedPipeline).toHaveBeenCalledOnce();
	});

	it("quarantined mail: notifies with quarantine as the folder in both text and link", async () => {
		mockedPipeline.mockResolvedValue({
			verdict: { action: "quarantine", score: 80, signals: [], explanation: "" },
			skipped: false,
		} as never);
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		await receiveEmail(makeNormalized(makeEmail()), makeEnv(stub, { NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL }), ctx);
		await settle();

		expect(fetchSpy).toHaveBeenCalledOnce();
		const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
		const body = JSON.parse(String(init.body)) as { text: string };
		expect(body.text).toContain("[quarantine]");
		expect(body.text).toContain("verdict: quarantine (80)");
		expect(body.text).toContain(`/mailbox/${encodeURIComponent(MAILBOX_ID)}/emails/quarantine?email=`);
	});

	it("honeypot mail: does not notify", async () => {
		mockedResolve.mockResolvedValue(makeSettings({ raw: { honeypot: { enabled: true, expires_at: "2099-01-01T00:00:00Z" } } }));
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		await receiveEmail(makeNormalized(makeEmail()), makeEnv(stub, { NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL }), ctx);
		await settle();

		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("successfully-ingested DMARC aggregate report mail: does not notify", async () => {
		mockedIsDmarcReport.mockReturnValue(true);
		mockedIngestDmarcReport.mockResolvedValue({ ingested: true } as never);
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		await receiveEmail(makeNormalized(makeEmail()), makeEnv(stub, { NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL }), ctx);
		await settle();

		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("successfully-ingested TLS-RPT report mail: does not notify", async () => {
		mockedIsTlsRptReport.mockReturnValue(true);
		mockedIngestTlsRptReport.mockResolvedValue({ ingested: true } as never);
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		await receiveEmail(makeNormalized(makeEmail()), makeEnv(stub, { NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL }), ctx);
		await settle();

		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("successfully-ingested DMARC RUF mail: does not notify", async () => {
		mockedIsDmarcRuf.mockReturnValue(true);
		mockedResolve.mockResolvedValue({
			security: { enabled: true, ruf_ingestion: { enabled: true, retain_raw: false }, thresholds: {} },
			autoDraft: { enabled: false },
			raw: undefined,
		} as unknown as Awaited<ReturnType<typeof resolveMailboxSettings>>);
		mockedIngestDmarcRuf.mockResolvedValue({ ingested: true } as never);
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		await receiveEmail(makeNormalized(makeEmail()), makeEnv(stub, { NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL }), ctx);
		await settle();

		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("strips <, >, | from attacker-controlled sender/subject so a crafted subject can't inject a fake link", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		const email = makeEmail({
			subject: "<evil>|<a href=x>click</a>",
			from: { address: "attacker@evil.example|<>", name: "" },
		});
		await receiveEmail(makeNormalized(email), makeEnv(stub, { NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL }), ctx);
		await settle();

		const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
		const body = JSON.parse(String(init.body)) as { text: string };
		// The `<`, `>`, `|` characters are stripped from attacker-controlled
		// fields so a crafted subject/sender can't close out of its slot and
		// inject a fake `<url|text>` chat link — the surrounding plain text may
		// survive, but no intact bracket/pipe sequence from attacker input does.
		expect(body.text).not.toContain("<evil>");
		expect(body.text).not.toContain("<a href=x>");
		expect(body.text).not.toContain("</a>");
		expect(body.text).not.toContain("attacker@evil.example|");
		expect(body.text).toContain("attacker@evil.example");
	});

	it("inline-gateway relay branch (issue #32) is inert when the domain has no relay policy", async () => {
		// makeEnv's BUCKET only stubs head/put; BUCKET.get is undefined, so
		// getDomainSettings' fetch throws internally and it falls back to `{}`,
		// which resolveRelayPolicy resolves to null — no relay attempted, and
		// setRelayStatus (not present in makeMailboxStub) is never invoked.
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		// receiveEmail resolves without throwing. Its return value is irrelevant
		// here — #587 changed it from void to a ReceiveEmailResult; inertness is
		// proven by setRelayStatus never being invoked, below.
		await receiveEmail(makeNormalized(makeEmail()), makeEnv(stub, { NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL }), ctx);
		await settle();

		expect(stub.createEmail).toHaveBeenCalledOnce();
		expect((stub as Record<string, unknown>).setRelayStatus).toBeUndefined();
	});
});

/**
 * Tiered webhook routing (#563 follow-up). A tier that names its own Worker
 * Secret takes over from the legacy global `NEW_EMAIL_WEBHOOK_URL`, so an
 * operator can point one mailbox at a bot without clobbering the org channel.
 */
/**
 * Match a recorded `fetch` call by parsed hostname.
 *
 * Substring checks (`url.includes("grok.example.com")`) trip CodeQL's
 * js/incomplete-url-substring-sanitization even in test-only code, and PRs
 * are gated on CodeQL — see the repo CLAUDE.md entry. Parse and compare the
 * hostname instead.
 */
function callsToHost(calls: unknown[][], host: string): unknown[][] {
	return calls.filter((c) => {
		try {
			return new URL(String(c[0])).hostname === host;
		} catch {
			return false;
		}
	});
}

describe("receiveEmail — tiered new-mail webhook", () => {
	const GROK_URL = "https://grok.example.com/hooks/abc?key=k";
	const ORG_URL = "https://chat.googleapis.com/v1/spaces/ORG/messages?key=k&token=t";

	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		vi.clearAllMocks();
		mockedPipeline.mockResolvedValue({
			verdict: { action: "allow", score: 12, signals: [], explanation: "" },
			skipped: false,
		} as never);
		mockedIsDmarcReport.mockReturnValue(false);
		mockedIsDmarcRuf.mockReturnValue(false);
		mockedIsTlsRptReport.mockReturnValue(false);
		fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	function envWith(stub: ReturnType<typeof makeMailboxStub>) {
		return makeEnv(stub, {
			NEW_EMAIL_WEBHOOK_URL: ORG_URL,
			NEW_EMAIL_WEBHOOK_GROK: GROK_URL,
		});
	}

	it("posts to the mailbox tier's secret instead of the global URL", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		mockedResolve.mockResolvedValue(
			makeSettings({ raw: { newEmailWebhook: { enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_GROK" } } }),
		);

		await receiveEmail(makeNormalized(makeEmail()), envWith(stub), ctx);
		await settle();

		const calls = callsToHost(fetchSpy.mock.calls, "grok.example.com");
		expect(calls).toHaveLength(1);
		expect(callsToHost(fetchSpy.mock.calls, "chat.googleapis.com")).toHaveLength(0);
	});

	it("falls back to the global URL when no tier configures a webhook", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		mockedResolve.mockResolvedValue(makeSettings());

		await receiveEmail(makeNormalized(makeEmail()), envWith(stub), ctx);
		await settle();

		expect(callsToHost(fetchSpy.mock.calls, "chat.googleapis.com")).toHaveLength(1);
	});

	it("sends nothing when the winning tier is muted, without falling back to the global URL", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		mockedResolve.mockResolvedValue(
			makeSettings({
				raw: { newEmailWebhook: { enabled: false } },
				org: { newEmailWebhook: { enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_GROK" } },
			}),
		);

		await receiveEmail(makeNormalized(makeEmail()), envWith(stub), ctx);
		await settle();

		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("refuses a secret name outside the prefix and does NOT fall back to the global URL", async () => {
		// Reaches dispatch only via a hand-edited R2 blob (the Zod schema rejects
		// it on write). Falling back here would leak the mail to the global
		// channel that the tier was configured to replace.
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		mockedResolve.mockResolvedValue(
			makeSettings({ raw: { newEmailWebhook: { enabled: true, urlSecret: "CONFIRMATION_TOKEN_SECRET" } } }),
		);

		await receiveEmail(
			makeNormalized(makeEmail()),
			makeEnv(stub, {
				NEW_EMAIL_WEBHOOK_URL: ORG_URL,
				CONFIRMATION_TOKEN_SECRET: "https://attacker.example.com/steal",
			}),
			ctx,
		);
		await settle();

		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("sends nothing when the named secret is not configured in the environment", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		mockedResolve.mockResolvedValue(
			makeSettings({ raw: { newEmailWebhook: { enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_ABSENT" } } }),
		);

		await receiveEmail(makeNormalized(makeEmail()), envWith(stub), ctx);
		await settle();

		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("uses the domain tier when the mailbox tier is absent", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		mockedResolve.mockResolvedValue(
			makeSettings({
				domain: { newEmailWebhook: { enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_GROK" } },
			}),
		);

		await receiveEmail(makeNormalized(makeEmail()), envWith(stub), ctx);
		await settle();

		expect(callsToHost(fetchSpy.mock.calls, "grok.example.com")).toHaveLength(1);
	});
});

/**
 * Outbound request signing (issue #700). `NEW_EMAIL_WEBHOOK_SIGNING_SECRET`
 * gates an `x-phishsoc-signature: t=,v1=` header — Stripe's construction —
 * computed over `${timestamp}.${rawBody}`. Applies uniformly regardless of
 * destination (global fallback or a per-tier secret) or payload shape, since
 * it signs whatever serialized body is about to be sent.
 */
async function hmacHex(secret: string, message: string): Promise<string> {
	const enc = new TextEncoder();
	const key = await crypto.subtle.importKey(
		"raw",
		enc.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
	return Array.from(new Uint8Array(sig))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

describe("receiveEmail — new-email webhook request signing", () => {
	const SIGNING_SECRET = "test-signing-secret-value";

	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		vi.clearAllMocks();
		mockedResolve.mockResolvedValue(makeSettings());
		mockedPipeline.mockResolvedValue({
			verdict: { action: "allow", score: 12, signals: [], explanation: "" },
			skipped: false,
		} as never);
		mockedIsDmarcReport.mockReturnValue(false);
		mockedIsDmarcRuf.mockReturnValue(false);
		mockedIsTlsRptReport.mockReturnValue(false);
		fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("no signing secret configured: headers and body are byte-for-byte unchanged from pre-#700 behavior", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		await receiveEmail(makeNormalized(makeEmail()), makeEnv(stub, { NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL }), ctx);
		await settle();

		expect(fetchSpy).toHaveBeenCalledOnce();
		const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
		expect(url).toBe(WEBHOOK_URL);
		expect(init.method).toBe("POST");
		expect(init.headers).toEqual({ "content-type": "application/json" });
		const body = JSON.parse(String(init.body)) as { text: string };
		expect(Object.keys(body)).toEqual(["text"]);
	});

	it("signing secret configured: carries a t=,v1= header whose signature independently verifies against the captured body", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		await receiveEmail(
			makeNormalized(makeEmail()),
			makeEnv(stub, {
				NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL,
				NEW_EMAIL_WEBHOOK_SIGNING_SECRET: SIGNING_SECRET,
			}),
			ctx,
		);
		await settle();

		expect(fetchSpy).toHaveBeenCalledOnce();
		const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
		const headers = init.headers as Record<string, string>;
		expect(headers["content-type"]).toBe("application/json");

		const match = /^t=(\d+),v1=([0-9a-f]+)$/.exec(headers["x-phishsoc-signature"] ?? "");
		expect(match).not.toBeNull();
		const [, timestamp, signature] = match as unknown as [string, string, string];

		// Recompute the signature independently from the captured body,
		// timestamp, and secret and assert equality — not merely that a
		// header is present (issue #700 acceptance criterion 3).
		const expected = await hmacHex(SIGNING_SECRET, `${timestamp}.${String(init.body)}`);
		expect(signature).toBe(expected);

		// The timestamp is fresh and part of the signed material, so a
		// captured request can't be replayed indefinitely.
		expect(Math.abs(Date.now() / 1000 - Number(timestamp))).toBeLessThan(30);
	});

	it("a signature computed with the wrong secret does not match", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		await receiveEmail(
			makeNormalized(makeEmail()),
			makeEnv(stub, {
				NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL,
				NEW_EMAIL_WEBHOOK_SIGNING_SECRET: SIGNING_SECRET,
			}),
			ctx,
		);
		await settle();

		const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
		const headers = init.headers as Record<string, string>;
		const [, timestamp, signature] = /^t=(\d+),v1=([0-9a-f]+)$/.exec(
			headers["x-phishsoc-signature"] ?? "",
		) as unknown as [string, string, string];

		const wrongSecretSignature = await hmacHex("not-the-real-secret", `${timestamp}.${String(init.body)}`);
		expect(signature).not.toBe(wrongSecretSignature);
	});

	it("signs requests routed to a per-tier destination the same way as the global fallback", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		mockedResolve.mockResolvedValue(
			makeSettings({ raw: { newEmailWebhook: { enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_GROK" } } }),
		);

		await receiveEmail(
			makeNormalized(makeEmail()),
			makeEnv(stub, {
				NEW_EMAIL_WEBHOOK_URL: WEBHOOK_URL,
				NEW_EMAIL_WEBHOOK_GROK: "https://grok.example.com/hooks/abc?key=k",
				NEW_EMAIL_WEBHOOK_SIGNING_SECRET: SIGNING_SECRET,
			}),
			ctx,
		);
		await settle();

		expect(fetchSpy).toHaveBeenCalledOnce();
		const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
		expect(new URL(url).hostname).toBe("grok.example.com");
		const headers = init.headers as Record<string, string>;
		expect(headers["x-phishsoc-signature"]).toMatch(/^t=\d+,v1=[0-9a-f]+$/);
	});
});

/**
 * `format: "json"` (#563 follow-up). The chat payload flattens a structured
 * event into Slack-shaped prose; a bot consumer wants the fields back.
 */
describe("receiveEmail — json payload format", () => {
	const HOOK = "https://bot.example.com/hooks/abc?key=k";

	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		vi.clearAllMocks();
		mockedPipeline.mockResolvedValue({
			verdict: { action: "allow", score: 12, signals: [], explanation: "" },
			skipped: false,
		} as never);
		mockedIsDmarcReport.mockReturnValue(false);
		mockedIsDmarcRuf.mockReturnValue(false);
		mockedIsTlsRptReport.mockReturnValue(false);
		fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	function jsonTierEnv(stub: ReturnType<typeof makeMailboxStub>) {
		return makeEnv(stub, { NEW_EMAIL_WEBHOOK_BOT: HOOK });
	}

	function jsonSettings() {
		return makeSettings({
			raw: { newEmailWebhook: { enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_BOT", format: "json" } },
		});
	}

	/** Parse the body of the single recorded webhook POST. */
	function postedBody(): Record<string, unknown> {
		const call = callsToHost(fetchSpy.mock.calls, "bot.example.com")[0];
		return JSON.parse(String((call[1] as RequestInit).body));
	}

	it("posts the structured event rather than a {text} blob", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		mockedResolve.mockResolvedValue(jsonSettings());

		await receiveEmail(makeNormalized(makeEmail()), jsonTierEnv(stub), ctx);
		await settle();

		const body = postedBody();
		expect(body.text).toBeUndefined();
		expect(body).toMatchObject({
			mailboxId: MAILBOX_ID,
			folder: "inbox",
			sender: "alice@example.com",
			subject: "Invoice attached",
			verdictAction: "allow",
			verdictScore: 12,
		});
		expect(String(body.url)).toContain(`${RP_ORIGIN}/mailbox/`);
	});

	it("sends the subject verbatim — the <>| strip exists only for chat link syntax", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		mockedResolve.mockResolvedValue(jsonSettings());

		await receiveEmail(
			makeNormalized(makeEmail({ subject: "Re: <urgent> | wire transfer" })),
			jsonTierEnv(stub),
			ctx,
		);
		await settle();

		// JSON.stringify escapes these safely; stripping them would corrupt
		// legitimate subjects for a structured consumer.
		expect(postedBody().subject).toBe("Re: <urgent> | wire transfer");
	});

	it("bounds a hostile subject so the payload can't balloon", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		mockedResolve.mockResolvedValue(jsonSettings());

		await receiveEmail(
			makeNormalized(makeEmail({ subject: "A".repeat(5000) })),
			jsonTierEnv(stub),
			ctx,
		);
		await settle();

		const body = postedBody();
		// Assert we are on the JSON path, so this cannot pass merely because
		// the chat formatter truncates at 120.
		expect(body.text).toBeUndefined();
		expect(String(body.subject).length).toBeGreaterThan(120);
		expect(String(body.subject).length).toBeLessThanOrEqual(1000);
	});

	it("still sends the chat shape when format is absent", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		mockedResolve.mockResolvedValue(
			makeSettings({ raw: { newEmailWebhook: { enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_BOT" } } }),
		);

		await receiveEmail(makeNormalized(makeEmail()), jsonTierEnv(stub), ctx);
		await settle();

		const body = postedBody();
		expect(typeof body.text).toBe("string");
		expect(body.mailboxId).toBeUndefined();
	});
});

/**
 * Signing (#700/#701) x json format (#699) — a combination neither side could
 * test, since #701 landed before `format: "json"` existed. #700's acceptance
 * criteria required signing to cover both shapes; this proves it does, because
 * signing operates on the serialized body rather than the payload structure.
 */
describe("receiveEmail — signing a json payload", () => {
	const SIGNING = "test-signing-secret-value";
	const HOOK = "https://bot.example.com/hooks/abc?key=k";

	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		vi.clearAllMocks();
		mockedPipeline.mockResolvedValue({
			verdict: { action: "allow", score: 12, signals: [], explanation: "" },
			skipped: false,
		} as never);
		mockedIsDmarcReport.mockReturnValue(false);
		mockedIsDmarcRuf.mockReturnValue(false);
		mockedIsTlsRptReport.mockReturnValue(false);
		fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("signs the json body, and the signature verifies over that exact body", async () => {
		const stub = makeMailboxStub();
		const { ctx, settle } = makeCtx();
		mockedResolve.mockResolvedValue(
			makeSettings({
				raw: { newEmailWebhook: { enabled: true, urlSecret: "NEW_EMAIL_WEBHOOK_BOT", format: "json" } },
			}),
		);

		await receiveEmail(
			makeNormalized(makeEmail()),
			makeEnv(stub, {
				NEW_EMAIL_WEBHOOK_BOT: HOOK,
				NEW_EMAIL_WEBHOOK_SIGNING_SECRET: SIGNING,
			}),
			ctx,
		);
		await settle();

		const init = callsToHost(fetchSpy.mock.calls, "bot.example.com")[0][1] as RequestInit;
		const headers = init.headers as Record<string, string>;

		// It really is the json shape, not chat prose.
		const parsed = JSON.parse(String(init.body));
		expect(parsed.text).toBeUndefined();
		expect(parsed.sender).toBe("alice@example.com");

		const match = /^t=(\d+),v1=([0-9a-f]+)$/.exec(headers["x-phishsoc-signature"] ?? "");
		expect(match).not.toBeNull();
		const [, timestamp, signature] = match as RegExpExecArray;
		expect(signature).toBe(await hmacHex(SIGNING, `${timestamp}.${String(init.body)}`));
	});
});
