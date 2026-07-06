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

function makeEnv(stub: ReturnType<typeof makeMailboxStub>, envOverrides: Partial<Env> = {}): Env {
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

function makeSettings(overrides: { raw?: unknown } = {}) {
	return {
		security: { enabled: true, ruf_ingestion: { enabled: false, retain_raw: false }, thresholds: {} },
		autoDraft: { enabled: false },
		raw: overrides.raw,
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
});
