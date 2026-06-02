// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it, vi, type MockedFunction } from "vitest";
import { isDmarcRuf, parseDmarcRuf, RUF_MAX_PAYLOAD_BYTES } from "../../workers/dmarc/ruf-parser";
import { ingestDmarcRuf } from "../../workers/dmarc/ingest";
import type { Email, Attachment } from "postal-mime";
import type { RufIngestionSettings } from "../../workers/security/defaults";

// ---------- helpers ----------

function enc(text: string): ArrayBuffer {
	return new TextEncoder().encode(text).buffer as ArrayBuffer;
}

function feedbackBody(overrides: Record<string, string> = {}): string {
	const fields: Record<string, string> = {
		"Feedback-Type": "auth-failure",
		"User-Agent": "FeedbackReporter/1.0",
		"Version": "1",
		"Original-Mail-From": "attacker@evil.example",
		"Source-IP": "198.51.100.7",
		"Failure-Type": "dmarc",
		"Reported-Domain": "example.com",
		"Authentication-Results": "mx.example.com; dmarc=fail header.from=example.com",
		...overrides,
	};
	return Object.entries(fields)
		.map(([k, v]) => `${k}: ${v}`)
		.join("\r\n");
}

function makeEmail(
	attachments: Array<{ mimeType: string; content: ArrayBuffer | string; filename?: string }>,
	overrides: Partial<Email> = {},
): Email {
	return {
		subject: "DMARC Failure Report",
		from: { address: "dmarc-ruf@reporter.example", name: "Reporter" },
		attachments: attachments.map((a) => ({
			mimeType: a.mimeType,
			content: a.content,
			filename: a.filename ?? "report",
			disposition: "attachment",
			headers: [],
		})) as unknown as Attachment[],
		...overrides,
	} as Email;
}

// ---------- isDmarcRuf ----------

describe("isDmarcRuf", () => {
	it("returns true when a message/feedback-report attachment is present", () => {
		const email = makeEmail([{ mimeType: "message/feedback-report", content: enc(feedbackBody()) }]);
		expect(isDmarcRuf(email)).toBe(true);
	});

	it("returns false for subject-only DMARC keywords without feedback-report part", () => {
		const email = makeEmail([], { subject: "DMARC Failure Report for example.com" });
		expect(isDmarcRuf(email)).toBe(false);
	});

	it("returns false for subject containing 'auth-failure' without feedback-report part", () => {
		const email = makeEmail([], { subject: "RE: auth-failure notification" });
		expect(isDmarcRuf(email)).toBe(false);
	});

	it("returns false for a normal email with no feedback-report attachment", () => {
		const email = makeEmail([{ mimeType: "text/plain", content: enc("hello") }], {
			subject: "Weekly newsletter",
		});
		expect(isDmarcRuf(email)).toBe(false);
	});

	it("returns false for an email with no attachments and an unrelated subject", () => {
		const email = makeEmail([], { subject: "Meeting agenda" });
		expect(isDmarcRuf(email)).toBe(false);
	});
});

// ---------- parseDmarcRuf ----------

describe("parseDmarcRuf", () => {
	it("extracts all ARF fields from a well-formed report", () => {
		const email = makeEmail([{ mimeType: "message/feedback-report", content: enc(feedbackBody()) }]);
		const record = parseDmarcRuf(email, false);
		expect(record).not.toBeNull();
		expect(record!.original_mail_from).toBe("attacker@evil.example");
		expect(record!.source_ip).toBe("198.51.100.7");
		expect(record!.failure_type).toBe("dmarc");
		expect(record!.reported_domain).toBe("example.com");
		expect(record!.feedback_type).toBe("auth-failure");
		expect(record!.auth_results).toBe("mx.example.com; dmarc=fail header.from=example.com");
	});

	it("returns null when no message/feedback-report attachment is present", () => {
		const email = makeEmail([{ mimeType: "text/plain", content: enc("nothing here") }]);
		expect(parseDmarcRuf(email, false)).toBeNull();
	});

	it("returns null for an email with no attachments", () => {
		const email = makeEmail([]);
		expect(parseDmarcRuf(email, false)).toBeNull();
	});

	it("sets original_headers to null when retain_raw is false", () => {
		const email = makeEmail([
			{ mimeType: "message/feedback-report", content: enc(feedbackBody()) },
			{
				mimeType: "message/rfc822",
				content: enc(
					"From: attacker@evil.example\r\nTo: victim@example.com\r\nSubject: Your invoice\r\n\r\nbody",
				),
			},
		]);
		const record = parseDmarcRuf(email, false);
		expect(record!.original_headers).toBeNull();
	});

	it("stores redacted headers when retain_raw is true", () => {
		const rawMsg =
			"From: attacker@evil.example\r\n" +
			"To: victim@example.com\r\n" +
			"Cc: cc@example.com\r\n" +
			"Bcc: bcc@example.com\r\n" +
			"Subject: Pay me now\r\n" +
			"Date: Mon, 1 Jan 2026 10:00:00 +0000\r\n" +
			"\r\n" +
			"body text here";
		const email = makeEmail([
			{ mimeType: "message/feedback-report", content: enc(feedbackBody()) },
			{ mimeType: "message/rfc822", content: enc(rawMsg) },
		]);
		const record = parseDmarcRuf(email, true);
		expect(record!.original_headers).not.toBeNull();
		// PII fields must be redacted
		expect(record!.original_headers).toContain("To: <redacted>");
		expect(record!.original_headers).toContain("Cc: <redacted>");
		expect(record!.original_headers).toContain("Bcc: <redacted>");
		expect(record!.original_headers).toContain("Subject: <redacted>");
		// Non-PII fields must be present
		expect(record!.original_headers).toContain("From: attacker@evil.example");
		expect(record!.original_headers).toContain("Date:");
		// Body must not be included (headers only up to blank line)
		expect(record!.original_headers).not.toContain("body text here");
	});

	it("throws when any attachment exceeds RUF_MAX_PAYLOAD_BYTES", () => {
		// Simulate an oversized attachment by creating a large content
		const oversized = new Uint8Array(RUF_MAX_PAYLOAD_BYTES + 1).buffer;
		const email = makeEmail([{ mimeType: "message/feedback-report", content: oversized }]);
		expect(() => parseDmarcRuf(email, false)).toThrow(/too large/i);
	});

	it("handles missing optional ARF fields gracefully (null)", () => {
		const minimal = "Feedback-Type: auth-failure\r\nVersion: 1";
		const email = makeEmail([{ mimeType: "message/feedback-report", content: enc(minimal) }]);
		const record = parseDmarcRuf(email, false);
		expect(record).not.toBeNull();
		expect(record!.original_mail_from).toBeNull();
		expect(record!.source_ip).toBeNull();
		expect(record!.failure_type).toBeNull();
		expect(record!.reported_domain).toBeNull();
		expect(record!.feedback_type).toBe("auth-failure");
	});
});

// ---------- ingestDmarcRuf ----------

function makeStub(overrides: Partial<{
	countDmarcRufRecordsSince: (since: string) => Promise<number>;
	insertDmarcRufRecord: (r: unknown) => Promise<void>;
}> = {}) {
	return {
		countDmarcRufRecordsSince: vi.fn().mockResolvedValue(0),
		insertDmarcRufRecord: vi.fn().mockResolvedValue(undefined),
		...overrides,
	};
}

function makeEnv(stub: ReturnType<typeof makeStub>) {
	return {
		MAILBOX: {
			idFromName: (_name: string) => ({ toString: () => "test-id" }),
			get: (_id: unknown) => stub,
		},
	} as unknown as import("../../workers/types").Env;
}

const ENABLED_SETTINGS: RufIngestionSettings = { enabled: true, retain_raw: false };
const DISABLED_SETTINGS: RufIngestionSettings = { enabled: false, retain_raw: false };

describe("ingestDmarcRuf", () => {
	it("returns { ingested: false } immediately when settings.enabled is false", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		const email = makeEmail([{ mimeType: "message/feedback-report", content: enc(feedbackBody()) }]);
		const result = await ingestDmarcRuf(env, "mb-1", "msg-1", email, DISABLED_SETTINGS);
		expect(result.ingested).toBe(false);
		expect(stub.insertDmarcRufRecord).not.toHaveBeenCalled();
	});

	it("inserts the parsed record when enabled and within rate limit", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		const email = makeEmail([{ mimeType: "message/feedback-report", content: enc(feedbackBody()) }]);
		const result = await ingestDmarcRuf(env, "mb-1", "msg-2", email, ENABLED_SETTINGS);
		expect(result.ingested).toBe(true);
		expect(stub.insertDmarcRufRecord).toHaveBeenCalledOnce();
		const inserted = (stub.insertDmarcRufRecord as MockedFunction<typeof stub.insertDmarcRufRecord>).mock.calls[0][0] as Record<string, unknown>;
		expect(inserted.id).toBe("msg-2");
		expect(inserted.source_ip).toBe("198.51.100.7");
		expect(inserted.reported_domain).toBe("example.com");
	});

	it("rejects the report when rate limit is reached", async () => {
		const stub = makeStub({
			// Simulate 100 reports already in the last 60s
			countDmarcRufRecordsSince: vi.fn().mockResolvedValue(100),
		});
		const env = makeEnv(stub);
		const email = makeEmail([{ mimeType: "message/feedback-report", content: enc(feedbackBody()) }]);
		const result = await ingestDmarcRuf(env, "mb-1", "msg-3", email, ENABLED_SETTINGS);
		expect(result.ingested).toBe(false);
		expect(result.reason).toMatch(/rate limit/i);
		expect(stub.insertDmarcRufRecord).not.toHaveBeenCalled();
	});

	it("returns { ingested: false } when no feedback-report part is found", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		const email = makeEmail([{ mimeType: "text/plain", content: enc("no ruf here") }]);
		const result = await ingestDmarcRuf(env, "mb-1", "msg-4", email, ENABLED_SETTINGS);
		expect(result.ingested).toBe(false);
		expect(result.reason).toMatch(/feedback-report/i);
		expect(stub.insertDmarcRufRecord).not.toHaveBeenCalled();
	});

	it("returns { ingested: false } when the attachment is oversized", async () => {
		const stub = makeStub();
		const env = makeEnv(stub);
		const oversized = new Uint8Array(RUF_MAX_PAYLOAD_BYTES + 1).buffer;
		const email = makeEmail([{ mimeType: "message/feedback-report", content: oversized }]);
		const result = await ingestDmarcRuf(env, "mb-1", "msg-5", email, ENABLED_SETTINGS);
		expect(result.ingested).toBe(false);
		expect(result.reason).toMatch(/too large/i);
		expect(stub.insertDmarcRufRecord).not.toHaveBeenCalled();
	});
});
