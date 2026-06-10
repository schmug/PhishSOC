// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it, vi } from "vitest";
import type { Email } from "postal-mime";
import { DMARC_MAX_DECOMPRESSED_BYTES } from "../../workers/dmarc/parser";
import { ingestDmarcReport, isDmarcReport } from "../../workers/dmarc/ingest";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function compress(data: Uint8Array): Promise<ArrayBuffer> {
	const stream = new Response(data).body!.pipeThrough(new CompressionStream("gzip"));
	return new Response(stream).arrayBuffer();
}

function makeEmail(overrides: Partial<Email> = {}): Email {
	return {
		from: { address: "dmarc-report@reporter.example", name: "" },
		subject: "Report Domain: example.com Submitter: reporter.example",
		attachments: [],
		headers: [],
		...overrides,
	} as unknown as Email;
}

function mailboxStubMock(insertSpy: ReturnType<typeof vi.fn>) {
	return { insertDmarcReport: insertSpy };
}

function envWith(stub: { insertDmarcReport: ReturnType<typeof vi.fn> }) {
	return {
		MAILBOX: {
			idFromName: () => "id",
			get: () => stub,
		},
	} as never;
}

// Minimal valid DMARC RUA aggregate XML.
function makeXml(recordCount: number): string {
	const records = Array.from(
		{ length: recordCount },
		(_, i) =>
			`<record><row><source_ip>203.0.113.${i % 256}</source_ip><count>1</count></row></record>`,
	).join("\n");
	return `<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>test.example</org_name>
    <report_id>r-${recordCount}</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>reject</p></policy_published>
  ${records}
</feedback>`;
}

// ---------------------------------------------------------------------------
// isDmarcReport
// ---------------------------------------------------------------------------

describe("isDmarcReport", () => {
	it("matches a .xml.gz attachment", () => {
		const e = makeEmail({
			subject: "ignore me",
			attachments: [
				{ filename: "google.com!example.com!1.xml.gz", mimeType: "application/gzip", content: new Uint8Array() } as never,
			],
		});
		expect(isDmarcReport(e)).toBe(true);
	});

	it("does NOT match a plain text attachment from an unrelated sender", () => {
		const e = makeEmail({
			subject: "hello world",
			from: { address: "alice@example.com", name: "Alice" },
			attachments: [
				{ filename: "report.txt", mimeType: "text/plain", content: new Uint8Array() } as never,
			],
		});
		expect(isDmarcReport(e)).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// ingestDmarcReport — gzip size cap
// ---------------------------------------------------------------------------

describe("ingestDmarcReport — gzip size cap (issue #460)", () => {
	it("rejects a gzip attachment that decompresses past DMARC_MAX_DECOMPRESSED_BYTES", async () => {
		// A large run of zeros compresses very efficiently — a few KB of gzip
		// decompresses to well over 5 MB.
		const oversized = new Uint8Array(DMARC_MAX_DECOMPRESSED_BYTES + 1);
		const gz = await compress(oversized);

		const insertSpy = vi.fn();
		const stub = mailboxStubMock(insertSpy);
		const e = makeEmail({
			attachments: [
				{
					filename: "report.xml.gz",
					mimeType: "application/gzip",
					content: new Uint8Array(gz),
				} as never,
			],
		});

		const result = await ingestDmarcReport(envWith(stub), "mb-1", "msg-1", e);
		expect(result.ingested).toBe(false);
		expect(result.reason).toMatch(/cap/i);
		expect(insertSpy).not.toHaveBeenCalled();
	});

	it("accepts a legitimate small .xml.gz attachment", async () => {
		const xml = makeXml(1);
		const gz = await compress(new TextEncoder().encode(xml));

		const insertSpy = vi.fn().mockResolvedValue(undefined);
		const stub = mailboxStubMock(insertSpy);
		const e = makeEmail({
			attachments: [
				{
					filename: "report.xml.gz",
					mimeType: "application/gzip",
					content: new Uint8Array(gz),
				} as never,
			],
		});

		const result = await ingestDmarcReport(envWith(stub), "mb-1", "msg-2", e);
		expect(result.ingested).toBe(true);
		expect(insertSpy).toHaveBeenCalledOnce();
		const [reportRow, records] = insertSpy.mock.calls[0];
		expect(reportRow.domain).toBe("example.com");
		expect(records).toHaveLength(1);
	});
});

// ---------------------------------------------------------------------------
// ingestDmarcReport — record count cap
// ---------------------------------------------------------------------------

describe("ingestDmarcReport — record count cap (issue #460)", () => {
	it("inserts at most 1 000 records even when the XML contains more", async () => {
		// Build XML with 1 100 records (100 over the cap) and gzip it.
		const xml = makeXml(1_100);
		const gz = await compress(new TextEncoder().encode(xml));

		const insertSpy = vi.fn().mockResolvedValue(undefined);
		const stub = mailboxStubMock(insertSpy);
		const e = makeEmail({
			attachments: [
				{
					filename: "report.xml.gz",
					mimeType: "application/gzip",
					content: new Uint8Array(gz),
				} as never,
			],
		});

		const result = await ingestDmarcReport(envWith(stub), "mb-1", "msg-3", e);
		expect(result.ingested).toBe(true);
		const [, records] = insertSpy.mock.calls[0];
		expect(records.length).toBeLessThanOrEqual(1_000);
	});
});
