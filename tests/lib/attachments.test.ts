import { describe, expect, it, vi } from "vitest";
import { attachmentObjectKey, MAX_ATTACHMENTS_PER_EMAIL, storeAttachments } from "../../workers/lib/attachments";

/**
 * The R2 key layout is load-bearing: the mailbox-delete reap
 * (`workers/index.ts:reapMailbox`) reconstructs every key from
 * `(email_id, attachment_id, filename)` triples pulled out of the
 * Durable Object. If the write path and the read/delete path ever
 * drift apart, deletes become silent no-ops and blobs orphan in R2
 * forever. These tests pin the format in exactly one place.
 */
describe("attachmentObjectKey", () => {
	it("uses the attachments/<emailId>/<attachmentId>/<filename> layout", () => {
		expect(attachmentObjectKey("email-1", "att-1", "report.pdf")).toBe(
			"attachments/email-1/att-1/report.pdf",
		);
	});

	it("preserves whatever filename the caller supplies", () => {
		// Filenames are sanitized at the write boundary (storeAttachments
		// and the email-receive path). This helper trusts its inputs so
		// read-side reconstruction matches byte-for-byte.
		const weird = "spaces and.dots.zip";
		expect(attachmentObjectKey("e", "a", weird)).toBe(`attachments/e/a/${weird}`);
	});

	it("round-trips: prefix + three segments separated by slashes", () => {
		const key = attachmentObjectKey("E", "A", "f.bin");
		expect(key.startsWith("attachments/")).toBe(true);
		expect(key.split("/")).toEqual(["attachments", "E", "A", "f.bin"]);
	});
});

function makeAttachment(i: number) {
	return {
		content: btoa(`content-${i}`),
		filename: `file-${i}.txt`,
		type: "text/plain",
		disposition: "attachment",
	};
}

function makeMockBucket(putFn?: () => Promise<void>) {
	return {
		put: vi.fn().mockImplementation(putFn ?? (() => Promise.resolve())),
	} as unknown as Parameters<typeof storeAttachments>[0];
}

describe("storeAttachments – attachment cap", () => {
	it("stores all attachments when count is within cap", async () => {
		const bucket = makeMockBucket();
		const attachments = Array.from({ length: 5 }, (_, i) => makeAttachment(i));
		const result = await storeAttachments(bucket, "email-1", attachments);
		expect(result).toHaveLength(5);
		expect(bucket.put).toHaveBeenCalledTimes(5);
	});

	it(`stores at most ${MAX_ATTACHMENTS_PER_EMAIL} attachments when count exceeds cap`, async () => {
		const bucket = makeMockBucket();
		const attachments = Array.from({ length: MAX_ATTACHMENTS_PER_EMAIL + 50 }, (_, i) =>
			makeAttachment(i),
		);
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const result = await storeAttachments(bucket, "email-overflow", attachments);
		expect(result).toHaveLength(MAX_ATTACHMENTS_PER_EMAIL);
		expect(bucket.put).toHaveBeenCalledTimes(MAX_ATTACHMENTS_PER_EMAIL);
		expect(warnSpy).toHaveBeenCalledOnce();
		expect(warnSpy.mock.calls[0][0]).toMatch(/truncat/i);
		warnSpy.mockRestore();
	});

	it("returns empty array for undefined/empty attachments", async () => {
		const bucket = makeMockBucket();
		expect(await storeAttachments(bucket, "e")).toEqual([]);
		expect(await storeAttachments(bucket, "e", [])).toEqual([]);
		expect(bucket.put).not.toHaveBeenCalled();
	});
});
