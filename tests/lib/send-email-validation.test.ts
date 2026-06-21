// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Unit tests for describeRecipientValidationError — the helper that turns a
 * SendEmailRequestSchema ZodError into a clear, user-facing message so that
 * invalid recipient input surfaces as a friendly 400 instead of an opaque 500.
 */

import { describe, expect, it } from "vitest";
import {
	SendEmailRequestSchema,
	describeRecipientValidationError,
} from "../../workers/lib/schemas";

function messageFor(body: Record<string, unknown>): string {
	const parsed = SendEmailRequestSchema.safeParse(body);
	expect(parsed.success).toBe(false);
	if (parsed.success) throw new Error("expected validation failure");
	return describeRecipientValidationError(parsed.error);
}

const VALID = {
	to: "alice@example.com",
	from: "me@example.com",
	subject: "hi",
	text: "body",
};

describe("describeRecipientValidationError", () => {
	it("asks for a To: recipient when to is missing", () => {
		const body = { ...VALID } as Record<string, unknown>;
		delete body.to;
		expect(messageFor(body)).toMatch(/to:/i);
	});

	it("asks for a To: recipient when to is an invalid email", () => {
		expect(messageFor({ ...VALID, to: "nope" })).toMatch(/to:/i);
	});

	it("names bcc when only bcc is a malformed email", () => {
		const msg = messageFor({ ...VALID, bcc: "not-an-email" });
		expect(msg).toMatch(/bcc/i);
		expect(msg).not.toMatch(/to:/i);
	});

	it("names cc when only cc is a malformed email", () => {
		const msg = messageFor({ ...VALID, cc: "not-an-email" });
		expect(msg).toMatch(/cc/i);
	});

	it("passes through the body requirement when neither html nor text is given", () => {
		const body = { to: "alice@example.com", from: "me@example.com", subject: "hi" };
		expect(messageFor(body)).toMatch(/html|text/i);
	});
});
