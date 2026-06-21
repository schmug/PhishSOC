// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Shared types and Zod schemas for email data.
 *
 * Types (from email-types.ts): used by the agent, MCP server, and route
 * handlers to avoid `as any` casting.
 *
 * Zod schemas: used across route handlers to eliminate duplication.
 */
import { z } from "zod";

// ── TypeScript Interfaces ──────────────────────────────────────────

export interface EmailMetadata {
	id: string;
	subject: string;
	sender: string;
	recipient: string;
	cc?: string | null;
	bcc?: string | null;
	date: string;
	read: boolean;
	starred: boolean;
	in_reply_to?: string | null;
	email_references?: string | null;
	thread_id?: string | null;
	folder_id?: string | null;
	snippet?: string | null;
}

export interface EmailFull extends EmailMetadata {
	body?: string | null;
	message_id?: string | null;
	raw_headers?: string | null;
	attachments?: AttachmentInfo[];
}

export interface AttachmentInfo {
	id: string;
	filename: string;
	mimetype: string;
	size: number;
	content_id?: string | null;
	disposition?: string | null;
}

// ── Zod Schemas ────────────────────────────────────────────────────

export const RecipientFieldSchema = z.union([
	z.string().email(),
	z.array(z.string().email()).min(1),
]);

export const ErrorResponseSchema = z.object({
	error: z.string(),
});

export const SendEmailRequestSchema = z
	.object({
		to: RecipientFieldSchema,
		cc: RecipientFieldSchema.optional(),
		bcc: RecipientFieldSchema.optional(),
		from: z.union([
			z.string().email(),
			z.object({ email: z.string().email(), name: z.string() }),
		]),
		subject: z.string(),
		html: z.string().optional(),
		text: z.string().optional(),
		attachments: z
			.array(
				z.object({
					content: z.string(), // base64 encoded
					filename: z.string(),
					type: z.string(),
					disposition: z.enum(["attachment", "inline"]),
					contentId: z.string().optional(),
				}),
			)
			.optional(),
		in_reply_to: z.string().optional(),
		references: z.array(z.string()).optional(),
		thread_id: z.string().optional(),
		/** When sending a saved draft, used to load `created_by` for send-risk (#266). */
		draft_id: z.string().optional(),
	})
	.refine((data) => data.html || data.text, {
		message: "Either 'html' or 'text' must be provided",
	});

export const SendEmailResponseSchema = z.object({
	id: z.string(),
	status: z.string(),
});

/**
 * Turn a {@link SendEmailRequestSchema} validation failure into a short,
 * user-facing message. Send/preflight/reply/forward handlers use this to
 * return a clear 400 instead of letting a raw `ZodError` bubble up as a 500
 * when a recipient field is missing or malformed (e.g. a partial address or a
 * comma-joined string typed into To:/Cc:/Bcc:).
 */
export function describeRecipientValidationError(error: z.ZodError): string {
	const issues = error.issues;
	const offending = (["to", "cc", "bcc"] as const).filter((field) =>
		issues.some((issue) => issue.path[0] === field),
	);

	// A missing or invalid To: is the most common cause; call it out explicitly
	// since To: is required (Cc/Bcc-only sends are intentionally blocked).
	if (offending.includes("to")) {
		const others = offending.filter((field) => field !== "to");
		const tail = others.length ? ` Also check: ${others.join(", ")}.` : "";
		return `A valid To: recipient is required.${tail}`;
	}
	if (offending.length > 0) {
		return `Invalid email address in: ${offending.join(", ")}. Use comma-separated addresses.`;
	}

	// Top-level refine (e.g. "Either 'html' or 'text' must be provided").
	const topLevel = issues.find((issue) => issue.path.length === 0);
	if (topLevel) return topLevel.message;

	return issues[0]?.message ?? "Invalid request payload.";
}

/**
 * Validate a raw request body against {@link SendEmailRequestSchema}, returning
 * either the parsed payload or a clear error message. Shared by the send,
 * preflight, reply, and forward handlers so a malformed recipient yields a 400
 * with a useful message rather than an unhandled `ZodError` (HTTP 500).
 */
export function parseSendEmailRequest(
	raw: unknown,
):
	| { ok: true; data: z.infer<typeof SendEmailRequestSchema> }
	| { ok: false; error: string } {
	const parsed = SendEmailRequestSchema.safeParse(raw);
	if (parsed.success) return { ok: true, data: parsed.data };
	return { ok: false, error: describeRecipientValidationError(parsed.error) };
}
