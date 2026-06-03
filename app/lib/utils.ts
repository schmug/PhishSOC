// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Shared utility functions used across the frontend.
 *
 * Date formatting has been consolidated into `shared/dates.ts`.
 * Re-export for backwards compatibility with existing imports.
 */
import DOMPurify from "dompurify";
import { formatQuotedDate } from "shared/dates";
import { htmlToPlainText as htmlToText } from "shared/html-text";
import type { Attachment } from "~/types";

export {
	formatDetailDate,
	formatListDate,
	formatShortDate,
} from "shared/dates";

/** @deprecated Use `formatQuotedDate` from `shared/dates` directly. */
export const formatComposeDate = formatQuotedDate;

/**
 * Format a byte count as a human-readable file size.
 */
export function formatBytes(bytes: number, decimals = 1): string {
	if (bytes === 0) return "0 B";
	const k = 1024;
	const dm = decimals < 0 ? 0 : decimals;
	const sizes = ["B", "KB", "MB", "GB"];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return `${Number.parseFloat((bytes / k ** i).toFixed(dm))} ${sizes[i]}`;
}

/**
 * Split a comma-separated email field into individual addresses.
 */
export function splitEmailList(value?: string | null): string[] {
	return (value || "")
		.split(",")
		.map((entry) => entry.trim())
		.filter(Boolean);
}

/**
 * Convert a list of addresses into the API payload format.
 */
export function toEmailListValue(
	addresses: string[],
): string | string[] | undefined {
	if (addresses.length === 0) return undefined;
	return addresses.length === 1 ? addresses[0] : addresses;
}

/**
 * Convert HTML content to plain text. Preserves paragraph breaks where the
 * source had block-level structure.
 */
export function htmlToPlainText(html: string): string {
	return htmlToText(html, { preserveLineBreaks: true });
}

// ⚡ Bolt: Cache stripHtml operations to prevent expensive HTML parsing of full email bodies
// on every re-render in ThreadMessage.tsx. Limits size to 1000 items.
const stripHtmlCache = new Map<string, string>();

/**
 * Strip all HTML tags and collapse whitespace to a single line of plain text.
 */
export function stripHtml(html: string): string {
	if (!html) return "";
	if (stripHtmlCache.has(html)) {
		const cached = stripHtmlCache.get(html);
		if (cached !== undefined) return cached;
	}

	const result = htmlToText(html);

	if (stripHtmlCache.size >= 1000) {
		const firstKey = stripHtmlCache.keys().next().value;
		if (firstKey !== undefined) stripHtmlCache.delete(firstKey);
	}
	stripHtmlCache.set(html, result);
	return result;
}

// ⚡ Bolt: Cache htmlToText operations to prevent expensive HTML parsing on every re-render
// of the email list. This acts as a simple LRU to bound memory while optimizing hot paths.
const snippetCache = new Map<string, string>();

// ⚡ Bolt: Cache participant parsing to prevent expensive split/map/filter operations on every re-render
const participantsCache = new Map<string, string>();

export function formatParticipants(email: {
	participants?: string | null;
	sender: string;
}): string {
	if (!email.participants) {
		return email.sender.split("@")[0];
	}

	const cacheKey = email.participants;
	if (participantsCache.has(cacheKey)) {
		const cached = participantsCache.get(cacheKey);
		if (cached !== undefined) return cached;
	}

	const names = email.participants
		.split(",")
		.map((p) => p.trim().split("@")[0])
		.filter((name, idx, arr) => arr.indexOf(name) === idx);

	let result: string;
	if (names.length <= 3) {
		result = names.join(", ");
	} else {
		result = `${names.slice(0, 2).join(", ")} +${names.length - 2}`;
	}

	if (participantsCache.size >= 1000) {
		const firstKey = participantsCache.keys().next().value;
		if (firstKey !== undefined) {
			participantsCache.delete(firstKey);
		}
	}
	participantsCache.set(cacheKey, result);
	return result;
}

export function getSnippetText(
	snippet?: string | null,
	maxLength = 100,
): string {
	if (!snippet) return "";
	const cacheKey = `${maxLength}:${snippet}`;

	// ⚡ Bolt: Return memoized result to avoid repeated htmlToText CPU overhead
	if (snippetCache.has(cacheKey)) {
		const cached = snippetCache.get(cacheKey);
		if (cached !== undefined) {
			return cached;
		}
	}
	const clean = htmlToText(snippet);
	if (!clean) return "";
	const result =
		clean.length > maxLength ? `${clean.slice(0, maxLength)}...` : clean;

	// ⚡ Bolt: Prevent memory leaks by maintaining a bounded size (evicts oldest entry)
	if (snippetCache.size >= 1000) {
		const firstKey = snippetCache.keys().next().value;
		if (firstKey !== undefined) {
			snippetCache.delete(firstKey);
		}
	}
	snippetCache.set(cacheKey, result);
	return result;
}

/**
 * Escape all five OWASP-recommended HTML special characters in plain text.
 * Safe for use in both text content and attribute contexts.
 */
export function escapeHtml(text: string): string {
	if (!text) return "";
	return text
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

/**
 * Generate the HTML signature block for compose forms.
 */
export function getSignatureBlock(settings?: {
	signature?: { enabled: boolean; text?: string; html?: string };
}): string {
	const sig = settings?.signature;
	if (sig?.enabled && (sig?.html || sig?.text)) {
		// Sanitize HTML signatures with DOMPurify to allow safe formatting
		// (bold, italic, links, etc.) while stripping scripts and event handlers.
		// Text signatures are HTML-escaped since they have no formatting.
		const content = sig.html
			? DOMPurify.sanitize(sig.html)
			: escapeHtml(sig.text || "");
		return `<div style="border-top: 1px solid #ccc; margin-top: 16px; padding-top: 12px;">${content}</div>`;
	}
	return "";
}

/**
 * Build a quoted reply block HTML string from original email data.
 */
export function buildQuotedReplyBlock(
	dateStr: string | undefined,
	sender: string,
	body: string,
): string {
	if (!body) return "";
	const formattedDate = formatComposeDate(dateStr);

	// HTML-escape sender to prevent <john@example.com> from disappearing as a tag
	const escapedSender = escapeHtml(sender);

	// Sanitize the body to plain text to prevent stored XSS.
	// The original HTML renders safely in the sandboxed iframe, but quoted
	// reply blocks are injected into the compose editor where raw HTML would
	// execute. Convert to escaped plain text instead.
	const bodyToQuote = escapeHtml(stripHtml(body)).replace(/\n/g, "<br>");

	return `<br><blockquote style="border-left: 2px solid #ccc; margin: 0; padding-left: 1em; color: #666;">On ${formattedDate}, ${escapedSender} wrote:<br><br>${bodyToQuote}</blockquote>`;
}

/**
 * Rewrite CID references in email HTML to API URLs for inline images.
 * Replaces `src="cid:image001@example.com"` with the attachment API endpoint.
 */
export function rewriteInlineImages(
	body: string,
	mailboxId: string,
	emailId: string,
	attachments?: {
		id: string;
		content_id?: string | null;
		disposition?: string | null;
	}[],
): string {
	if (!body || !attachments?.length) return body;
	let result = body;
	for (const att of attachments) {
		if (att.disposition === "inline" && att.content_id) {
			const url = `/api/v1/mailboxes/${mailboxId}/emails/${emailId}/attachments/${att.id}`;
			// Strip angle brackets from content_id if present
			const cid = att.content_id.startsWith("<")
				? att.content_id.slice(1, -1)
				: att.content_id;
			result = result.replace(
				new RegExp(`cid:${cid.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "gi"),
				url,
			);
		}
	}
	return result;
}

export function getNonInlineAttachments(
	attachments?: Attachment[],
): Attachment[] {
	return (
		attachments?.filter((attachment) => attachment.disposition !== "inline") ??
		[]
	);
}

export function getAttachmentUrl(
	mailboxId: string,
	emailId: string,
	attachmentId: string,
): string {
	return `/api/v1/mailboxes/${mailboxId}/emails/${emailId}/attachments/${attachmentId}`;
}

export function downloadFile(url: string, filename: string) {
	const link = document.createElement("a");
	link.href = url;
	link.download = filename;
	link.target = "_blank";
	link.rel = "noopener noreferrer";
	document.body.appendChild(link);
	link.click();
	document.body.removeChild(link);
}
