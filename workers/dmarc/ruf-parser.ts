// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * DMARC RUF (forensic report) parser — RFC 6591 / ARF (Abuse Reporting Format).
 *
 * DMARC forensic reports are multipart/report messages containing:
 *   Part 1: text/plain (human-readable)
 *   Part 2: message/feedback-report (machine-readable ARF headers)
 *   Part 3: message/rfc822 or text/rfc822-headers (original failing message, optional)
 *
 * We only parse the machine-readable Part 2. Part 3 (original message) is
 * stored only when `retain_raw === true` and is stripped of PII fields
 * (`To`, `Cc`, `Bcc`, `Subject`) before storage.
 *
 * RUF reception is opt-in per mailbox and privacy-gated by default. See
 * `workers/security/defaults.ts → RufIngestionSettings`.
 */

import type { Email } from "postal-mime";

export interface DmarcRufRecord {
	/** Originating email address from the `Original-Mail-From` ARF field. */
	original_mail_from: string | null;
	/** Source IP from the `Source-IP` ARF field. */
	source_ip: string | null;
	/** Failure type: dkim | spf | dkim-adsp | bodyhash | revoked | arc */
	failure_type: string | null;
	/** Reported domain from the `Reported-Domain` ARF field. */
	reported_domain: string | null;
	/** ARF Feedback-Type value (always "auth-failure" for DMARC RUF). */
	feedback_type: string | null;
	/** Authentication-Results header from the original message (abbreviated). */
	auth_results: string | null;
	/**
	 * Redacted RFC 822 headers of the original failing message. Populated
	 * only when `retain_raw === true`; PII fields (`To`, `Cc`, `Bcc`,
	 * `Subject`) are always masked.
	 */
	original_headers: string | null;
}

/** Maximum accepted raw attachment size per RUF report (bytes). */
export const RUF_MAX_PAYLOAD_BYTES = 5 * 1024 * 1024; // 5 MB

/**
 * Heuristic: does this parsed email look like a DMARC forensic report?
 *
 * RUF reports carry a `message/feedback-report` MIME part (RFC 6591 §3).
 * We require that part — subject-only keywords like "auth-failure" are too
 * broad and previously let phishing skip the inbound security pipeline when
 * `receiveEmail` returned early on a failed/disabled ingest.
 */
export function isDmarcRuf(parsed: Email): boolean {
	for (const att of parsed.attachments ?? []) {
		const mt = (att.mimeType ?? "").toLowerCase();
		if (mt === "message/feedback-report") return true;
	}
	return false;
}

/**
 * Extract a named header value from a raw RFC 2822 / ARF header block.
 * Header names are case-insensitive per RFC 5321.
 */
function extractHeader(raw: string, name: string): string | null {
	const re = new RegExp(`^${name}\\s*:\\s*(.+)$`, "im");
	const m = raw.match(re);
	return m ? m[1].trim() : null;
}

/**
 * Redact PII-carrying headers in a raw RFC 2822 header block. Replaces
 * the values of `To`, `Cc`, `Bcc`, and `Subject` with `<redacted>` so
 * operators see the header structure without the content.
 */
function redactHeaders(raw: string): string {
	return raw.replace(
		/^(To|Cc|Bcc|Subject)\s*:.*$/gim,
		(_m, name: string) => `${name}: <redacted>`,
	);
}

/**
 * Parse a DMARC RUF report from a `postal-mime` parsed email.
 *
 * @param parsed    The fully parsed inbound email.
 * @param retainRaw Whether to store original headers (privacy gate).
 * @returns         Parsed record, or null if no machine-readable part found.
 * @throws          If any attachment exceeds `RUF_MAX_PAYLOAD_BYTES`.
 */
export function parseDmarcRuf(
	parsed: Email,
	retainRaw: boolean,
): DmarcRufRecord | null {
	let feedbackBody: string | null = null;
	let originalHeaders: string | null = null;

	for (const att of parsed.attachments ?? []) {
		const mt = (att.mimeType ?? "").toLowerCase();

		// Enforce size cap before decoding.
		const size =
			att.content instanceof ArrayBuffer
				? att.content.byteLength
				: ArrayBuffer.isView(att.content)
					? att.content.byteLength
					: typeof att.content === "string"
						? att.content.length
						: 0;
		if (size > RUF_MAX_PAYLOAD_BYTES) {
			throw new Error(`RUF attachment too large: ${size} bytes (limit ${RUF_MAX_PAYLOAD_BYTES})`);
		}

		if (mt === "message/feedback-report" && feedbackBody === null) {
			feedbackBody = decodeContent(att.content);
		} else if (
			(mt === "message/rfc822" || mt === "text/rfc822-headers") &&
			originalHeaders === null &&
			retainRaw
		) {
			// Store only the header section (up to the first blank line).
			const raw = decodeContent(att.content);
			if (raw) {
				const headerSection = raw.split(/\r?\n\r?\n/)[0] ?? raw;
				originalHeaders = redactHeaders(headerSection);
			}
		}
	}

	if (!feedbackBody) return null;

	return {
		original_mail_from: extractHeader(feedbackBody, "Original-Mail-From"),
		source_ip: extractHeader(feedbackBody, "Source-IP"),
		failure_type: extractHeader(feedbackBody, "Failure-Type"),
		reported_domain: extractHeader(feedbackBody, "Reported-Domain"),
		feedback_type: extractHeader(feedbackBody, "Feedback-Type"),
		auth_results: extractHeader(feedbackBody, "Authentication-Results"),
		original_headers: originalHeaders,
	};
}

function decodeContent(content: unknown): string | null {
	if (!content) return null;
	if (typeof content === "string") return content;
	if (content instanceof ArrayBuffer) {
		return new TextDecoder("utf-8", { fatal: false }).decode(content);
	}
	if (ArrayBuffer.isView(content)) {
		return new TextDecoder("utf-8", { fatal: false }).decode(content as BufferSource);
	}
	return null;
}
