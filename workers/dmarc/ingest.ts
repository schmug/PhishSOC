// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * DMARC aggregate-report ingestion (RUA) and forensic-report ingestion (RUF).
 *
 * RUA reports arrive as email with a gzipped XML attachment. We divert them
 * out of the normal security pipeline and feed them into the per-mailbox DB.
 *
 * RUF reports (RFC 6591) are privacy-gated and opt-in per mailbox. They only
 * ingest when `ruf_ingestion.enabled === true` in the mailbox security settings.
 */

import type { Email } from "postal-mime";
import type { Env } from "../types";
import { getMailboxStub } from "../lib/email-helpers";
import { bufferToXmlText, gunzip, parseDmarcXml } from "./parser";
import { parseDmarcRuf } from "./ruf-parser";
import type { RufIngestionSettings } from "../security/defaults";

export { isDmarcRuf } from "./ruf-parser";

/** Heuristic: does this parsed email look like a DMARC aggregate report? */
export function isDmarcReport(parsed: Email): boolean {
	const from = parsed.from?.address?.toLowerCase() ?? "";
	const subject = (parsed.subject ?? "").toLowerCase();
	if (from.includes("dmarc") || from.includes("noreply-dmarc")) return true;
	if (subject.startsWith("report domain:") || subject.includes("dmarc aggregate report")) return true;
	for (const a of parsed.attachments ?? []) {
		const fn = (a.filename ?? "").toLowerCase();
		if (fn.endsWith(".xml.gz") || fn.endsWith(".xml.zip")) return true;
		const mt = (a.mimeType ?? "").toLowerCase();
		if (mt === "application/gzip" || mt === "application/zip" || mt === "application/xml") {
			if (fn.includes("!")) return true; // DMARC RUA conventionally names `example.com!google.com!start!end.xml.gz`
		}
	}
	return false;
}

export async function ingestDmarcReport(
	env: Env,
	mailboxId: string,
	messageId: string,
	parsed: Email,
): Promise<{ ingested: boolean; reason?: string }> {
	const attachments = parsed.attachments ?? [];
	let xmlText: string | null = null;

	for (const att of attachments) {
		const fn = (att.filename ?? "").toLowerCase();
		const raw = normalizeContent(att.content);
		if (!raw) continue;
		if (fn.endsWith(".xml.gz") || (att.mimeType ?? "").toLowerCase() === "application/gzip") {
			try {
				const decompressed = await gunzip(raw);
				xmlText = bufferToXmlText(decompressed);
				break;
			} catch (e) {
				console.error("dmarc gunzip failed:", (e as Error).message);
			}
		} else if (fn.endsWith(".xml")) {
			xmlText = bufferToXmlText(raw);
			break;
		}
		// .xml.zip: deferred — zip needs a proper parser. See plan M4 notes.
	}

	if (!xmlText) return { ingested: false, reason: "no decodable XML attachment" };

	const report = parseDmarcXml(xmlText);
	if (!report.policy_domain) return { ingested: false, reason: "no policy_domain in XML" };

	const stub = getMailboxStub(env, mailboxId);
	const reportRow = {
		id: messageId,
		received_at: new Date().toISOString(),
		org_name: report.org_name ?? null,
		report_id: report.report_id ?? null,
		domain: report.policy_domain,
		date_range_begin: report.date_range_begin ?? null,
		date_range_end: report.date_range_end ?? null,
		policy_p: report.policy_p ?? null,
		policy_adkim: report.policy_adkim ?? null,
		policy_aspf: report.policy_aspf ?? null,
		policy_sp: report.policy_sp ?? null,
		policy_pct: report.policy_pct ?? null,
		raw_r2_key: null,
	};
	const recordsToInsert = report.records.map((r) => ({
		id: crypto.randomUUID(),
		source_ip: r.source_ip,
		count: r.count,
		disposition: r.disposition ?? null,
		dkim_result: r.dkim_result ?? null,
		spf_result: r.spf_result ?? null,
		header_from: r.header_from ?? null,
		auth_results_json: r.auth_results ? JSON.stringify(r.auth_results) : null,
	}));
	await stub.insertDmarcReport(reportRow, recordsToInsert);

	return { ingested: true };
}

function normalizeContent(content: unknown): ArrayBuffer | null {
	if (!content) return null;
	if (content instanceof ArrayBuffer) return content;
	if (ArrayBuffer.isView(content)) {
		return (content.buffer as ArrayBuffer).slice(content.byteOffset, content.byteOffset + content.byteLength);
	}
	if (typeof content === "string") {
		return new TextEncoder().encode(content).buffer as ArrayBuffer;
	}
	return null;
}

/** Rate-limit: max RUF reports accepted per mailbox per minute (issue #171). */
const RUF_RATE_LIMIT_PER_MINUTE = 100;

/**
 * Ingest a DMARC RUF forensic report (RFC 6591) into the per-mailbox DB.
 *
 * Returns early with `{ ingested: false, reason }` when:
 * - `settings.enabled` is false (opt-out path — report silently dropped)
 * - The report exceeds the 5 MB payload cap
 * - The mailbox has hit the 100-reports/minute rate limit
 * - The `message/feedback-report` part is missing or undecodable
 */
export async function ingestDmarcRuf(
	env: Env,
	mailboxId: string,
	messageId: string,
	parsed: Email,
	settings: RufIngestionSettings,
): Promise<{ ingested: boolean; reason?: string }> {
	if (!settings.enabled) {
		return { ingested: false, reason: "ruf_ingestion disabled for this mailbox" };
	}

	const stub = getMailboxStub(env, mailboxId);

	// Rate-limit: count reports received in the last 60 seconds.
	const rateLimitWindowStart = new Date(Date.now() - 60_000).toISOString();
	const recentCount = await stub.countDmarcRufRecordsSince(rateLimitWindowStart);
	if (recentCount >= RUF_RATE_LIMIT_PER_MINUTE) {
		return { ingested: false, reason: `rate limit exceeded (${recentCount} reports in the last 60s)` };
	}

	let record;
	try {
		record = parseDmarcRuf(parsed, settings.retain_raw);
	} catch (e) {
		return { ingested: false, reason: (e as Error).message };
	}

	if (!record) {
		return { ingested: false, reason: "no message/feedback-report part found" };
	}

	await stub.insertDmarcRufRecord({
		id: messageId,
		received_at: new Date().toISOString(),
		original_mail_from: record.original_mail_from,
		source_ip: record.source_ip,
		failure_type: record.failure_type,
		reported_domain: record.reported_domain,
		feedback_type: record.feedback_type,
		auth_results: record.auth_results,
		original_headers: record.original_headers,
	});

	return { ingested: true };
}
