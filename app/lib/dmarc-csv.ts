// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Pure CSV-generation helpers for the DMARC sending-sources export.
 * Kept in a separate module so they can be unit-tested in the node
 * environment without pulling in any React or JSX dependencies.
 */

export interface DmarcSourceForCsv {
	source_ip: string;
	total_count: number;
	pass_count: number;
	quarantine_count: number;
	reject_count: number;
}

/**
 * Wraps a value in double quotes and escapes any embedded double quotes as `""`.
 * Newlines are replaced with a space to keep each CSV record on one line.
 */
export function csvField(v: string | number | boolean): string {
	return '"' + String(v).replace(/"/g, '""').replace(/\r?\n/g, " ") + '"';
}

const CSV_HEADERS = ["source_ip", "label", "message_count", "pass_count", "fail_count", "legitimate"];

/**
 * Converts a DmarcSource array into a well-formed CSV string.
 * - All fields are double-quoted.
 * - Embedded double quotes are escaped as `""`.
 * - `label` is left empty (not present in the summary rollup).
 * - `fail_count` = quarantine_count + reject_count.
 * - `legitimate` = true when pass_count equals total_count and total_count > 0.
 */
export function buildDmarcCsv(sources: DmarcSourceForCsv[]): string {
	const header = CSV_HEADERS.map(csvField).join(",");
	const rows = sources.map((s) => {
		const failCount = s.quarantine_count + s.reject_count;
		const legitimate = s.total_count > 0 && s.pass_count === s.total_count;
		return [
			csvField(s.source_ip),
			csvField(""),
			csvField(s.total_count),
			csvField(s.pass_count),
			csvField(failCount),
			csvField(legitimate),
		].join(",");
	});
	return [header, ...rows].join("\r\n");
}
