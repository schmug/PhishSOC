// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Minimal DMARC RUA (aggregate report) XML parser.
 *
 * DMARC's aggregate-feedback schema is small and fixed — see RFC 7489 §7.2.
 * A hand-written tag extractor is simpler than pulling in a full XML parser.
 * We only capture the fields needed for the dashboard and forger intel.
 */

export interface DmarcReport {
	org_name?: string;
	report_id?: string;
	date_range_begin?: string; // epoch seconds
	date_range_end?: string;
	policy_domain?: string;
	policy_p?: string;
	policy_adkim?: string;
	policy_aspf?: string;
	policy_sp?: string;
	policy_pct?: string;
	records: DmarcRecord[];
}

export interface DmarcAuthResultDkim {
	domain?: string;
	selector?: string;
	result?: string;
}

export interface DmarcAuthResultSpf {
	domain?: string;
	result?: string;
}

export interface DmarcAuthResults {
	dkim: DmarcAuthResultDkim[];
	spf: DmarcAuthResultSpf[];
}

export interface DmarcRecord {
	source_ip: string;
	count: number;
	disposition?: string;
	dkim_result?: string;
	spf_result?: string;
	header_from?: string;
	auth_results?: DmarcAuthResults;
}

/** Hard cap on decompressed DMARC RUA payload — mirrors the TLS-RPT / RUF siblings. */
export const DMARC_MAX_DECOMPRESSED_BYTES = 5 * 1024 * 1024;

/**
 * Gunzip an arraybuffer using the runtime's DecompressionStream.
 *
 * Reads chunks incrementally and stops as soon as accumulated bytes exceed
 * maxBytes, so a gzip bomb is rejected mid-stream rather than after the
 * full payload has been materialised in memory.
 *
 * Returns null when the cap is exceeded; throws on malformed gzip input.
 */
export async function gunzip(
	buf: ArrayBuffer,
	maxBytes: number = DMARC_MAX_DECOMPRESSED_BYTES,
): Promise<ArrayBuffer | null> {
	const stream = new Response(buf).body!.pipeThrough(new DecompressionStream("gzip"));
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	let accumulated = 0;
	let capExceeded = false;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			accumulated += value.byteLength;
			if (accumulated > maxBytes) {
				capExceeded = true;
				break;
			}
			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}
	if (capExceeded) return null;
	const out = new Uint8Array(accumulated);
	let offset = 0;
	for (const chunk of chunks) {
		out.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return out.buffer as ArrayBuffer;
}

/** Read the first XML-looking text out of a raw buffer. */
export function bufferToXmlText(buf: ArrayBuffer): string {
	return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

/**
 * Extract the text content of the first tag matching `name` within `scope`.
 * `name` is matched case-sensitively; DMARC XML uses lowercase throughout
 * the standard schema.
 */
function tag(scope: string, name: string): string | undefined {
	const re = new RegExp(`<${name}\\b[^>]*>([\\s\\S]*?)<\\/${name}>`, "i");
	const match = scope.match(re);
	return match?.[1]?.trim();
}

function allTags(scope: string, name: string): string[] {
	const re = new RegExp(`<${name}\\b[^>]*>([\\s\\S]*?)<\\/${name}>`, "gi");
	const out: string[] = [];
	for (const match of scope.matchAll(re)) out.push(match[1]);
	return out;
}

export function parseDmarcXml(xml: string): DmarcReport {
	const metadata = tag(xml, "report_metadata") ?? "";
	const policy = tag(xml, "policy_published") ?? "";

	const records: DmarcRecord[] = [];
	for (const rec of allTags(xml, "record")) {
		const row = tag(rec, "row") ?? "";
		const identifiers = tag(rec, "identifiers") ?? "";
		const policyEval = tag(row, "policy_evaluated") ?? "";
		const source_ip = tag(row, "source_ip")?.trim();
		if (!source_ip) continue;
		const countStr = tag(row, "count") ?? "0";

		const authResultsBlock = tag(rec, "auth_results") ?? "";
		const dkimEntries = allTags(authResultsBlock, "dkim").map((d) => ({
			domain: tag(d, "domain"),
			selector: tag(d, "selector"),
			result: tag(d, "result"),
		}));
		const spfEntries = allTags(authResultsBlock, "spf").map((s) => ({
			domain: tag(s, "domain"),
			result: tag(s, "result"),
		}));
		const auth_results: DmarcAuthResults | undefined =
			dkimEntries.length > 0 || spfEntries.length > 0
				? { dkim: dkimEntries, spf: spfEntries }
				: undefined;

		records.push({
			source_ip,
			count: Math.max(0, Math.min(1000000, parseInt(countStr, 10) || 0)),
			disposition: tag(policyEval, "disposition"),
			dkim_result: tag(policyEval, "dkim"),
			spf_result: tag(policyEval, "spf"),
			header_from: tag(identifiers, "header_from"),
			auth_results,
		});
	}

	return {
		org_name: tag(metadata, "org_name"),
		report_id: tag(metadata, "report_id"),
		date_range_begin: tag(tag(metadata, "date_range") ?? "", "begin"),
		date_range_end: tag(tag(metadata, "date_range") ?? "", "end"),
		policy_domain: tag(policy, "domain"),
		policy_p: tag(policy, "p"),
		policy_adkim: tag(policy, "adkim"),
		policy_aspf: tag(policy, "aspf"),
		policy_sp: tag(policy, "sp"),
		policy_pct: tag(policy, "pct"),
		records,
	};
}
