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

export interface AuthDkimResult {
	domain?: string;
	selector?: string;
	result?: string;
}

export interface AuthSpfResult {
	domain?: string;
	result?: string;
}

export interface AuthResults {
	dkim: AuthDkimResult[];
	spf: AuthSpfResult[];
}

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

export interface DmarcRecord {
	source_ip: string;
	count: number;
	disposition?: string;
	dkim_result?: string;
	spf_result?: string;
	header_from?: string;
	auth_results?: AuthResults;
}

/** Gunzip an arraybuffer using the runtime's DecompressionStream. */
export async function gunzip(buf: ArrayBuffer): Promise<ArrayBuffer> {
	const stream = new Response(buf).body!.pipeThrough(new DecompressionStream("gzip"));
	return new Response(stream).arrayBuffer();
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

function parseAuthResults(scope: string): AuthResults | undefined {
	const ar = tag(scope, "auth_results") ?? "";
	const dkim: AuthDkimResult[] = allTags(ar, "dkim").map((d) => ({
		domain: tag(d, "domain"),
		selector: tag(d, "selector"),
		result: tag(d, "result"),
	}));
	const spf: AuthSpfResult[] = allTags(ar, "spf").map((s) => ({
		domain: tag(s, "domain"),
		result: tag(s, "result"),
	}));
	if (dkim.length === 0 && spf.length === 0) return undefined;
	return { dkim, spf };
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
		records.push({
			source_ip,
			count: Math.max(0, Math.min(1000000, parseInt(countStr, 10) || 0)),
			disposition: tag(policyEval, "disposition"),
			dkim_result: tag(policyEval, "dkim"),
			spf_result: tag(policyEval, "spf"),
			header_from: tag(identifiers, "header_from"),
			auth_results: parseAuthResults(rec),
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
