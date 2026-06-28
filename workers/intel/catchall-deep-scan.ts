// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Async deep-scan for high-score catch-all probes (#438, epic #423 Follow-up I).
 *
 * Runs OUT of band from `receiveCatchall` (dispatched via `ctx.waitUntil`) for
 * probes scoring at or above `catchall_intel.deep_scan_threshold`. It performs
 * exactly two enrichments and writes them back to the probe's `CatchallIntelDO`
 * sample row:
 *
 *   - RDAP domain age of the sender domain (`lookupDomainAge`)
 *   - redirect-chain resolution of the first message URL (`resolveUrl`)
 *
 * Hard scope boundaries (asserted by tests):
 *   - NO IP-reputation signals (that is the catch-all analyzer's job, #424).
 *   - NEVER touches any `MailboxDO` verdict — this is catch-all intel only.
 *
 * Both enrichments are best-effort: `lookupDomainAge` and `resolveUrl` already
 * swallow their own failures and return null, and the high-level functions are
 * injectable so unit tests can drive the write-back without the network.
 */

import { lookupDomainAge } from "./rdap";
import { resolveUrl } from "./url-resolver";
import type { CatchallDeepScanResult } from "../durableObject/catchall-intel";

export type { CatchallDeepScanResult };

/** The probe fields the deep-scan needs — no email body, no PII. */
export interface CatchallDeepScanProbe {
	/** `probe_recent.id` of the sample to write results back to. */
	sampleId: string;
	/** Sender domain whose RDAP age is looked up (empty ⇒ age skipped). */
	senderDomain: string;
	/** First message URL whose redirect chain is resolved (null ⇒ redirect skipped). */
	url: string | null;
}

/** Write-back target + injectable enrichment fns (defaults hit the network). */
export interface CatchallDeepScanContext {
	stub: { updateProbeDeepScan(sampleId: string, result: CatchallDeepScanResult): Promise<void> };
	/** Override the RDAP domain-age lookup (tests). */
	lookupDomainAge?: (domain: string) => Promise<{ age_days: number } | null>;
	/** Override the redirect-chain resolver (tests). */
	resolveUrl?: (url: string) => Promise<{ resolved: string; hops: number } | null>;
}

/**
 * Resolve RDAP domain age + the URL redirect chain for a high-score probe and
 * persist them to its sample row. Returns the written result. Never throws —
 * each enrichment degrades to null on failure, and the write-back is the only
 * side effect.
 */
export async function runCatchallDeepScan(
	probe: CatchallDeepScanProbe,
	ctx: CatchallDeepScanContext,
): Promise<CatchallDeepScanResult> {
	const ageFn = ctx.lookupDomainAge ?? ((d: string) => lookupDomainAge(d));
	const resolveFn = ctx.resolveUrl ?? ((u: string) => resolveUrl(u));

	const [age, resolved] = await Promise.all([
		probe.senderDomain ? ageFn(probe.senderDomain).catch(() => null) : Promise.resolve(null),
		probe.url ? resolveFn(probe.url).catch(() => null) : Promise.resolve(null),
	]);

	const result: CatchallDeepScanResult = {
		resolved_url: resolved?.resolved ?? null,
		domain_age_days: age?.age_days ?? null,
		redirect_chain_length: resolved?.hops ?? null,
	};

	await ctx.stub.updateProbeDeepScan(probe.sampleId, result);
	return result;
}
