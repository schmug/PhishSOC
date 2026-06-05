// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Hub reporting for aggregated catch-all probe indicators (#430).
 *
 * Publishes corroborated source IPs and sender domains observed probing
 * catch-all domains to the MISP-compatible community hub. Structurally
 * excludes PII: only `ip-src` and `domain` attribute types are produced;
 * local-parts and subject snippets never appear in the input type.
 *
 * The caller owns loading hub credentials and fetching the rollup from
 * `CatchallIntelDO` — this module is a pure reporting leaf so it can be
 * tested and used independently of those dependencies.
 */

import type { MispEvent } from "./report";
import { MispClient } from "./misp-client";
import type { HubConfig } from "../lib/hub-config";

/** Aggregated rollup row from `CatchallIntelDO.getCatchallSummary` (#425). */
export interface CatchallTopSource {
	source_ip: string;
	sender_domain: string;
	count: number;
	first_seen: string;
	last_seen: string;
}

/** Minimum summary shape needed for hub reporting — callers extract from the
 *  full `getCatchallSummary` response and pass it here. */
export interface CatchallSummaryForReport {
	topSources: CatchallTopSource[];
}

export interface ReportCatchallProbesOpts {
	hubConfig: HubConfig;
	apiKey: string;
	/** The catch-all domain (used in the event title). */
	domain: string;
	summary: CatchallSummaryForReport;
}

/**
 * Build a MISP-compatible event from aggregated catch-all probe rollups.
 *
 * Only `ip-src` (source IP) and `domain` (sender domain) attributes are
 * emitted. Local-parts, subject snippets, and full sender addresses are
 * absent from the input type and are never included.
 */
export async function buildCatchallMispEvent(opts: {
	orgUuid?: string;
	sharingGroupUuid?: string;
	domain: string;
	sources: CatchallTopSource[];
	observedAt?: string;
}): Promise<MispEvent> {
	const now = new Date();
	const observedAt = opts.observedAt ?? now.toISOString();
	const date = observedAt.slice(0, 10);
	const timestamp = Math.floor(now.getTime() / 1000).toString();

	const attrs: MispEvent["Event"]["Attribute"] = [];

	for (const src of opts.sources) {
		attrs.push({
			uuid: crypto.randomUUID(),
			type: "ip-src",
			category: "Network activity",
			value: src.source_ip,
			to_ids: true,
			comment: `catch-all probe: ${src.count} attempt(s) since ${src.first_seen}`,
		});
		if (src.sender_domain) {
			attrs.push({
				uuid: crypto.randomUUID(),
				type: "domain",
				category: "Network activity",
				value: src.sender_domain,
				to_ids: true,
			});
		}
	}

	return {
		Event: {
			uuid: crypto.randomUUID(),
			info: `Catch-all probe aggregation: ${opts.domain}`.slice(0, 256),
			date,
			timestamp,
			analysis: "1",
			threat_level_id: "2",
			distribution: opts.sharingGroupUuid ? "4" : "1",
			orgc_uuid: opts.orgUuid,
			sharing_group_uuid: opts.sharingGroupUuid,
			Tag: [
				{ name: 'type:"OSINT"' },
				{ name: 'tlp:"white"' },
				{ name: "catchall-probe" },
			],
			Attribute: attrs,
		},
	};
}

/**
 * Publish aggregated catch-all probe indicators to the community hub.
 *
 * Returns `{ posted: false }` without throwing when:
 *  - `hubConfig.auto_report` is not `true` (consent gate)
 *  - `summary.topSources` is empty (nothing to report)
 *  - The hub POST fails for any reason (best-effort, callers don't retry)
 */
export async function reportCatchallProbes(
	opts: ReportCatchallProbesOpts,
): Promise<{ posted: boolean; uuid?: string }> {
	if (!opts.hubConfig.auto_report) {
		return { posted: false };
	}
	if (opts.summary.topSources.length === 0) {
		return { posted: false };
	}

	const event = await buildCatchallMispEvent({
		orgUuid: opts.hubConfig.org_uuid,
		sharingGroupUuid: opts.hubConfig.default_sharing_group_uuid,
		domain: opts.domain,
		sources: opts.summary.topSources,
	});

	const client = new MispClient({
		baseUrl: opts.hubConfig.url,
		apiKey: opts.apiKey,
	});

	try {
		const result = await client.postEvent(event);
		if (result?.uuid) {
			return { posted: true, uuid: result.uuid };
		}
		return { posted: false };
	} catch {
		return { posted: false };
	}
}
