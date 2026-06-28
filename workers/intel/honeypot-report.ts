// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Honeypot inbound IOC publishing (issue #24).
 *
 * Everything that lands in a honeypot is unsolicited by construction, so its
 * URL / sender / attachment IOCs are extremely high-signal with no
 * legitimate-sender false-positive risk. This module builds a MISP event for a
 * single honeypot capture with ELEVATED trust (highest threat level + a
 * `honeypot` tag) and posts it to the configured hub.
 *
 * Reuses `buildMispEvent` for the attribute/anonymization policy (recipients
 * stripped, body replaced with a hash, URLs kept verbatim) and only overrides
 * the trust signals — so the no-PII guarantees from `report.ts` hold here too.
 */

import type { Email } from "postal-mime";
import { extractUrls } from "../security/urls";
import type { HubConfig } from "../lib/hub-config";
import { MispClient } from "./misp-client";
import { buildMispEvent, type LocalPhishReportInput, type MispEvent } from "./report";

/**
 * Build a MISP event for a honeypot capture: identical to `buildMispEvent` but
 * with elevated trust — `threat_level_id: "1"` (high) and a `honeypot` tag so
 * downstream consumers can weight these IOCs above ordinary user reports.
 */
export async function buildHoneypotMispEvent(input: LocalPhishReportInput): Promise<MispEvent> {
	const event = await buildMispEvent(input);
	event.Event.threat_level_id = "1";
	event.Event.Tag.push({ name: "honeypot" });
	return event;
}

export interface ReportHoneypotInboundOpts {
	hubConfig: HubConfig;
	apiKey: string;
	/** The honeypot mailbox id (used only for the event title). */
	mailboxId: string;
	parsedEmail: Email;
}

/** Parse a URL's hostname; null when it has no parseable host. */
function hostnameOf(url: string): string | null {
	try {
		return new URL(url).hostname;
	} catch {
		return null;
	}
}

/**
 * Publish a honeypot's inbound IOCs to the hub with elevated trust. Gated on
 * `hubConfig.auto_report` (consent) and a non-empty sender. Best-effort — the
 * caller treats any failure as a no-op; this never throws on a hub error.
 */
export async function reportHoneypotInbound(
	opts: ReportHoneypotInboundOpts,
): Promise<{ posted: boolean; uuid?: string }> {
	if (!opts.hubConfig.auto_report) return { posted: false };
	const sender = opts.parsedEmail.from?.address ?? "";
	if (!sender) return { posted: false };

	const body = opts.parsedEmail.html ?? opts.parsedEmail.text ?? "";
	const urls = extractUrls(body)
		.map((u) => ({ url: u.url, hostname: hostnameOf(u.url) }))
		.filter((u): u is { url: string; hostname: string } => u.hostname !== null);

	const event = await buildHoneypotMispEvent({
		orgUuid: opts.hubConfig.org_uuid,
		sharingGroupUuid: opts.hubConfig.default_sharing_group_uuid,
		info: `Honeypot capture (${opts.mailboxId}): ${sender}`,
		observedAt: new Date().toISOString(),
		sender,
		subject: opts.parsedEmail.subject ?? "",
		bodyText: opts.parsedEmail.text ?? "",
		urls,
	});

	const client = new MispClient({ baseUrl: opts.hubConfig.url, apiKey: opts.apiKey });
	const res = await client.postEvent(event);
	return res ? { posted: true, uuid: res.uuid } : { posted: false };
}
