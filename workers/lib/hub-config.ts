// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * MISP-compatible threat-intel hub configuration. Resolved through the
 * inheritance hierarchy from #106 (mailbox > org > system default), so an
 * org-level hub config takes effect for every mailbox that doesn't carry
 * its own. The API key itself is NOT stored in R2 — the JSON only carries
 * the secret *name* via `api_key_secret_name`, and the worker resolves it
 * from `c.env` at call time so an org can rotate without rewriting blobs.
 */

import { resolveMailboxSettings } from "./mailbox-settings";

export interface HubConfig {
	url: string;
	org_uuid: string;
	api_key_secret_name: string;
	default_sharing_group_uuid?: string;
	auto_report?: boolean;
}

interface BucketEnv {
	BUCKET: R2Bucket;
}

/** Returns the resolved hub config for a mailbox, or null when neither
 *  tier supplies a complete one. */
export async function loadHubConfig(
	env: BucketEnv,
	mailboxId: string,
): Promise<HubConfig | null> {
	const resolved = await resolveMailboxSettings(env, mailboxId);
	const raw = resolved.intel.hub;
	if (!raw || typeof raw !== "object") return null;
	const cfg = raw as Partial<HubConfig>;
	if (!cfg.url || !cfg.org_uuid || !cfg.api_key_secret_name) return null;
	return {
		url: cfg.url,
		org_uuid: cfg.org_uuid,
		api_key_secret_name: cfg.api_key_secret_name,
		default_sharing_group_uuid: cfg.default_sharing_group_uuid,
		auto_report: cfg.auto_report ?? false,
	};
}

/**
 * Resolve a hub config + the live API key. Returns null if either the config
 * is missing or the named secret is unset on `env`. Callers that need the
 * "configured but unhealthy" distinction should branch on which side returned
 * null — for the read-only hub UI we treat both as "not configured" so the
 * empty state has one shape.
 */
export async function loadHubCredentials(
	env: Record<string, unknown> & BucketEnv,
	mailboxId: string,
): Promise<{ cfg: HubConfig; apiKey: string } | null> {
	const cfg = await loadHubConfig(env, mailboxId);
	if (!cfg) return null;
	// Prevent confused deputy / secret exfiltration via unconstrained secret access.
	// Only allow access to explicitly designated hub secrets.
	if (!cfg.api_key_secret_name.startsWith("HUB_SECRET_")) return null;
	const apiKey = env[cfg.api_key_secret_name];
	if (typeof apiKey !== "string" || !apiKey) return null;
	return { cfg, apiKey };
}
