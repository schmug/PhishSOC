// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * MISP-compatible threat-intel hub configuration. Resolved through the
 * inheritance hierarchy from #106 (mailbox > org > system default), so an
 * org-level hub config takes effect for every mailbox that doesn't carry
 * its own. The API key itself is NOT stored in R2 — the JSON only carries
 * the secret *name* via `api_key_secret_name`, and the worker resolves it
 * from `c.env` at call time so an org can rotate without rewriting blobs.
 */

import { getDomainSettings } from "./domain-settings";
import { hostAllowed } from "./host-allowlist";
import { resolveMailboxSettings } from "./mailbox-settings";
import { getOrgSettings } from "./org-settings";

export interface HubConfig {
	url: string;
	org_uuid: string;
	api_key_secret_name: string;
	default_sharing_group_uuid?: string;
	auto_report?: boolean;
}

interface BucketEnv {
	BUCKET: R2Bucket;
	/** Operator-set hostname allowlist for `cfg.url` — see `workers/types.ts`. */
	HUB_ALLOWED_HOSTS?: string;
}

/**
 * Validate a raw `intel.hub` block into a complete, destination-pinned
 * `HubConfig`, or null when incomplete / unsafe. Shared by the mailbox-scoped
 * and domain-scoped resolvers so both enforce the identical security checks:
 * required fields, `HUB_SECRET_` secret-name prefix, and `HUB_ALLOWED_HOSTS`
 * destination pinning (GHSA-jfj6-w954-96vg f29).
 */
function validateHubConfig(env: BucketEnv, raw: unknown): HubConfig | null {
	if (!raw || typeof raw !== "object") return null;
	const cfg = raw as Partial<HubConfig>;
	if (!cfg.url || !cfg.org_uuid || !cfg.api_key_secret_name) return null;
	// Prevent confused deputy / secret exfiltration via unconstrained secret access.
	// Only allow access to explicitly designated hub secrets.
	if (!cfg.api_key_secret_name.startsWith("HUB_SECRET_")) return null;
	// Pin the destination too (GHSA-jfj6-w954-96vg f29): `cfg.url` is
	// teammate-editable settings data, so the secret named above may only be
	// sent to an https host on the operator-set `HUB_ALLOWED_HOSTS` env
	// allowlist. Off-allowlist (or no allowlist configured) → treat the hub
	// as not configured rather than ship the credential to an arbitrary URL.
	if (!hostAllowed(cfg.url, env.HUB_ALLOWED_HOSTS)) return null;
	return {
		url: cfg.url,
		org_uuid: cfg.org_uuid,
		api_key_secret_name: cfg.api_key_secret_name,
		default_sharing_group_uuid: cfg.default_sharing_group_uuid,
		auto_report: cfg.auto_report ?? false,
	};
}

/** Returns the resolved hub config for a mailbox, or null when neither
 *  tier supplies a complete one. */
export async function loadHubConfig(
	env: BucketEnv,
	mailboxId: string,
): Promise<HubConfig | null> {
	const resolved = await resolveMailboxSettings(env, mailboxId);
	return validateHubConfig(env, resolved.intel.hub);
}

/**
 * Domain-scoped hub config for the catch-all path (#437), which has no mailbox.
 * Resolves `intel.hub` from the domain settings, falling back to the org tier
 * (`domain > org`, mirroring the mailbox resolver minus the per-mailbox tier).
 * Returns null when neither tier supplies a complete, allowlisted config.
 */
export async function loadHubConfigForDomain(
	env: BucketEnv,
	domain: string,
): Promise<HubConfig | null> {
	const domainSettings = await getDomainSettings(env, domain);
	const domainHub = (domainSettings.intel as { hub?: unknown } | undefined)?.hub;
	if (domainHub) {
		const cfg = validateHubConfig(env, domainHub);
		if (cfg) return cfg;
	}
	const org = await getOrgSettings(env);
	return validateHubConfig(env, (org.intel as { hub?: unknown } | undefined)?.hub);
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
	const apiKey = env[cfg.api_key_secret_name];
	if (typeof apiKey !== "string" || !apiKey) return null;
	return { cfg, apiKey };
}

/**
 * Domain-scoped variant of `loadHubCredentials` for the catch-all path (#437).
 * Resolves the hub config from the domain (then org) tier and the live API key
 * from the named secret. Returns null if either is missing.
 */
export async function loadHubCredentialsForDomain(
	env: Record<string, unknown> & BucketEnv,
	domain: string,
): Promise<{ cfg: HubConfig; apiKey: string } | null> {
	const cfg = await loadHubConfigForDomain(env, domain);
	if (!cfg) return null;
	const apiKey = env[cfg.api_key_secret_name];
	if (typeof apiKey !== "string" || !apiKey) return null;
	return { cfg, apiKey };
}
