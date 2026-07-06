// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sidecar-config resolution (issue #31). Validates the raw `sidecar` block
 * off a mailbox-settings blob and fills defaults, mirroring
 * `validateHubConfig` in `workers/lib/hub-config.ts`: invalid or absent
 * config resolves to null (feature off) rather than throwing, so a
 * malformed blob can never crash the cron loop or the receive path.
 */

import { SidecarSettings } from "../../shared/mailbox-settings";

export interface SidecarConfig {
	provider: "workspace";
	credentials_secret_name: string;
	mode: "observe" | "active";
	quarantine_behavior: "label-only" | "label-and-archive";
	/** Days to keep message bodies before the reap job strips them. 0 = keep forever. */
	retention_days: number;
}

export const SIDECAR_DEFAULT_RETENTION_DAYS = 7;

/**
 * Resolve the sidecar config from a raw mailbox-settings object (the
 * unresolved per-mailbox tier — `resolveMailboxSettings(...).raw` or a
 * freshly parsed blob). Returns null when absent or invalid.
 */
export function sidecarConfigOf(raw: unknown): SidecarConfig | null {
	if (!raw || typeof raw !== "object") return null;
	const block = (raw as { sidecar?: unknown }).sidecar;
	if (!block) return null;
	const parsed = SidecarSettings.safeParse(block);
	if (!parsed.success) return null;
	return {
		provider: parsed.data.provider,
		credentials_secret_name: parsed.data.credentials_secret_name,
		mode: parsed.data.mode ?? "observe",
		quarantine_behavior: parsed.data.quarantine_behavior ?? "label-only",
		retention_days: parsed.data.retention_days ?? SIDECAR_DEFAULT_RETENTION_DAYS,
	};
}
