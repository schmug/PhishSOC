// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Per-domain inline-gateway relay policy resolution (issue #32).
 *
 * `RelaySettings` (shared/domain-settings.ts) is all-optional so
 * absent-key-inherits semantics hold; the defaults live here. A policy
 * only resolves when `enabled` is true AND a target host is configured —
 * everything else about the domain behaves exactly as before.
 */

import type { DomainSettings, RelayActionBehavior } from "../../shared/domain-settings";
import type { VerdictAction } from "../security/verdict";

export interface ResolvedRelayPolicy {
	target: { host: string; port: number; implicitTls: boolean };
	credentialsSecret?: string;
	actions: Record<VerdictAction, RelayActionBehavior>;
}

/**
 * Fail-closed defaults: quarantine holds locally, block drops. Relaying a
 * quarantine/block verdict requires an explicit per-domain override.
 */
export const DEFAULT_RELAY_ACTIONS: Record<VerdictAction, RelayActionBehavior> = {
	allow: "relay",
	tag: "relay",
	quarantine: "hold",
	block: "drop",
};

export function resolveRelayPolicy(settings: DomainSettings): ResolvedRelayPolicy | null {
	const relay = settings.relay;
	if (!relay?.enabled) return null;
	const host = relay.target?.host;
	if (!host) return null;
	return {
		target: {
			host,
			port: relay.target?.port ?? 587,
			implicitTls: relay.target?.implicitTls ?? false,
		},
		credentialsSecret: relay.credentialsSecret,
		actions: { ...DEFAULT_RELAY_ACTIONS, ...(relay.actions ?? {}) },
	};
}

/**
 * Map a verdict action to a relay behavior.
 *
 * - `null` verdict (pipeline skipped or threw) fails OPEN to `relay`: a
 *   gateway must never eat mail because scanning broke. The stored mirror
 *   copy (registered mailboxes) still preserves auditability.
 * - `passthrough` (unregistered recipient): `hold` degrades to `relay` —
 *   there is no mailbox to hold into, and delivering tagged beats losing
 *   mail. `drop` is honoured as configured.
 */
export function behaviorFor(
	action: VerdictAction | null,
	policy: ResolvedRelayPolicy,
	opts?: { passthrough?: boolean },
): RelayActionBehavior {
	if (action === null) return "relay";
	let behavior = policy.actions[action];
	if (opts?.passthrough && behavior === "hold") behavior = "relay";
	return behavior;
}
