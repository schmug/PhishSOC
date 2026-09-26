// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Client helpers for the outbound send-risk preview (see
 * workers/security/send-risk.ts). Kept apart from the step-up relay so
 * callers and tests can use them without the WebAuthn plumbing.
 */

import { ApiError } from "~/services/api";

export interface SendRiskPreview {
	tier: 0 | 1 | 2;
	reasons: string[];
}

/**
 * The server's send-risk result when a send was rejected for needing a higher
 * step-up tier than the client confirmed at — e.g. a rule the preflight could
 * not see, or a body edited after the last preflight. Callers adopt it so the
 * next attempt steps up at the right tier (and asks for the typed phrase at
 * tier 2). Null for any other error.
 */
export function serverRequiredRisk(err: unknown): SendRiskPreview | null {
	if (!(err instanceof ApiError) || err.status !== 401 || err.body.error !== "confirmation_required") return null;
	const risk = err.body.risk as { tier?: unknown; reasons?: unknown } | undefined;
	if (!risk || (risk.tier !== 1 && risk.tier !== 2) || !Array.isArray(risk.reasons)) return null;
	return { tier: risk.tier, reasons: risk.reasons.filter((r): r is string => typeof r === "string") };
}

export function requiredRiskMessage(risk: SendRiskPreview): string {
	const what = risk.tier === 2 ? "passkey confirmation and the typed recipient" : "passkey confirmation";
	const why = risk.reasons.length > 0 ? ` (${risk.reasons.join("; ")})` : "";
	return `This send needs ${what}${why}. Review and send again.`;
}
