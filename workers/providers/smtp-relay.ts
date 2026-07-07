// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Outbound relay provider for inline-gateway mode (issue #32).
 *
 * Relays the raw (verdict-header-prepended, ARC-sealed) RFC-5322 bytes to
 * the per-domain SMTP submission target. Credentials come from a Worker
 * Secret named by the policy (`{"user":"...","pass":"..."}` JSON) — never
 * from R2 settings blobs.
 *
 * A missing/malformed credentials secret is a PERMANENT failure: retrying
 * won't fix operator misconfiguration, and the caller alerts on it.
 */

import type { Env } from "../types";
import type { ResolvedRelayPolicy } from "../lib/relay-policy";
import { SmtpPermanentError, submitRaw, type SmtpConnectFn } from "../lib/smtp-client";

export interface RelayEnvelope {
	mailFrom: string;
	rcptTo: string;
}

export class SmtpRelayProvider {
	readonly id = "smtp-relay";

	async relayRaw(
		env: Env,
		raw: Uint8Array,
		envelope: RelayEnvelope,
		policy: ResolvedRelayPolicy,
		connectFn?: SmtpConnectFn,
	): Promise<void> {
		let auth: { user: string; pass: string } | undefined;
		if (policy.credentialsSecret) {
			const secret = (env as unknown as Record<string, unknown>)[policy.credentialsSecret];
			if (typeof secret !== "string" || secret.length === 0) {
				throw new SmtpPermanentError(
					`relay credentials secret ${policy.credentialsSecret} is not configured`,
				);
			}
			let parsed: { user?: unknown; pass?: unknown };
			try {
				parsed = JSON.parse(secret) as { user?: unknown; pass?: unknown };
			} catch {
				throw new SmtpPermanentError(
					`relay credentials secret ${policy.credentialsSecret} is not valid JSON`,
				);
			}
			if (typeof parsed.user !== "string" || typeof parsed.pass !== "string") {
				throw new SmtpPermanentError(
					`relay credentials secret ${policy.credentialsSecret} must be {"user","pass"} JSON`,
				);
			}
			auth = { user: parsed.user, pass: parsed.pass };
		}

		await submitRaw({
			host: policy.target.host,
			port: policy.target.port,
			implicitTls: policy.target.implicitTls,
			auth,
			mailFrom: envelope.mailFrom,
			rcptTo: envelope.rcptTo,
			raw,
			connectFn,
		});
	}
}

export const smtpRelayProvider = new SmtpRelayProvider();
