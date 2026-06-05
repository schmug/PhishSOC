// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Provider abstraction layer for mail ingress and egress.
 *
 * Inbound: each platform-specific adapter (CF Email Routing, Workspace,
 * Graph, IMAP) normalises its wire format into `NormalizedInbound` and
 * hands it to the shared pipeline in `workers/index.ts`.
 *
 * Outbound: MailProvider.send() is the single call-site for delivery;
 * the registry returns the right provider for a given mailbox.
 *
 * Adding a provider is a single new file under `workers/providers/` plus
 * a registry entry — no edits to `workers/security/`, `workers/intel/`,
 * or `workers/agent/`.
 */

import type { Email } from "postal-mime";
import type { Env } from "../types";
import type { SendEmailParams } from "../email-sender";

export type { Email };

/**
 * Inbound message destined for a registered mailbox.
 */
export interface MailboxInbound {
	kind: "mailbox";
	/** Raw bytes of the full RFC-5322 message. */
	rawEmail: ArrayBuffer;
	/** Normalised parsed representation (PostalMime `Email`). */
	parsedEmail: Email;
	/** The local-part@domain address that identifies the target mailbox. */
	mailboxId: string;
}

/**
 * Inbound message for a catch-all recipient on an owned+enabled domain.
 * There is no registered mailbox for this address; the message is scored
 * by the catch-all analyzer and persisted to `CatchallIntelDO`.
 */
export interface CatchallInbound {
	kind: "catchall";
	rawEmail: ArrayBuffer;
	parsedEmail: Email;
	/** Domain the recipient address belongs to. */
	domain: string;
	/** From `catchall_intel.retention_days` on the domain settings. */
	retentionDays: number;
	/** From `catchall_intel.sample_limit` on the domain settings. */
	sampleLimit: number;
}

/**
 * Parsed inbound message, normalised across inbound providers.
 * @deprecated Use `MailboxInbound | CatchallInbound` for discriminated dispatch.
 */
export type NormalizedInbound = MailboxInbound;

/**
 * Outbound message params — mirrors `SendEmailParams` so callers don't
 * have to change import paths.  Alias may diverge once multi-provider
 * outbound (e.g. Workspace send-as, M365 Graph) is implemented.
 */
export type NormalizedOutbound = SendEmailParams;

/**
 * Pluggable mail provider interface.
 *
 * `send` is required and handles outbound delivery.
 * `applyVerdict` is optional — sidecar providers (Workspace, M365) use
 * it to write labels/folder-moves back to the source inbox; CF Routing
 * has no inbox to label and leaves it undefined.
 */
export interface MailProvider {
	readonly id: string;
	send(env: Env, msg: NormalizedOutbound): Promise<{ messageId: string }>;
	applyVerdict?(env: Env, msg: MailboxInbound, verdict: unknown): Promise<void>;
}
