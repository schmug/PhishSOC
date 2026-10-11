// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sender blocklist rule schema + validation, shared by the UI and Workers.
 * Rules live in a top-level `blocklist` field on the mailbox / domain / org
 * settings blobs (never under `security`, which whole-replaces across tiers).
 * Spec: docs/superpowers/specs/2026-09-27-sender-blocklist-design.md
 */

import { z } from "zod";

export const BlockAction = z.enum(["drop", "reject", "spam"]);
export type BlockAction = z.infer<typeof BlockAction>;

export const BlockRule = z.object({
	id: z.string().min(1),
	match: z.string().min(1),
	action: BlockAction,
	reason: z.string().max(200).optional(),
	created_at: z.string(),
});
export type BlockRule = z.infer<typeof BlockRule>;

export const Blocklist = z.array(BlockRule).max(1000);

export const DEFAULT_REJECT_REASON = "Unsolicited commercial email refused by recipient";

/** Two-label public suffixes common enough to guard against. Not a full PSL:
 *  the guard only refuses obviously-too-broad rules. Single-label domains
 *  (`com`) are refused separately. */
const MULTI_LABEL_PUBLIC_SUFFIXES: ReadonlySet<string> = new Set([
	"co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
	"com.au", "net.au", "org.au", "edu.au", "gov.au",
	"co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "co.za", "co.in",
	"com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.hk",
]);

/** Freemail + ESP bounce domains: a domain rule here blocks unrelated senders. */
export const SHARED_SENDER_DOMAINS: ReadonlySet<string> = new Set([
	"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
	"yahoo.com", "icloud.com", "aol.com", "proton.me", "protonmail.com",
	"sendgrid.net", "amazonses.com", "resend.dev", "mailgun.org",
]);

const HOST_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;

/** Lowercase + IDNA A-label a bare hostname. Null when it is not one. */
export function toALabel(domain: string): string | null {
	const d = domain.trim();
	if (!d || /[\s/:?#@\\]/.test(d)) return null;
	try {
		const host = new URL(`http://${d}`).hostname;
		return HOST_RE.test(host) ? host : null;
	} catch {
		return null;
	}
}

export function normalizeMatch(raw: string): { kind: "address" | "domain"; value: string } | null {
	const v = raw.trim();
	if (!v) return null;
	const at = v.indexOf("@");
	if (at === -1) {
		const host = toALabel(v);
		return host ? { kind: "domain", value: host } : null;
	}
	if (at !== v.lastIndexOf("@")) return null;
	const local = v.slice(0, at);
	if (!local || /[\s]/.test(local)) return null;
	const host = toALabel(v.slice(at + 1));
	return host ? { kind: "address", value: `${local.toLowerCase()}@${host}` } : null;
}

export function isPublicSuffix(domain: string): boolean {
	return !domain.includes(".") || MULTI_LABEL_PUBLIC_SUFFIXES.has(domain);
}

export function registrableDomain(domain: string): string {
	const labels = domain.split(".");
	if (labels.length <= 2) return domain;
	const lastTwo = labels.slice(-2).join(".");
	return MULTI_LABEL_PUBLIC_SUFFIXES.has(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

export function sanitizeRejectReason(raw: string | undefined): string {
	const cleaned = (raw ?? "").replace(/[^\x20-\x7e]/g, "").trim().slice(0, 200);
	return cleaned || DEFAULT_REJECT_REASON;
}

export interface BlockRuleInput {
	match: string;
	action: BlockAction;
	reason?: string;
	confirm_shared_domain?: boolean;
}

export type BlockRuleValidation =
	| { ok: true; rule: { match: string; action: BlockAction; reason?: string } }
	| { ok: false; code: "invalid_match" | "invalid_action" | "public_suffix" | "shared_domain_unconfirmed"; error: string };

export function validateBlockRuleInput(input: BlockRuleInput): BlockRuleValidation {
	const action = BlockAction.safeParse(input?.action);
	if (!action.success) return { ok: false, code: "invalid_action", error: "action must be drop, reject or spam" };
	const m = typeof input.match === "string" ? normalizeMatch(input.match) : null;
	if (!m) return { ok: false, code: "invalid_match", error: "match must be an email address or a domain" };
	if (m.kind === "domain") {
		if (isPublicSuffix(m.value)) {
			return { ok: false, code: "public_suffix", error: `${m.value} is a public suffix; block a specific domain instead` };
		}
		if (SHARED_SENDER_DOMAINS.has(m.value) && input.confirm_shared_domain !== true) {
			return {
				ok: false,
				code: "shared_domain_unconfirmed",
				error: `${m.value} is shared by many unrelated senders; confirm to block the whole domain`,
			};
		}
	}
	const rule: { match: string; action: BlockAction; reason?: string } = { match: m.value, action: action.data };
	if (action.data === "reject") rule.reason = sanitizeRejectReason(input.reason);
	return { ok: true, rule };
}
