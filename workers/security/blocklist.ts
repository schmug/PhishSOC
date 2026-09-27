// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sender blocklist matcher. Pure — no I/O. Called from `receiveEmail` before
 * any storage. Precedence: mailbox > domain > org; address beats domain
 * within a tier; ties → strictest action. An allowlist entry suppresses a
 * block only from a strictly more specific tier. Any error fails open.
 * Spec: docs/superpowers/specs/2026-09-27-sender-blocklist-design.md
 */

import { toALabel, type BlockRule } from "../../shared/blocklist";

export type BlockTier = "mailbox" | "domain" | "org";
export interface BlockHit { rule: BlockRule; tier: BlockTier }
export interface TierInput {
	blocklist?: readonly BlockRule[];
	allowlist_senders?: readonly string[];
	allowlist_domains?: readonly string[];
}
export type TierInputs = Partial<Record<BlockTier, TierInput>>;
export interface ReceiveBlocked { action: "drop" | "reject"; ruleId: string; tier: BlockTier; reason?: string }

const TIER_RANK: Record<BlockTier, number> = { mailbox: 3, domain: 2, org: 1 };
const ACTION_RANK: Record<BlockRule["action"], number> = { reject: 3, drop: 2, spam: 1 };
const TIERS: BlockTier[] = ["mailbox", "domain", "org"];

export function normalizeSenderAddress(raw: string | null | undefined): string | null {
	const v = (raw ?? "").trim();
	const at = v.lastIndexOf("@");
	if (at <= 0 || at === v.length - 1) return null;
	const host = toALabel(v.slice(at + 1));
	return host ? `${v.slice(0, at).toLowerCase()}@${host}` : null;
}

function domainOf(sender: string): string {
	return sender.slice(sender.lastIndexOf("@") + 1);
}

function domainCovers(ruleDomain: string, senderDomain: string): boolean {
	return senderDomain === ruleDomain || senderDomain.endsWith(`.${ruleDomain}`);
}

export function ruleMatches(match: string, sender: string): "address" | "domain" | null {
	const m = match.toLowerCase();
	if (m.includes("@")) return m === sender ? "address" : null;
	return domainCovers(m, domainOf(sender)) ? "domain" : null;
}

function allowedAt(input: TierInput | undefined, sender: string): boolean {
	if (!input) return false;
	const d = domainOf(sender);
	return (
		(input.allowlist_senders ?? []).some((s) => s.toLowerCase() === sender) ||
		(input.allowlist_domains ?? []).some((a) => domainCovers(a.toLowerCase(), d))
	);
}

export function matchBlocklist(tiers: TierInputs, fromAddress: string | null | undefined): BlockHit | null {
	const sender = normalizeSenderAddress(fromAddress);
	if (!sender) return null;
	let best: { hit: BlockHit; kind: "address" | "domain" } | null = null;
	for (const tier of TIERS) {
		for (const rule of tiers[tier]?.blocklist ?? []) {
			const kind = ruleMatches(rule.match, sender);
			if (!kind) continue;
			const cand = { hit: { rule, tier }, kind };
			if (!best || better(cand, best)) best = cand;
		}
	}
	if (!best) return null;
	const winningRank = TIER_RANK[best.hit.tier];
	const suppressed = TIERS.some((t) => TIER_RANK[t] > winningRank && allowedAt(tiers[t], sender));
	return suppressed ? null : best.hit;
}

function better(
	a: { hit: BlockHit; kind: "address" | "domain" },
	b: { hit: BlockHit; kind: "address" | "domain" },
): boolean {
	const t = TIER_RANK[a.hit.tier] - TIER_RANK[b.hit.tier];
	if (t !== 0) return t > 0;
	if (a.kind !== b.kind) return a.kind === "address";
	return ACTION_RANK[a.hit.rule.action] > ACTION_RANK[b.hit.rule.action];
}

function tierInput(blob: unknown): TierInput | undefined {
	if (!blob || typeof blob !== "object") return undefined;
	const b = blob as { blocklist?: unknown; security?: { allowlist_senders?: unknown; allowlist_domains?: unknown } };
	const arr = (v: unknown) => (Array.isArray(v) ? v : undefined);
	return {
		blocklist: arr(b.blocklist) as BlockRule[] | undefined,
		allowlist_senders: arr(b.security?.allowlist_senders) as string[] | undefined,
		allowlist_domains: arr(b.security?.allowlist_domains) as string[] | undefined,
	};
}

export function tierInputsFromResolved(r: { raw?: unknown; domain?: unknown; org?: unknown }): TierInputs {
	return { mailbox: tierInput(r.raw), domain: tierInput(r.domain), org: tierInput(r.org) };
}

export function safeMatchBlocklist(
	r: { raw?: unknown; domain?: unknown; org?: unknown },
	fromAddress: string | null | undefined,
): BlockHit | null {
	try {
		return matchBlocklist(tierInputsFromResolved(r), fromAddress);
	} catch (e) {
		console.error("blocklist evaluation failed (fail-open):", (e as Error).message);
		return null;
	}
}

export function applyBlockedOutcome(
	event: { setReject?: (reason: string) => void },
	result: { blocked?: ReceiveBlocked } | null | undefined,
): void {
	if (result?.blocked?.action === "reject" && result.blocked.reason) {
		event.setReject?.(result.blocked.reason);
	}
}
