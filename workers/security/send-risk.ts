// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Outbound send-risk classifier for PhishSOC (issue #15).
 *
 * Classifies a draft send into one of three tiers:
 *   Tier 0 — no restriction (internal-only, or opt-in established correspondents)
 *   Tier 1 — step-up (external recipient, high count, macro/disk-image
 *            attachment, lookalike link, flagged-thread tag)
 *   Tier 2 — step-up + typed confirmation (BEC/credential keywords, executable
 *            attachment, lookalike recipient domain, reply to a quarantined /
 *            phishing / BEC message, link on a threat-intel feed)
 *
 * This function stays pure and synchronous. Signals that need mailbox state
 * (recipient history, the replied-to message's verdict, feed hits, settings)
 * arrive precomputed in `input.context`, gathered by `assessSendRisk` in
 * `workers/lib/send-risk-assess.ts`. With no context, only the stateless
 * rules run — the pre-context behaviour.
 */

import { classifyAttachment, extractExtension } from "./attachments";
import { extractUrls, levenshtein, registrableDomain } from "./urls";

export type SendRiskTier = 0 | 1 | 2;

export interface SendRisk {
	tier: SendRiskTier;
	reasons: string[];
}

/**
 * The gate decision persisted as JSON in `emails.send_risk` on every SENT
 * row (migration 32), so each outbound message records why it was allowed
 * out. `confirmed` is true when a step-up confirmation token was verified
 * for the send.
 */
export interface SendRiskRecord extends SendRisk {
	v: 1;
	confirmed: boolean;
}

/** Mailbox state for the stateful rules. Every field is optional; absent = rule skipped. */
export interface SendRiskContext {
	/** Prior sends per recipient address (lowercased). An address that is absent was never sent to. */
	recipientHistory?: Record<string, { send_count: number; first_sent: string; last_sent: string }>;
	/** Total prior sends per recipient domain. A domain that is absent was never sent to. */
	domainSendCounts?: Record<string, number>;
	/** Domains with established send history — the anchors for lookalike detection. */
	knownDomains?: string[];
	/** Verdict of the message this send replies to or forwards. */
	thread?: { action?: string; label?: string } | null;
	/** Threat-intel feed matches for links in the body. */
	feedHits?: Array<{ host: string; feedId: string; confirmed: boolean }>;
	/** `attachment_policy.custom_blocklist_extensions` — treated as executables. */
	customBlockedExtensions?: string[];
	/**
	 * Opt-in (`security.send_risk.trust_known_recipients`, API channel only):
	 * external recipients that are all established correspondents do not by
	 * themselves require step-up. Every other rule still applies.
	 */
	trustKnownRecipients?: boolean;
	/** Clock for the history-age checks (ms). Defaults to `Date.now()`. */
	now?: number;
}

export interface ClassifySendInput {
	/** Primary recipient(s) — string or array of RFC-5322 address strings. */
	to: string | string[];
	cc?: string | string[] | null;
	bcc?: string | string[] | null;
	subject?: string | null;
	/** Plain-text or HTML body — used for keyword and link matching. */
	body?: string | null;
	attachments?: Array<{ filename?: string | null }>;
	/** The mailboxId is an email address; its domain is the "internal" domain. */
	mailboxId: string;
	/**
	 * Provenance of the draft (issue #266). When "agent", the computed tier is
	 * bumped by +1 (capped at 2): a Tier-1 agent send (e.g. external recipient)
	 * becomes Tier 2; Tier-0 stays Tier 0; Tier-2 stays Tier 2. Omitted /
	 * "user" preserves the human-authored behavior. Agent drafts never get
	 * established-correspondent trust.
	 */
	createdBy?: "agent" | "user";
	/** Mailbox state for the stateful rules (see `SendRiskContext`). */
	context?: SendRiskContext;
}

// ── Tier-2 BEC / credential keyword list ────────────────────────────────────

const TIER2_KEYWORDS: readonly string[] = [
	"wire transfer",
	"wire funds",
	"bank details",
	"bank account",
	"routing number",
	"gift card",
	"mfa code",
	"one-time code",
	"authenticator code",
	"reset my password",
	"change my password",
	"urgent payment",
];

// ── Established-correspondent thresholds ─────────────────────────────────────

const DAY_MS = 24 * 60 * 60 * 1000;
/** Prior sends before an address counts as established. */
export const ESTABLISHED_MIN_SENDS = 2;
/** The first send must be at least this old — a burst of sends cannot fast-track trust. */
export const ESTABLISHED_MIN_AGE_MS = 7 * DAY_MS;
/** A correspondent not written to for this long must be re-confirmed. */
export const ESTABLISHED_MAX_IDLE_MS = 365 * DAY_MS;

/** Distinct external domains compared against the lookalike anchors per send. */
const LOOKALIKE_DOMAIN_CAP = 20;

// ── helpers ──────────────────────────────────────────────────────────────────

function parseAddresses(field: string | string[] | null | undefined): string[] {
	if (!field) return [];
	const addresses = Array.isArray(field) ? field : [field];
	return addresses.flatMap((a) => a.split(",").map((s) => s.trim())).filter(Boolean);
}

/** Extract the bare lowercased address from an RFC-5322 address or bare email. */
function extractAddress(address: string): string {
	const match = address.match(/<([^>]+)>/) || address.match(/(\S+@\S+)/);
	return match ? match[1].toLowerCase() : "";
}

/** Extract the @domain part from an RFC-5322 address or bare email. */
function extractDomain(address: string): string {
	const email = extractAddress(address);
	const atIdx = email.lastIndexOf("@");
	return atIdx >= 0 ? email.slice(atIdx + 1) : "";
}

function sampleList(items: string[]): string {
	const sample = items.slice(0, 3).join(", ");
	return items.length > 3 ? `${sample} (+${items.length - 3} more)` : sample;
}

function isEstablished(
	history: SendRiskContext["recipientHistory"],
	address: string,
	now: number,
): boolean {
	const h = history?.[address];
	if (!h || h.send_count < ESTABLISHED_MIN_SENDS) return false;
	const first = Date.parse(h.first_sent);
	const last = Date.parse(h.last_sent);
	if (Number.isNaN(first) || Number.isNaN(last)) return false;
	return now - first >= ESTABLISHED_MIN_AGE_MS && now - last <= ESTABLISHED_MAX_IDLE_MS;
}

/** Collapse the multi-character and digit confusables attackers use in lookalike domains. */
function confusableSkeleton(domain: string): string {
	return domain.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/1/g, "l");
}

/**
 * Return the anchor `domain` imitates, or null. An anchor is a domain the
 * mailbox sends to regularly, or its own domain. Matches are close edit
 * distance, a confusable-character swap, or (own domain only) the same name
 * under a different suffix — `acme.co` / `acme.net` for `acme.com`.
 */
export function lookalikeAnchor(domain: string, anchors: string[], internalDomain: string): string | null {
	const d = registrableDomain(domain);
	if (!d) return null;
	const dSkeleton = confusableSkeleton(d);
	for (const anchor of anchors) {
		const a = registrableDomain(anchor);
		if (!a || a === d) continue;
		if (dSkeleton === confusableSkeleton(a)) return anchor;
		if (Math.abs(a.length - d.length) > 2) continue;
		const dist = levenshtein(d, a);
		const minLen = Math.min(a.length, d.length);
		if ((dist === 1 && minLen >= 6) || (dist === 2 && minLen >= 10)) return anchor;
	}
	const own = registrableDomain(internalDomain);
	if (own && own !== d) {
		const ownName = own.split(".")[0];
		if (ownName.length >= 4 && d.split(".")[0] === ownName) return internalDomain;
	}
	return null;
}

// ── classifier ───────────────────────────────────────────────────────────────

/**
 * Classify the outbound send risk of a draft.
 *
 * Returns a tier (0–2) and a list of human-readable reasons.
 * The caller decides what to do with the tier (block, re-prompt, allow).
 */
export function classifySend(input: ClassifySendInput): SendRisk {
	const reasons: string[] = [];
	let tier: SendRiskTier = 0;
	const ctx = input.context;
	const now = ctx?.now ?? Date.now();

	const raise = (t: SendRiskTier, reason: string) => {
		reasons.push(reason);
		if (t > tier) tier = t;
	};

	// ── gather all recipients ────────────────────────────────────────────────
	const allRecipients = [
		...parseAddresses(input.to),
		...parseAddresses(input.cc),
		...parseAddresses(input.bcc),
	];

	// ── derive internal domain from mailboxId ────────────────────────────────
	const internalDomain = extractDomain(input.mailboxId);
	const external = internalDomain
		? allRecipients.filter((r) => extractDomain(r) !== internalDomain)
		: [];

	// ── Tier-2: BEC / credential keyword detection ───────────────────────────
	const body = input.body ?? "";
	const searchText = [input.subject ?? "", body].join(" ").toLowerCase();
	const matchedKeyword = TIER2_KEYWORDS.find((kw) => searchText.includes(kw));
	if (matchedKeyword) {
		raise(2, `BEC/credential keyword: "${matchedKeyword}"`);
	}

	// ── Attachments: same extension classes as the inbound gate ─────────────
	// Executables (any, not only double-extension droppers) and operator
	// blocklisted extensions are Tier 2; macro Office and disk images Tier 1.
	const customBlocked = new Set(
		(ctx?.customBlockedExtensions ?? []).map((e) => e.trim().toLowerCase().replace(/^\./, "")).filter(Boolean),
	);
	for (const att of input.attachments ?? []) {
		if (!att.filename) continue;
		const { category } = classifyAttachment(att.filename, null);
		if (category === "executable" || customBlocked.has(extractExtension(att.filename))) {
			raise(2, `Suspicious attachment extension: "${att.filename}"`);
		} else if (category === "macro_office" || category === "container") {
			raise(1, `Macro-enabled or disk-image attachment: "${att.filename}"`);
		}
	}

	// ── Tier-1: high recipient count ─────────────────────────────────────────
	if (allRecipients.length > 10) {
		raise(1, `High recipient count: ${allRecipients.length}`);
	}

	// ── Tier-1: any external recipient ───────────────────────────────────────
	if (external.length > 0) {
		const externalAddresses = [...new Set(external.map(extractAddress).filter(Boolean))];
		const trusted =
			ctx?.trustKnownRecipients === true &&
			input.createdBy !== "agent" &&
			externalAddresses.length > 0 &&
			externalAddresses.every((a) => isEstablished(ctx.recipientHistory, a, now));
		if (trusted) {
			// Informational only: the send stays at whatever the other rules
			// decide. Recorded so the SENT row shows why step-up was skipped.
			reasons.push(`External recipient(s) are established correspondents: ${sampleList(externalAddresses)}`);
		} else {
			raise(1, `External recipient(s): ${sampleList(external)}`);
		}

		// ── First-time external recipients (informational) ───────────────
		if (ctx?.recipientHistory) {
			const firstTime = externalAddresses.filter((a) => !ctx.recipientHistory?.[a]);
			if (firstTime.length > 0) {
				reasons.push(`First-time recipient(s): ${sampleList(firstTime)}`);
			}
		}

		// ── Tier-2: lookalike recipient domain ───────────────────────────
		// Only for domains this mailbox has never sent to: once a user has
		// confirmed a send to a domain, later sends to it are not re-flagged.
		if (ctx?.domainSendCounts && ctx.knownDomains) {
			const anchors = [...new Set([...ctx.knownDomains, internalDomain])];
			const newDomains = [...new Set(externalAddresses.map((a) => a.slice(a.lastIndexOf("@") + 1)))]
				.filter((d) => !ctx.domainSendCounts?.[d])
				.slice(0, LOOKALIKE_DOMAIN_CAP);
			for (const domain of newDomains) {
				const anchor = lookalikeAnchor(domain, anchors, internalDomain);
				if (anchor) raise(2, `Recipient domain "${domain}" resembles "${anchor}"`);
			}
		}
	}

	// ── Replying to / forwarding a flagged message ───────────────────────────
	const thread = ctx?.thread;
	if (thread) {
		const flaggedAs =
			thread.label === "phishing" || thread.label === "bec"
				? thread.label
				: thread.action === "quarantine"
					? "quarantined"
					: thread.action === "block"
						? "blocked"
						: null;
		if (flaggedAs) {
			raise(external.length > 0 ? 2 : 1, `Reply or forward of a message flagged as ${flaggedAs}`);
		} else if (thread.action === "tag" && external.length > 0) {
			raise(1, "Reply or forward of a message tagged suspicious");
		}
	}

	// ── Links ────────────────────────────────────────────────────────────────
	for (const hit of ctx?.feedHits ?? []) {
		if (hit.confirmed) raise(2, `Link on threat-intel feed: ${hit.host} (${hit.feedId})`);
		else raise(1, `Link possibly on threat-intel feed: ${hit.host} (unconfirmed)`);
	}
	const homograph = extractUrls(body).find((u) => u.is_homograph);
	if (homograph) {
		raise(1, `Lookalike or internationalized link: ${homograph.hostname}`);
	}

	// ── Agent-authored bump (issue #266) ─────────────────────────────────────
	// Bump tier by +1 (capped at 2) when the draft was written by the agent
	// rather than a human. Tier 0 stays Tier 0 (purely internal traffic gets
	// no bump — there is nothing risky to elevate); Tier 2 stays Tier 2
	// (already at the ceiling). The reason is emitted on every non-zero
	// agent send so audit reviewers see provenance on Tier-2 keyword/macro
	// drafts too, not just the bumped ones.
	if (input.createdBy === "agent" && tier > 0) {
		reasons.push("Agent-authored draft");
		if (tier < 2) tier = 2;
	}

	return { tier, reasons };
}
