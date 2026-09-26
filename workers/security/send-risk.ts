// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Outbound send-risk classifier for PhishSOC (issue #15 slice 1).
 *
 * Classifies a draft send into one of three tiers:
 *   Tier 0 — no restriction (internal-only, or trusted reply)
 *   Tier 1 — Access re-prompt (external recipient, high count, novel link domains)
 *   Tier 2 — Confirm + step-up required (BEC/credential keywords, macro attachment)
 *
 * This module is intentionally stateless — it does not call the DO or fetch
 * external data.  Signals that need DO state (first-seen recipient age, inbound
 * thread verdict) are reserved for a follow-up slice that wraps this function.
 */

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

export interface ClassifySendInput {
	/** Primary recipient(s) — string or array of RFC-5322 address strings. */
	to: string | string[];
	cc?: string | string[] | null;
	bcc?: string | string[] | null;
	subject?: string | null;
	/** Plain-text or HTML body — used for keyword matching. */
	body?: string | null;
	attachments?: Array<{ filename?: string | null }>;
	/** The mailboxId is an email address; its domain is the "internal" domain. */
	mailboxId: string;
	/**
	 * Provenance of the draft (issue #266). When "agent", the computed tier is
	 * bumped by +1 (capped at 2): a Tier-1 agent send (e.g. external recipient)
	 * becomes Tier 2; Tier-0 stays Tier 0; Tier-2 stays Tier 2. Omitted /
	 * "user" preserves the human-authored behavior.
	 */
	createdBy?: "agent" | "user";
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

// File extensions whose presence in a double-extension filename signals a
// macro dropper (e.g. "invoice.pdf.exe", "report.docx.vbs").
const MACRO_EXTENSIONS = new Set(["exe", "bat", "cmd", "vbs", "js", "jar", "com", "scr", "pif", "ps1", "hta"]);

// ── helpers ──────────────────────────────────────────────────────────────────

function parseAddresses(field: string | string[] | null | undefined): string[] {
	if (!field) return [];
	const addresses = Array.isArray(field) ? field : [field];
	return addresses.flatMap((a) => a.split(",").map((s) => s.trim())).filter(Boolean);
}

/** Extract the @domain part from an RFC-5322 address or bare email. */
function extractDomain(address: string): string {
	// Handle "Display Name <user@domain>" and bare "user@domain" forms.
	const match = address.match(/<([^>]+)>/) || address.match(/(\S+@\S+)/);
	if (!match) return "";
	const email = match[1];
	const atIdx = email.lastIndexOf("@");
	return atIdx >= 0 ? email.slice(atIdx + 1).toLowerCase() : "";
}

function hasSuspiciousExtension(filename: string): boolean {
	const parts = filename.split(".");
	// Need at least "name.ext1.ext2" to be a double-extension.
	if (parts.length < 3) return false;
	return MACRO_EXTENSIONS.has(parts[parts.length - 1].toLowerCase());
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

	// ── Tier-2: BEC / credential keyword detection ───────────────────────────
	const searchText = [input.subject ?? "", input.body ?? ""].join(" ").toLowerCase();
	const matchedKeyword = TIER2_KEYWORDS.find((kw) => searchText.includes(kw));
	if (matchedKeyword) {
		raise(2, `BEC/credential keyword: "${matchedKeyword}"`);
	}

	// ── Tier-2: attachment with macro/double-extension ───────────────────────
	for (const att of input.attachments ?? []) {
		if (att.filename && hasSuspiciousExtension(att.filename)) {
			raise(2, `Suspicious attachment extension: "${att.filename}"`);
		}
	}

	// ── Tier-1: high recipient count ─────────────────────────────────────────
	if (allRecipients.length > 10) {
		raise(1, `High recipient count: ${allRecipients.length}`);
	}

	// ── Tier-1: any external recipient ───────────────────────────────────────
	if (internalDomain) {
		const external = allRecipients.filter(
			(r) => extractDomain(r) !== internalDomain,
		);
		if (external.length > 0) {
			const sample = external.slice(0, 3).join(", ");
			raise(1, `External recipient(s): ${sample}${external.length > 3 ? ` (+${external.length - 3} more)` : ""}`);
		}
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
