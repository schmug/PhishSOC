// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Inbound own-domain lookalike detector (issue #756).
 *
 * Flags mail whose sender domain, or a link domain, imitates one of the
 * receiving org's own domains (`acme-hr.com`, `acrne.com`, `acme.co`, a
 * Cyrillic-`а` `acme.com` for `acme.com`). Reuses `lookalikeAnchor` from
 * the outbound send-risk check. Pure and offline: no network, no state.
 *
 * Exact matches and subdomains of an anchor are never lookalikes. The result
 * is a bounded additive score, never a verdict on its own.
 */

import { lookalikeAnchor } from "./send-risk";
import { registrableDomain } from "./urls";

/** Upper bound on the boost this detector may add. */
export const OWN_DOMAIN_LOOKALIKE_MAX_SCORE = 25;
const SENDER_SCORE = 25;
const LINK_SCORE = 15;

// Cyrillic and Greek letters that render like Latin ones.
const CONFUSABLE_LETTERS: Record<string, string> = {
	"а": "a", "с": "c", "е": "e", "һ": "h", "і": "i", "ј": "j", "о": "o", "р": "p",
	"ѕ": "s", "х": "x", "у": "y", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ӏ": "l",
	"α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "υ": "u",
};

/** Decode one punycode label (RFC 3492) — enough to unmask `xn--` link hosts. */
function punycodeDecode(input: string): string | null {
	const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
	const out: number[] = [];
	const basic = input.lastIndexOf("-");
	for (let j = 0; j < Math.max(basic, 0); j++) out.push(input.charCodeAt(j));
	let n = 128, bias = 72, i = 0;
	const adapt = (delta: number, points: number, first: boolean) => {
		delta = first ? Math.floor(delta / damp) : delta >> 1;
		delta += Math.floor(delta / points);
		let k = 0;
		while (delta > ((base - tMin) * tMax) >> 1) {
			delta = Math.floor(delta / (base - tMin));
			k += base;
		}
		return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
	};
	for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length; ) {
		const oldi = i;
		for (let w = 1, k = base; ; k += base) {
			if (idx >= input.length) return null;
			const c = input.charCodeAt(idx++);
			const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
			if (digit >= base) return null;
			i += digit * w;
			const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
			if (digit < t) break;
			w *= base - t;
		}
		bias = adapt(i - oldi, out.length + 1, oldi === 0);
		n += Math.floor(i / (out.length + 1));
		i %= out.length + 1;
		out.splice(i++, 0, n);
	}
	try {
		return String.fromCodePoint(...out);
	} catch {
		return null;
	}
}

/** Lowercase, decode `xn--` labels and fold confusable non-Latin letters to Latin. */
function foldDomain(domain: string): string {
	const labels = domain.toLowerCase().replace(/\.$/, "").split(".").map((label) => {
		const decoded = label.startsWith("xn--") ? punycodeDecode(label.slice(4)) : null;
		return decoded ?? label;
	});
	return labels.join(".").replace(/[^\x00-\x7f]/g, (ch) => CONFUSABLE_LETTERS[ch] ?? ch);
}

export interface OwnDomainLookalikeInput {
	/** Domains the sender claims: the DMARC-evaluated From domain and the address domain. */
	senderDomains: string[];
	/** Hostnames of links already extracted by the pipeline (cap already applied). */
	linkHosts: string[];
	/** The org's own domains, including the receiving mailbox's domain. */
	anchors: string[];
	/** The receiving mailbox's domain (drives the same-name-different-suffix rule). */
	mailboxDomain: string;
}

/**
 * The anchor's name glued to extra words with hyphens — `acme-hr.com`,
 * `my-acme.net` for `acme.com`. `lookalikeAnchor` is edit-distance based and
 * misses these; the inbound check adds them. Needs a 4+ character name so a
 * short anchor does not match unrelated hyphenated domains.
 */
function hyphenatedAnchor(reg: string, anchors: string[]): string | null {
	const label = reg.split(".")[0];
	if (!label.includes("-")) return null;
	const parts = label.split("-");
	for (const anchor of anchors) {
		const name = registrableDomain(anchor).split(".")[0];
		if (name.length >= 4 && (parts[0] === name || parts[parts.length - 1] === name)) return anchor;
	}
	return null;
}

/** A match of `domain` against the org's anchors, or null when it is the org's own or unrelated. */
function matchAnchor(domain: string, anchors: string[], mailboxDomain: string): string | null {
	const lowered = domain.toLowerCase().replace(/\.$/, "");
	// Exact match or subdomain of any anchor is the org itself, not an imitation.
	// Compared before folding: `аcme.com` (Cyrillic а) folds to `acme.com` but is not it.
	const rawReg = registrableDomain(lowered);
	if (anchors.some((a) => registrableDomain(a) === rawReg)) return null;
	const folded = foldDomain(lowered);
	const reg = registrableDomain(folded);
	if (!reg) return null;
	const exact = anchors.find((a) => registrableDomain(a) === reg);
	if (exact) return exact;
	return lookalikeAnchor(folded, anchors, mailboxDomain) ?? hyphenatedAnchor(reg, anchors);
}

export function scoreOwnDomainLookalike(
	input: OwnDomainLookalikeInput,
): { score: number; reason?: string } {
	const anchors = [...new Set(input.anchors.map((a) => foldDomain(a)).filter(Boolean))];
	if (anchors.length === 0) return { score: 0 };
	const mailboxDomain = foldDomain(input.mailboxDomain);

	for (const domain of new Set(input.senderDomains.filter(Boolean))) {
		const anchor = matchAnchor(domain, anchors, mailboxDomain);
		if (anchor) {
			return {
				score: Math.min(SENDER_SCORE, OWN_DOMAIN_LOOKALIKE_MAX_SCORE),
				reason: `Sender domain "${domain}" resembles your domain "${anchor}"`,
			};
		}
	}
	for (const host of new Set(input.linkHosts.filter(Boolean))) {
		const anchor = matchAnchor(host, anchors, mailboxDomain);
		if (anchor) {
			return {
				score: Math.min(LINK_SCORE, OWN_DOMAIN_LOOKALIKE_MAX_SCORE),
				reason: `Link domain "${host}" resembles your domain "${anchor}"`,
			};
		}
	}
	return { score: 0 };
}
