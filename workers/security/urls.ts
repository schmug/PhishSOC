// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * URL extraction and synchronous heuristic scoring.
 *
 * Fetch-based enrichment (URL preview, redirect chain, RDAP) happens in the
 * async deep-scan stage — see `workers/intel/deep-scan.ts`. Feed-based
 * lookups (bloom filter against PhishDestroy/URLhaus lists) are applied by
 * `workers/intel/feeds.ts` at the pipeline integration point.
 */

import { normalizeHost } from "../lib/url-canonical";

/** Domains whose typos are extremely high-value for phishers. */
export const HIGH_VALUE_DOMAINS = [
	"google.com", "gmail.com", "googledrive.com", "googleusercontent.com",
	"microsoft.com", "outlook.com", "office.com", "live.com", "microsoftonline.com",
	"apple.com", "icloud.com",
	"amazon.com", "amazon.co.uk", "amazonaws.com",
	"paypal.com", "venmo.com", "zelle.com", "cashapp.com",
	"facebook.com", "instagram.com", "meta.com", "whatsapp.com",
	"dropbox.com", "box.com", "onedrive.com",
	"adobe.com", "docusign.com", "docusign.net",
	"github.com", "gitlab.com",
	"linkedin.com", "twitter.com", "x.com",
	"netflix.com", "spotify.com",
	"bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
	"hsbc.com", "barclays.com",
	"cloudflare.com", "cloudflareaccess.com",
];

const SHORTENER_DOMAINS = new Set([
	"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
	"rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "bl.ink",
	"lnkd.in", "t.ly", "s.id", "v.gd", "qr.ae", "x.gd", "short.io",
	"linktr.ee", "mcaf.ee", "trib.al", "dlvr.it",
]);

export interface ExtractedUrl {
	url: string;
	display_text?: string;
	hostname: string;
	is_homograph: boolean;
	is_shortener: boolean;
	/**
	 * The anchor's visible text is itself a URL or bare hostname whose
	 * registrable domain differs from the href's ("shows bank.example, goes
	 * to evil.example"). Only set for anchors; bare/href-only URLs have no
	 * display text to compare.
	 */
	is_text_mismatch?: boolean;
}

const HREF_RE = /href\s*=\s*["']([^"']+)["']/gi;
const BARE_URL_RE = /\bhttps?:\/\/[^\s<>"')]+/gi;
const ANCHOR_RE = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;

function stripTags(html: string): string {
	return html.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

/** Canonical host of a link (see `normalizeHost`), or null when it has none. */
function safeHostname(url: string): string | null {
	try {
		return normalizeHost(new URL(url).hostname);
	} catch {
		return null;
	}
}

/** Levenshtein distance — used for typo/homograph detection. */
export function levenshtein(a: string, b: string): number {
	if (a === b) return 0;
	const n = a.length, m = b.length;
	if (n === 0) return m;
	if (m === 0) return n;
	let prev = new Array(m + 1);
	let curr = new Array(m + 1);
	for (let j = 0; j <= m; j++) prev[j] = j;
	for (let i = 1; i <= n; i++) {
		curr[0] = i;
		for (let j = 1; j <= m; j++) {
			const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
			curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
		}
		[prev, curr] = [curr, prev];
	}
	return prev[m];
}

/**
 * Small allow-list of second-level country-code TLDs. The Public Suffix List
 * is the "correct" answer but pulling it in costs ~200KB of compiled data
 * per Worker; this 20-entry list covers the domains that matter for the
 * high-value-domain homograph check (so `amazom.co.uk` is compared against
 * `amazon.co.uk` rather than the nonsensical `co.uk`).
 */
const MULTI_LABEL_PUBLIC_SUFFIXES = new Set([
	"co.uk", "co.jp", "co.kr", "co.nz", "co.za", "co.in",
	"com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.tr", "com.ar",
	"ac.uk", "gov.uk", "org.uk", "net.au", "org.au",
]);

/**
 * Extract the registrable (eTLD+1) portion of a hostname, handling common
 * multi-label suffixes so we compare like-for-like against HIGH_VALUE_DOMAINS.
 */
export function registrableDomain(hostname: string): string {
	const parts = hostname.split(".");
	if (parts.length < 2) return hostname;
	const last2 = parts.slice(-2).join(".");
	if (parts.length >= 3 && MULTI_LABEL_PUBLIC_SUFFIXES.has(last2)) {
		return parts.slice(-3).join(".");
	}
	return last2;
}

/**
 * Non-ASCII hostnames, bare punycode, or close Levenshtein matches to
 * high-value domains are flagged as homographs. Legitimate mail practically
 * never uses IDN hostnames; attackers use Cyrillic/Greek lookalikes.
 */
export function isHomographic(host: string): boolean {
	const hostname = normalizeHost(host) ?? host;
	for (let i = 0; i < hostname.length; i++) {
		if (hostname.charCodeAt(i) > 127) return true;
	}
	if (hostname.includes("xn--")) return true;
	for (const d of HIGH_VALUE_DOMAINS) {
		if (hostname === d || hostname.endsWith("." + d)) return false;
	}
	const registrable = registrableDomain(hostname);
	for (const d of HIGH_VALUE_DOMAINS) {
		const dist = levenshtein(registrable, d);
		if (dist > 0 && dist <= 2) return true;
	}
	return false;
}

export function extractUrls(body: string | null | undefined, cap = 20): ExtractedUrl[] {
	if (!body) return [];
	const seen = new Set<string>();
	const out: ExtractedUrl[] = [];

	for (const match of body.matchAll(ANCHOR_RE)) {
		if (out.length >= cap) break;
		pushUrl(out, seen, match[1], stripTags(match[2]).slice(0, 200));
	}
	for (const match of body.matchAll(HREF_RE)) {
		if (out.length >= cap) break;
		pushUrl(out, seen, match[1]);
	}
	for (const match of body.matchAll(BARE_URL_RE)) {
		if (out.length >= cap) break;
		pushUrl(out, seen, match[0]);
	}
	return out;
}

// Visible text that is entirely a URL or hostname — optional scheme, a
// dotted host with an alphabetic TLD, optional port/path/query. Anything with
// surrounding prose ("Visit example.com today", "Click here") is ignored so
// only text that *claims* a destination is compared against the href.
const DISPLAY_HOST_RE = /^(?:https?:\/\/)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63})\.?(?::\d+)?(?:[\/?#]\S*)?$/i;

// Filename-shaped anchor text ("invoice.pdf", "report.docx") matches the
// hostname shape but names a file, not a destination.
const FILE_EXTENSION_TLDS = new Set([
	"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "rtf",
	"zip", "rar", "7z", "gz", "html", "htm", "php", "asp", "aspx", "jsp",
	"jpg", "jpeg", "png", "gif", "svg", "mp3", "mp4", "mov", "ics", "eml",
]);

/**
 * Registrable domain the anchor text claims to point at, or null when the
 * text isn't a bare URL/hostname.
 */
export function displayedDomain(display: string | undefined): string | null {
	if (!display) return null;
	const m = DISPLAY_HOST_RE.exec(display.trim());
	if (!m) return null;
	const tld = m[1].slice(m[1].lastIndexOf(".") + 1).toLowerCase();
	if (FILE_EXTENSION_TLDS.has(tld)) return null;
	const host = normalizeHost(m[1]);
	return host ? registrableDomain(host) : null;
}

function pushUrl(out: ExtractedUrl[], seen: Set<string>, rawUrl: string, display?: string) {
	const hostname = safeHostname(rawUrl);
	if (!hostname) return;
	if (seen.has(rawUrl)) return;
	seen.add(rawUrl);
	const registrable = registrableDomain(hostname);
	const shown = displayedDomain(display);
	out.push({
		url: rawUrl,
		display_text: display,
		hostname,
		is_homograph: isHomographic(hostname),
		is_shortener: SHORTENER_DOMAINS.has(hostname) || SHORTENER_DOMAINS.has(registrable),
		...(shown && shown !== registrable ? { is_text_mismatch: true } : {}),
	});
}

/** Weight of the `deceptive_link_text` rule before mitigations. */
export const DECEPTIVE_LINK_TEXT_WEIGHT = 15;

/**
 * Confidence sources (issue #105, v1):
 *   - 0.9 — a homograph fired (non-ASCII, bare punycode, or close
 *     Levenshtein to a high-value domain). These checks are deterministic
 *     once the URL is parsed.
 *   - 0.8 — a deceptive-link-text match fired (no homograph). The
 *     comparison is deterministic, but ESP click-tracking legitimately
 *     rewrites hrefs, so it is not as conclusive as a homograph.
 *   - 0.6 — only a shortener match fired. Shortener-by-itself is a weak
 *     signal (legit users do shorten links).
 *   - 1.0 — no URL signals fired; nothing to be uncertain about.
 */
export function scoreUrls(urls: ExtractedUrl[]): {
	score: number;
	reasons: string[];
	confidence: number;
	contributions: Array<{ scorer: "urls"; rule: string; weight: number; reason: string }>;
} {
	const reasons: string[] = [];
	const contributions: Array<{ scorer: "urls"; rule: string; weight: number; reason: string }> = [];
	let score = 0;
	const homograph = urls.find((u) => u.is_homograph);
	if (homograph) {
		score += 20;
		const reason = `homograph URL (${homograph.hostname})`;
		reasons.push(reason);
		contributions.push({ scorer: "urls", rule: "homograph_url", weight: 20, reason });
	}
	const shortener = urls.find((u) => u.is_shortener);
	if (shortener) {
		score += 5;
		const reason = `link shortener (${shortener.hostname})`;
		reasons.push(reason);
		contributions.push({ scorer: "urls", rule: "link_shortener", weight: 5, reason });
	}
	const mismatch = urls.find((u) => u.is_text_mismatch);
	if (mismatch) {
		score += DECEPTIVE_LINK_TEXT_WEIGHT;
		const reason = `deceptive link text (shows ${mismatch.display_text}, goes to ${mismatch.hostname})`;
		reasons.push(reason);
		contributions.push({ scorer: "urls", rule: "deceptive_link_text", weight: DECEPTIVE_LINK_TEXT_WEIGHT, reason });
	}
	const confidence = homograph ? 0.9 : mismatch ? 0.8 : shortener ? 0.6 : 1.0;
	return { score, reasons, confidence, contributions };
}
