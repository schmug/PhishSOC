// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

// Dual-runtime safe: pure JS, no DOM / window / jsdom dependency. Runs
// identically in browsers and Cloudflare workerd. XSS lockdown covered by
// `tests/lib/html-text.test.ts` (#116).

/**
 * Runtime-agnostic HTML → plain text conversion.
 *
 * Used in two places where regex-based stripping was previously flagged by
 * CodeQL (js/incomplete-multi-character-sanitization, js/bad-tag-filter,
 * js/double-escaping):
 *   - browser code in app/lib/utils.ts (snippets, quoted-reply blocks)
 *   - worker code in workers/lib/email-helpers.ts (outbound MIME plain-text
 *     alternative, classifier inputs)
 *
 * The implementation is a small character-walking tokenizer rather than a set
 * of regex replacements. This avoids the well-known regex pitfalls — e.g.
 * `/<script[^>]*>[\s\S]*?<\/script>/gi` misses `</script foo="">` — and
 * handles attribute values that contain `>` correctly.
 *
 * It is *not* a full HTML parser. It does not validate structure, build a
 * tree, or care about malformed input. Its only job is to extract the
 * user-visible text while dropping script/style content.
 */

const NAMED_ENTITIES: Record<string, string> = {
	amp: "&",
	lt: "<",
	gt: ">",
	quot: '"',
	apos: "'",
	nbsp: " ",
};

/**
 * Decode HTML entities in already-extracted text. Numeric (`&#39;`, `&#x27;`)
 * and the small set of named entities above are recognized. Unknown entities
 * are left as-is — no double-decoding.
 */
function decodeEntities(text: string): string {
	if (!text || text.indexOf("&") === -1) return text;
	return text.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (match, body: string) => {
		if (body.startsWith("#x") || body.startsWith("#X")) {
			const code = Number.parseInt(body.slice(2), 16);
			return Number.isFinite(code) ? String.fromCodePoint(code) : match;
		}
		if (body.startsWith("#")) {
			const code = Number.parseInt(body.slice(1), 10);
			return Number.isFinite(code) ? String.fromCodePoint(code) : match;
		}
		const named = NAMED_ENTITIES[body.toLowerCase()];
		return named ?? match;
	});
}

/** Skip past the closing `>` of a tag, respecting quoted attribute values. */
function skipTag(html: string, start: number): number {
	let i = start;
	let quote = "";
	while (i < html.length) {
		const ch = html[i];
		if (quote) {
			if (ch === quote) quote = "";
		} else if (ch === '"' || ch === "'") {
			quote = ch;
		} else if (ch === ">") {
			return i + 1;
		}
		i++;
	}
	return html.length;
}

/**
 * Skip past `</tagName ...>` for the given tag name (case-insensitive). The
 * HTML spec terminates rawtext on `</tag` followed by whitespace, `/`, or
 * `>` — anything else is treated as text.
 */
function skipRawText(html: string, start: number, tagName: string): number {
	const lower = html.toLowerCase();
	const needle = `</${tagName}`;
	let i = start;
	while (i < html.length) {
		const found = lower.indexOf(needle, i);
		if (found === -1) return html.length;
		const after = found + needle.length;
		const next = html[after];
		if (next === undefined || next === ">" || next === "/" || /\s/.test(next)) {
			return skipTag(html, after);
		}
		i = found + needle.length;
	}
	return html.length;
}

/**
 * Tag-shaped detector: matches `<tag ...>` / `</tag>` / `<tag/>` where the
 * first character after `<` (or `</`) is a letter, optionally followed by
 * more name characters, optional whitespace-delimited attributes, an
 * optional self-close slash, and a closing `>`. A bare `<` or `>` in prose
 * (e.g. "3 < 5", "<support@example.com>") does not match because nothing in
 * the string reaches a valid tag-close boundary. This is a structural check,
 * not a substring search (root CLAUDE.md Rule 2 / CodeQL
 * js/incomplete-multi-character-sanitization).
 */
const HTML_TAG_SHAPE = /<\/?[a-zA-Z][a-zA-Z0-9-]*(?:\s[^<>]*)?\/?>/;

/**
 * True when `value` contains at least one HTML-tag-shaped substring. Used to
 * decide whether a stored email body is HTML (render as-is) or plain text
 * (escape + preserve whitespace) when no content-type is recorded alongside
 * the body (issue #708).
 */
export function looksLikeHtml(value: string): boolean {
	if (!value) return false;
	return HTML_TAG_SHAPE.test(value);
}

/**
 * Escape the five OWASP-recommended HTML special characters. Safe to inject
 * into text content or attribute values afterward.
 */
export function escapeHtml(text: string): string {
	if (!text) return "";
	return text
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

export interface HtmlToTextOptions {
	/** Convert <br> and block-level closes to newlines instead of spaces. */
	preserveLineBreaks?: boolean;
}

const BLOCK_CLOSE_TAGS = new Set([
	"p",
	"div",
	"br",
	"li",
	"tr",
	"h1",
	"h2",
	"h3",
	"h4",
	"h5",
	"h6",
]);

/**
 * Extract user-visible text from an HTML fragment. Drops `<script>` and
 * `<style>` content entirely; replaces all other tags with whitespace
 * (or a newline, if `preserveLineBreaks` is set and the tag is block-level).
 * Decodes HTML entities and collapses whitespace.
 */
export function htmlToPlainText(html: string, opts: HtmlToTextOptions = {}): string {
	if (!html) return "";

	const { preserveLineBreaks = false } = opts;
	const out: string[] = [];
	let i = 0;
	const len = html.length;

	while (i < len) {
		const lt = html.indexOf("<", i);
		if (lt === -1) {
			out.push(html.slice(i));
			break;
		}
		if (lt > i) out.push(html.slice(i, lt));

		// Comment: `<!-- ... -->`. Treat as a word break so `a<!--x-->b`
		// doesn't merge into `ab`.
		if (html.startsWith("<!--", lt)) {
			const end = html.indexOf("-->", lt + 4);
			out.push(" ");
			i = end === -1 ? len : end + 3;
			continue;
		}
		// Doctype / processing instruction / CDATA — skip to next `>`.
		if (html.startsWith("<!", lt) || html.startsWith("<?", lt)) {
			i = skipTag(html, lt + 2);
			continue;
		}

		// Read tag name. `<` not followed by a tag-name char is literal text.
		const nameStart = html[lt + 1] === "/" ? lt + 2 : lt + 1;
		const firstCh = html[nameStart];
		if (!firstCh || !/[a-zA-Z]/.test(firstCh)) {
			out.push("<");
			i = lt + 1;
			continue;
		}

		let nameEnd = nameStart;
		while (nameEnd < len && /[a-zA-Z0-9]/.test(html[nameEnd])) nameEnd++;
		const tagName = html.slice(nameStart, nameEnd).toLowerCase();
		const afterTag = skipTag(html, nameEnd);

		if (tagName === "script" || tagName === "style") {
			// Rawtext element: drop content until the matching close tag.
			// Emit a space so adjacent words don't merge.
			out.push(" ");
			i = skipRawText(html, afterTag, tagName);
			continue;
		}

		const separator =
			preserveLineBreaks && BLOCK_CLOSE_TAGS.has(tagName) ? "\n" : " ";
		out.push(separator);
		i = afterTag;
	}

	const text = decodeEntities(out.join(""));

	if (preserveLineBreaks) {
		// Collapse runs of spaces/tabs without eating newlines, then trim.
		return text
			.replace(/[^\S\n]+/g, " ")
			.replace(/\n{3,}/g, "\n\n")
			.replace(/[ \t]+\n/g, "\n")
			.trim();
	}
	return text.replace(/\s+/g, " ").trim();
}
