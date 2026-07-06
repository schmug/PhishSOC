// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * ARC sealing (RFC 8617) for inline-gateway relay (issue #32).
 *
 * Owned protocol code by design: `workers/CLAUDE.md` forbids `node:`
 * imports/Buffer in workers code, which rules out mailauth at runtime. The
 * cryptographic primitive is `crypto.subtle` RSASSA-PKCS1-v1_5/SHA-256 —
 * never hand-rolled. Canonicalization (RFC 6376 §3.4 relaxed/relaxed) is
 * pinned to the RFC's own vectors in tests, and every seal this module
 * produces is cross-verified by mailauth's independent validator in
 * `tests/lib/arc-seal.test.ts`.
 *
 * Byte fidelity: Encoding/decoding uses manual 1:1 byte↔code-point conversion
 * (latin1Encode/latin1Decode) everywhere. TextDecoder("latin1") is actually
 * windows-1252, which corrupts 0x80–0x9F on round-trip; we avoid it entirely.
 *
 * v1 seals only when the message carries no prior ARC chain (we are i=1,
 * cv=none). Messages with an existing chain relay unsealed — validating a
 * prior chain is out of scope (spec), and asserting cv= without validating
 * would be dishonest.
 */

/** Encode a string whose code points are all <= 0xFF back to raw bytes. */
export function latin1Encode(s: string): Uint8Array {
	const out = new Uint8Array(s.length);
	for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
	return out;
}

/** Decode raw bytes to a string 1:1 (byte N → code point N). TextDecoder("latin1")
 *  is windows-1252 and corrupts 0x80–0x9F on round-trip — do not use it here. */
export function latin1Decode(bytes: Uint8Array): string {
	let out = "";
	const CHUNK = 0x8000;
	for (let i = 0; i < bytes.length; i += CHUNK) {
		out += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
	}
	return out;
}

/**
 * Split raw RFC-5322 bytes into the header block (latin1 string, 1:1 with
 * bytes, including the trailing CRLF of the last header) and body bytes.
 * The CRLFCRLF separator belongs to neither part.
 */
export function splitRawMessage(raw: Uint8Array): { headerBlock: string; body: Uint8Array } {
	for (let i = 0; i + 3 < raw.length; i++) {
		if (raw[i] === 13 && raw[i + 1] === 10 && raw[i + 2] === 13 && raw[i + 3] === 10) {
			return {
				headerBlock: latin1Decode(raw.subarray(0, i + 2)),
				body: raw.subarray(i + 4),
			};
		}
	}
	// No body separator: the whole message is headers.
	return { headerBlock: latin1Decode(raw), body: new Uint8Array(0) };
}

/**
 * Parse a raw header block into `{ name, raw }` entries. `raw` is the
 * exact original text (folding preserved, no trailing CRLF); `name` is
 * lowercased for lookups.
 */
export function parseRawHeaders(headerBlock: string): Array<{ name: string; raw: string }> {
	const out: Array<{ name: string; raw: string }> = [];
	// Split on CRLF NOT followed by whitespace (folded continuations stay).
	const lines = headerBlock.split(/\r\n(?![ \t])/);
	for (const line of lines) {
		if (!line) continue;
		const colon = line.indexOf(":");
		if (colon <= 0) continue;
		out.push({ name: line.slice(0, colon).trim().toLowerCase(), raw: line });
	}
	return out;
}

/** RFC 6376 §3.4.2 relaxed header canonicalization → `name:value` (no CRLF). */
export function canonicalizeHeaderRelaxed(rawHeader: string): string {
	const colon = rawHeader.indexOf(":");
	const name = rawHeader.slice(0, colon).trim().toLowerCase();
	let value = rawHeader.slice(colon + 1);
	value = value.replace(/\r\n/g, ""); // unfold
	value = value.replace(/[ \t]+/g, " "); // collapse WSP runs
	value = value.trim();
	return `${name}:${value}`;
}

/** RFC 6376 §3.4.4 relaxed body canonicalization. */
export function canonicalizeBodyRelaxed(body: Uint8Array): Uint8Array {
	if (body.length === 0) return body;
	const text = latin1Decode(body);
	const lines = text.split("\r\n").map((l) => l.replace(/[ \t]+/g, " ").replace(/[ \t]+$/, ""));
	while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
	if (lines.length === 0) return new Uint8Array(0);
	return latin1Encode(lines.join("\r\n") + "\r\n");
}
