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

const ARC_HEADER_NAMES = new Set(["arc-seal", "arc-message-signature", "arc-authentication-results"]);

/** Headers AMS signs when present, in this fixed order. Never ARC-* (RFC 8617 §4.1.2). */
const AMS_SIGNED_HEADERS = [
	"from",
	"to",
	"cc",
	"subject",
	"date",
	"message-id",
	"mime-version",
	"content-type",
	"x-phishpilot-verdict",
	"x-phishpilot-score",
];

export function hasExistingArcChain(raw: Uint8Array): boolean {
	const { headerBlock } = splitRawMessage(raw);
	return parseRawHeaders(headerBlock).some((h) => ARC_HEADER_NAMES.has(h.name));
}

function toBase64(bytes: Uint8Array): string {
	let bin = "";
	const CHUNK = 0x8000;
	for (let i = 0; i < bytes.length; i += CHUNK) {
		bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
	}
	return btoa(bin);
}

function fromBase64(b64: string): Uint8Array {
	const bin = atob(b64);
	return latin1Encode(bin);
}

async function importPkcs8(pem: string): Promise<CryptoKey> {
	const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
	return crypto.subtle.importKey(
		"pkcs8",
		fromBase64(b64).buffer as ArrayBuffer,
		{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		false,
		["sign"],
	);
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.buffer as ArrayBuffer));
}

async function rsaSign(key: CryptoKey, data: string): Promise<string> {
	const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, latin1Encode(data).buffer as ArrayBuffer);
	return toBase64(new Uint8Array(sig));
}

export interface ArcSealOptions {
	auth: { spf: string; dkim: string; dmarc: string };
	sealerDomain: string;
	selector: string;
	privateKeyPem: string;
	/** Unix seconds; injectable so tests are deterministic. */
	now?: number;
}

/**
 * Build the i=1 ARC set for a message with no prior chain. Returns the
 * three headers (AS, AMS, AAR — newest-first, ready to prepend) ending in
 * CRLF, or null when a prior chain exists.
 */
export async function sealMessage(raw: Uint8Array, opts: ArcSealOptions): Promise<string | null> {
	if (hasExistingArcChain(raw)) return null;

	const { headerBlock, body } = splitRawMessage(raw);
	const headers = parseRawHeaders(headerBlock);
	const key = await importPkcs8(opts.privateKeyPem);
	const t = opts.now ?? Math.floor(Date.now() / 1000);
	const d = opts.sealerDomain;
	const s = opts.selector;

	// ── AAR ──────────────────────────────────────────────────────────
	const aar =
		`ARC-Authentication-Results: i=1; ${d}; ` +
		`spf=${opts.auth.spf || "none"}; dkim=${opts.auth.dkim || "none"}; dmarc=${opts.auth.dmarc || "none"}`;

	// ── AMS ──────────────────────────────────────────────────────────
	// h= lists each signed name once, matching the LAST occurrence of that
	// header in the message (DKIM verifiers select bottom-up).
	const present = AMS_SIGNED_HEADERS.filter((n) => headers.some((h) => h.name === n));
	const bh = toBase64(await sha256(canonicalizeBodyRelaxed(body)));
	const amsUnsigned =
		`ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; ` +
		`d=${d}; s=${s}; t=${t}; h=${present.join(":")}; bh=${bh}; b=`;
	let amsInput = "";
	for (const name of present) {
		const matches = headers.filter((h) => h.name === name);
		const last = matches[matches.length - 1];
		amsInput += canonicalizeHeaderRelaxed(last.raw) + "\r\n";
	}
	amsInput += canonicalizeHeaderRelaxed(amsUnsigned); // own header, b= empty, no CRLF
	const ams = amsUnsigned + (await rsaSign(key, amsInput));

	// ── AS ───────────────────────────────────────────────────────────
	// Signs the ARC set in instance order: AAR, AMS, AS(b=) (RFC 8617 §5.1.1).
	const asUnsigned = `ARC-Seal: i=1; a=rsa-sha256; cv=none; d=${d}; s=${s}; t=${t}; b=`;
	const asInput =
		canonicalizeHeaderRelaxed(aar) +
		"\r\n" +
		canonicalizeHeaderRelaxed(ams) +
		"\r\n" +
		canonicalizeHeaderRelaxed(asUnsigned);
	const arcSeal = asUnsigned + (await rsaSign(key, asInput));

	return `${arcSeal}\r\n${ams}\r\n${aar}\r\n`;
}
