import { describe, expect, it } from "vitest";
import {
	canonicalizeBodyRelaxed,
	canonicalizeHeaderRelaxed,
	latin1Decode,
	latin1Encode,
	parseRawHeaders,
	splitRawMessage,
} from "../../workers/lib/arc-seal";

const enc = (s: string) => latin1Encode(s);
const dec = (b: Uint8Array) => Array.from(b, (c) => String.fromCharCode(c)).join("");

describe("splitRawMessage", () => {
	it("splits at the first CRLFCRLF", () => {
		const raw = enc("Subject: hi\r\nFrom: a@b\r\n\r\nbody line\r\n");
		const { headerBlock, body } = splitRawMessage(raw);
		expect(headerBlock).toBe("Subject: hi\r\nFrom: a@b\r\n");
		expect(dec(body)).toBe("body line\r\n");
	});

	it("handles a missing body (headers only)", () => {
		const { headerBlock, body } = splitRawMessage(enc("Subject: hi\r\n\r\n"));
		expect(headerBlock).toBe("Subject: hi\r\n");
		expect(body.length).toBe(0);
	});
});

describe("parseRawHeaders", () => {
	it("keeps folded headers as one entry", () => {
		const hs = parseRawHeaders("A: X\r\nB : Y\t\r\n\tZ  \r\n");
		expect(hs).toEqual([
			{ name: "a", raw: "A: X" },
			{ name: "b", raw: "B : Y\t\r\n\tZ  " },
		]);
	});
});

// Vectors straight from RFC 6376 §3.4.5.
describe("relaxed canonicalization (RFC 6376 §3.4.5 vectors)", () => {
	it("canonicalizes headers", () => {
		expect(canonicalizeHeaderRelaxed("A: X")).toBe("a:X");
		expect(canonicalizeHeaderRelaxed("B : Y\t\r\n\tZ  ")).toBe("b:Y Z");
	});

	it("canonicalizes the body", () => {
		const out = canonicalizeBodyRelaxed(enc(" C \r\nD \t E\r\n\r\n\r\n"));
		expect(dec(out)).toBe(" C\r\nD E\r\n");
	});

	it("empty body canonicalizes to empty; non-empty gains trailing CRLF", () => {
		expect(canonicalizeBodyRelaxed(enc("")).length).toBe(0);
		expect(dec(canonicalizeBodyRelaxed(enc("x")))).toBe("x\r\n");
	});
});

describe("byte fidelity (0x80–0x9F must round-trip)", () => {
	it("latin1Decode/latin1Encode round-trip every byte value", () => {
		const all = new Uint8Array(256);
		for (let i = 0; i < 256; i++) all[i] = i;
		expect(latin1Encode(latin1Decode(all))).toEqual(all);
	});

	it("canonicalizeBodyRelaxed preserves high bytes", () => {
		// body: 0x80 0x81 ... 0x9F CRLF — no WSP, so canonicalization must not alter it
		const line = new Uint8Array(34);
		for (let i = 0; i < 32; i++) line[i] = 0x80 + i;
		line[32] = 0x0d;
		line[33] = 0x0a;
		expect(canonicalizeBodyRelaxed(line)).toEqual(line);
	});

	it("splitRawMessage headerBlock survives re-encoding byte-exactly", () => {
		const raw = latin1Encode("X-Weird: café\r\n\r\nbody\r\n");
		const { headerBlock } = splitRawMessage(raw);
		expect(latin1Encode(headerBlock)).toEqual(raw.subarray(0, headerBlock.length));
	});
});
