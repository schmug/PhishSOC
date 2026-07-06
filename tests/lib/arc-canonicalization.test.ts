import { describe, expect, it } from "vitest";
import {
	canonicalizeBodyRelaxed,
	canonicalizeHeaderRelaxed,
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
