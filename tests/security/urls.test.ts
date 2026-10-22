import { describe, expect, it } from "vitest";
import {
	DECEPTIVE_LINK_TEXT_WEIGHT,
	displayedDomain,
	extractUrls,
	isHomographic,
	scoreUrls,
	type ExtractedUrl,
} from "../../workers/security/urls";

describe("extractUrls", () => {
	it("returns [] for empty/null input", () => {
		expect(extractUrls(null)).toEqual([]);
		expect(extractUrls(undefined)).toEqual([]);
		expect(extractUrls("")).toEqual([]);
	});

	it("extracts an anchor href and its visible display text", () => {
		const urls = extractUrls('<a href="https://example.com/login">Click here</a>');
		expect(urls).toHaveLength(1);
		expect(urls[0]).toMatchObject({
			url: "https://example.com/login",
			display_text: "Click here",
			hostname: "example.com",
		});
	});

	it("extracts bare URLs from plain text", () => {
		const urls = extractUrls("Visit https://example.com/path now.");
		expect(urls.map((u) => u.url)).toContain("https://example.com/path");
	});

	it("de-duplicates URLs by exact match", () => {
		const urls = extractUrls(
			'<a href="https://a.com/x">a</a> and <a href="https://a.com/x">b</a>',
		);
		expect(urls).toHaveLength(1);
	});

	it("caps output at the configured limit", () => {
		const body = Array.from({ length: 30 }, (_, i) => `https://example${i}.com`).join(" ");
		expect(extractUrls(body, 10)).toHaveLength(10);
	});

	it("ignores garbage that does not parse as a URL", () => {
		expect(extractUrls('<a href="javascript:void(0)">x</a>')).toEqual([]);
		expect(extractUrls("not a url")).toEqual([]);
	});

	it("flags shorteners on extracted URLs", () => {
		const urls = extractUrls("https://bit.ly/abc and https://tinyurl.com/xyz");
		expect(urls.every((u) => u.is_shortener)).toBe(true);
	});

	it("strips HTML from display_text", () => {
		const urls = extractUrls('<a href="https://example.com"><b>Click <i>here</i></b></a>');
		expect(urls[0].display_text).toBe("Click here");
	});

	it("canonicalizes the hostname (case, one trailing dot) and keeps the raw url", () => {
		const urls = extractUrls('<a href="https://Evil.Example./login">x</a>');
		expect(urls[0]).toMatchObject({ url: "https://Evil.Example./login", hostname: "evil.example" });
	});

	it("flags a lookalike host written with a trailing dot", () => {
		const urls = extractUrls("https://paypa1.com./login");
		expect(urls[0]).toMatchObject({ hostname: "paypa1.com", is_homograph: true });
	});

	it("drops a link whose host has an empty label", () => {
		expect(extractUrls("https://evil.example../login")).toEqual([]);
	});
});

describe("isHomographic", () => {
	it("flags non-ASCII hostnames", () => {
		expect(isHomographic("раypal.com")).toBe(true); // Cyrillic 'р'
		expect(isHomographic("münchen.example")).toBe(true);
	});

	it("flags bare punycode hostnames", () => {
		expect(isHomographic("xn--paypa-7ve.com")).toBe(true);
	});

	it("does NOT flag exact matches or subdomains of high-value domains", () => {
		expect(isHomographic("paypal.com")).toBe(false);
		expect(isHomographic("mail.google.com")).toBe(false);
		expect(isHomographic("accounts.google.com")).toBe(false);
	});

	it("flags typo-squats of high-value .com domains (Lev dist 1–2)", () => {
		expect(isHomographic("paypa1.com")).toBe(true);
		expect(isHomographic("g00gle.com")).toBe(true);
		expect(isHomographic("anazon.com")).toBe(true);
	});

	it("gives a host with one trailing dot the same result as without it", () => {
		expect(isHomographic("paypa1.com.")).toBe(true);
		expect(isHomographic("micros0ft.com.")).toBe(true);
		expect(isHomographic("paypal.com.")).toBe(false);
	});

	it("does not flag unrelated third-party domains", () => {
		expect(isHomographic("openai.com")).toBe(false);
		expect(isHomographic("rust-lang.org")).toBe(false);
	});

	it("handles multi-label public suffixes (amazon.co.uk and lookalikes)", () => {
		// Regression: earlier versions used last-2-labels as the registrable
		// domain, so `amazom.co.uk` was compared against `co.uk` (and slipped
		// through), and the real `amazon.co.uk` was fine only because of the
		// exact/suffix early return. Lookalikes of brands that are NOT in the
		// high-value list still go undetected — that's by design; we'd need a
		// broader brand database to catch those.
		expect(isHomographic("amazon.co.uk")).toBe(false);
		expect(isHomographic("amazom.co.uk")).toBe(true);
	});
});

describe("scoreUrls", () => {
	it("returns zero when all URLs are clean", () => {
		const urls: ExtractedUrl[] = [
			{ url: "https://a.com", hostname: "a.com", is_homograph: false, is_shortener: false },
		];
		expect(scoreUrls(urls)).toMatchObject({ score: 0, reasons: [], confidence: 1.0, contributions: [] });
	});

	it("scores a homograph URL at +20", () => {
		const urls: ExtractedUrl[] = [
			{ url: "https://paypa1.com", hostname: "paypa1.com", is_homograph: true, is_shortener: false },
		];
		expect(scoreUrls(urls).score).toBe(20);
	});

	it("scores a shortener at +5", () => {
		const urls: ExtractedUrl[] = [
			{ url: "https://bit.ly/x", hostname: "bit.ly", is_homograph: false, is_shortener: true },
		];
		expect(scoreUrls(urls).score).toBe(5);
	});

	it("stacks homograph + shortener", () => {
		const urls: ExtractedUrl[] = [
			{ url: "https://bit.ly/x", hostname: "bit.ly", is_homograph: false, is_shortener: true },
			{ url: "https://paypa1.com", hostname: "paypa1.com", is_homograph: true, is_shortener: false },
		];
		expect(scoreUrls(urls).score).toBe(25);
	});
});

describe("deceptive link text", () => {
	it("flags an anchor whose text is a different domain than its href", () => {
		const urls = extractUrls('<a href="https://evil.example/login">https://www.paypal.com/signin</a>');
		expect(urls[0].is_text_mismatch).toBe(true);
	});

	it("flags a bare-hostname anchor text", () => {
		const urls = extractUrls('<a href="https://collect.example.net/x">mybank.co.jp</a>');
		expect(urls[0].is_text_mismatch).toBe(true);
	});

	it("does not flag text on the same registrable domain", () => {
		const urls = extractUrls('<a href="https://login.example.com/a">www.example.com</a>');
		expect(urls[0].is_text_mismatch).toBeUndefined();
	});

	it("does not flag prose, filenames, or email addresses", () => {
		const urls = extractUrls(
			'<a href="https://a.example/1">Click here</a>' +
			'<a href="https://a.example/2">Visit example.com today</a>' +
			'<a href="https://a.example/3">invoice.pdf</a>' +
			'<a href="https://a.example/4">help@b.example</a>',
		);
		expect(urls.some((u) => u.is_text_mismatch)).toBe(false);
	});

	it("displayedDomain extracts the registrable domain from URL-shaped text", () => {
		expect(displayedDomain("https://Sub.Amazon.co.jp/path?q=1")).toBe("amazon.co.jp");
		expect(displayedDomain("example.org.")).toBe("example.org");
		expect(displayedDomain("not a domain")).toBeNull();
		expect(displayedDomain(undefined)).toBeNull();
	});

	it("scoreUrls adds deceptive_link_text with the shown and real hosts", () => {
		const urls = extractUrls('<a href="https://evil.example/x">paypal.com</a>');
		const r = scoreUrls(urls);
		expect(r.score).toBe(DECEPTIVE_LINK_TEXT_WEIGHT);
		expect(r.confidence).toBe(0.8);
		expect(r.contributions).toEqual([
			expect.objectContaining({ rule: "deceptive_link_text", weight: DECEPTIVE_LINK_TEXT_WEIGHT }),
		]);
		expect(r.reasons[0]).toContain("evil.example");
	});
});
