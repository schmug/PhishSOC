// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * `normalizeHost` / `canonicalFeedUrl` — the host and URL canonical forms
 * shared by link extraction and intel-feed ingest/lookup.
 */

import { describe, expect, it } from "vitest";
import { canonicalFeedUrl, normalizeHost } from "../../workers/lib/url-canonical";

describe("normalizeHost", () => {
	it.each([
		["evil.example", "evil.example"],
		["EVIL.Example", "evil.example"],
		["evil.example.", "evil.example"],
		["xn--pypal-4ve.com", "xn--pypal-4ve.com"],
		["pаypal.com", "xn--pypal-4ve.com"],
		["192.0.2.1", "192.0.2.1"],
	])("%s → %s", (input, expected) => {
		expect(normalizeHost(input)).toBe(expected);
	});

	it.each(["", ".", "evil.example..", ".evil.example", "a..example"])(
		"returns null for an empty label: %j",
		(input) => {
			expect(normalizeHost(input)).toBeNull();
		},
	);
});

describe("canonicalFeedUrl", () => {
	it.each([
		["https://phish.example/login", "https://phish.example/login"],
		["https://phish.example./login", "https://phish.example/login"],
		["HTTPS://PHISH.Example/login", "https://phish.example/login"],
		["https://phish.example:443/login", "https://phish.example/login"],
		["http://phish.example:80/login", "http://phish.example/login"],
		["https://phish.example/x/../login", "https://phish.example/login"],
		["https://phish.example/./login", "https://phish.example/login"],
		["https://phish.example/login?", "https://phish.example/login"],
		["https://phish.example/login#", "https://phish.example/login"],
		["https://phish.example/login?#", "https://phish.example/login"],
		["https://phish.example/%6Cogin", "https://phish.example/login"],
		["https://phish.example/a%7eb%2D", "https://phish.example/a~b-"],
		["https://phish.example/a%2fb%3a", "https://phish.example/a%2Fb%3A"],
		["http://phish.example", "http://phish.example/"],
		["  https://phish.example/login  ", "https://phish.example/login"],
		["https://anything@phish.example/login", "https://phish.example/login"],
		["https://user:pass@PHISH.example./login", "https://phish.example/login"],
	])("lossless: %s → %s", (input, expected) => {
		expect(canonicalFeedUrl(input)).toBe(expected);
	});

	it("keeps a non-empty fragment and the query", () => {
		expect(canonicalFeedUrl("https://app.example/#/t/evil")).toBe("https://app.example/#/t/evil");
		expect(canonicalFeedUrl("https://drive.example/open?id=AAA&x=1")).toBe(
			"https://drive.example/open?id=AAA&x=1",
		);
	});

	it("keeps path case", () => {
		expect(canonicalFeedUrl("https://phish.example/LOGIN")).toBe("https://phish.example/LOGIN");
	});

	it.each(["not a url", "ftp://phish.example/x", "mailto:a@phish.example", "https://phish.example../x"])(
		"returns null for %j",
		(input) => {
			expect(canonicalFeedUrl(input)).toBeNull();
		},
	);
});
