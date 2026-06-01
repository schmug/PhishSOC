// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import { csvEscapeField, sourcesToCsv } from "~/routes/dmarc";

describe("csvEscapeField", () => {
	it("wraps a plain string in double-quotes", () => {
		expect(csvEscapeField("hello")).toBe('"hello"');
	});

	it("preserves embedded commas inside the quoted field", () => {
		expect(csvEscapeField("hello, world")).toBe('"hello, world"');
	});

	it("doubles embedded double-quotes", () => {
		expect(csvEscapeField('say "hi"')).toBe('"say ""hi"""');
	});

	it("escapes a field containing both commas and double-quotes", () => {
		expect(csvEscapeField('a, "b", c')).toBe('"a, ""b"", c"');
	});

	it("handles numeric values", () => {
		expect(csvEscapeField(42)).toBe('"42"');
	});
});

describe("sourcesToCsv", () => {
	it("returns only the header row for an empty sources array", () => {
		expect(sourcesToCsv([])).toBe(
			"source_ip,total_count,pass_count,quarantine_count,reject_count,first_seen,last_seen",
		);
	});

	it("produces a well-formed two-line CSV for a single source", () => {
		const csv = sourcesToCsv([
			{
				source_ip: "203.0.113.1",
				total_count: 10,
				pass_count: 8,
				quarantine_count: 1,
				reject_count: 1,
				first_seen: "2026-01-01",
				last_seen: "2026-01-31",
				legitimate: 0,
			},
		]);
		const lines = csv.split("\r\n");
		expect(lines).toHaveLength(2);
		expect(lines[0]).toBe(
			"source_ip,total_count,pass_count,quarantine_count,reject_count,first_seen,last_seen",
		);
		expect(lines[1]).toBe('"203.0.113.1","10","8","1","1","2026-01-01","2026-01-31"');
	});

	it("safely escapes a source_ip that contains commas and quotes", () => {
		const csv = sourcesToCsv([
			{
				source_ip: '1.2.3.4, "label"',
				total_count: 1,
				pass_count: 1,
				quarantine_count: 0,
				reject_count: 0,
				first_seen: "2026-01-01",
				last_seen: "2026-01-31",
				legitimate: 0,
			},
		]);
		const lines = csv.split("\r\n");
		expect(lines[1]).toContain('"1.2.3.4, ""label"""');
	});

	it("produces CRLF line endings", () => {
		const csv = sourcesToCsv([
			{
				source_ip: "1.1.1.1",
				total_count: 1,
				pass_count: 1,
				quarantine_count: 0,
				reject_count: 0,
				first_seen: "2026-01-01",
				last_seen: "2026-01-02",
				legitimate: 0,
			},
		]);
		expect(csv).toContain("\r\n");
	});
});
