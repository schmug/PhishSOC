// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { describe, expect, it } from "vitest";
import { buildDmarcCsv, csvField } from "../../app/lib/dmarc-csv";

// Minimal shape needed for the CSV builder — mirrors the DmarcSource interface.
function makeSource(overrides: {
	source_ip: string;
	total_count?: number;
	pass_count?: number;
	quarantine_count?: number;
	reject_count?: number;
}) {
	return {
		source_ip: overrides.source_ip,
		total_count: overrides.total_count ?? 10,
		pass_count: overrides.pass_count ?? 8,
		quarantine_count: overrides.quarantine_count ?? 1,
		reject_count: overrides.reject_count ?? 1,
		first_seen: "2026-01-01T00:00:00Z",
		last_seen: "2026-01-31T00:00:00Z",
	};
}

describe("csvField", () => {
	it("wraps a plain string in double quotes", () => {
		expect(csvField("hello")).toBe('"hello"');
	});

	it("escapes embedded double quotes as double-double-quotes", () => {
		expect(csvField('say "hi"')).toBe('"say ""hi"""');
	});

	it("replaces embedded newlines with a space", () => {
		expect(csvField("line1\nline2")).toBe('"line1 line2"');
		expect(csvField("line1\r\nline2")).toBe('"line1 line2"');
	});

	it("coerces numbers and booleans to strings", () => {
		expect(csvField(42)).toBe('"42"');
		expect(csvField(true)).toBe('"true"');
		expect(csvField(false)).toBe('"false"');
	});
});

describe("buildDmarcCsv", () => {
	it("produces a header row as the first line", () => {
		const csv = buildDmarcCsv([]);
		const firstLine = csv.split("\r\n")[0];
		expect(firstLine).toBe(
			'"source_ip","label","message_count","pass_count","fail_count","legitimate"',
		);
	});

	it("returns only the header when sources is empty", () => {
		const csv = buildDmarcCsv([]);
		const lines = csv.split("\r\n");
		expect(lines).toHaveLength(1);
	});

	it("maps counts into the correct columns", () => {
		const csv = buildDmarcCsv([
			makeSource({ source_ip: "203.0.113.1", total_count: 10, pass_count: 8, quarantine_count: 1, reject_count: 1 }),
		]);
		const lines = csv.split("\r\n");
		// header + 1 data row
		expect(lines).toHaveLength(2);
		// fail_count = quarantine + reject = 1 + 1 = 2
		expect(lines[1]).toBe('"203.0.113.1","","10","8","2","false"');
	});

	it("sets legitimate=true when pass_count equals total_count", () => {
		const csv = buildDmarcCsv([
			makeSource({ source_ip: "198.51.100.1", total_count: 5, pass_count: 5, quarantine_count: 0, reject_count: 0 }),
		]);
		const dataRow = csv.split("\r\n")[1];
		expect(dataRow).toContain('"true"');
	});

	it("sets legitimate=false when pass_count is less than total_count", () => {
		const csv = buildDmarcCsv([
			makeSource({ source_ip: "198.51.100.2", total_count: 5, pass_count: 3, quarantine_count: 2, reject_count: 0 }),
		]);
		const dataRow = csv.split("\r\n")[1];
		expect(dataRow).toContain('"false"');
	});

	it("sets legitimate=false when total_count is 0", () => {
		const csv = buildDmarcCsv([
			makeSource({ source_ip: "198.51.100.3", total_count: 0, pass_count: 0, quarantine_count: 0, reject_count: 0 }),
		]);
		const dataRow = csv.split("\r\n")[1];
		expect(dataRow).toContain('"false"');
	});

	it("wraps a field containing a comma in double quotes without altering the comma", () => {
		// A comma inside a quoted CSV field must remain as-is (no escaping needed
		// for commas — the surrounding quotes make the comma non-structural).
		const field = csvField("192.0.2.1, extra");
		// The output is a double-quoted string; the comma is preserved verbatim.
		expect(field).toBe('"192.0.2.1, extra"');
		// The quoted wrapper starts and ends with a double-quote.
		expect(field.startsWith('"')).toBe(true);
		expect(field.endsWith('"')).toBe(true);
		// The raw comma is still present inside the quotes (a CSV parser would
		// correctly read this as a single field value "192.0.2.1, extra").
		expect(field).toContain(",");
	});

	it("properly escapes a field containing a double-quote", () => {
		// Simulate a label or annotation with an embedded quote (e.g. nickname).
		const field = csvField('Acme "Corp" Mailer');
		expect(field).toBe('"Acme ""Corp"" Mailer"');
	});

	it("produces a valid multi-row CSV with sources containing commas and quotes in IP/label data", () => {
		// Construct sources where the source_ip includes a comma and a double-quote
		// (not real IPs, but stress-tests the escaping path end-to-end).
		const sources = [
			makeSource({ source_ip: "203.0.113.1,extra", total_count: 20, pass_count: 20, quarantine_count: 0, reject_count: 0 }),
			makeSource({ source_ip: '198.51.100.1 "alias"', total_count: 7, pass_count: 3, quarantine_count: 2, reject_count: 2 }),
		];
		const csv = buildDmarcCsv(sources);
		const lines = csv.split("\r\n");
		expect(lines).toHaveLength(3); // header + 2 rows

		// Row 1: comma in source_ip → wrapped and escaped; fail_count = 0; legitimate = true
		expect(lines[1]).toBe('"203.0.113.1,extra","","20","20","0","true"');

		// Row 2: double-quote in source_ip → escaped as ""; fail_count = 4; legitimate = false
		expect(lines[2]).toBe('"198.51.100.1 ""alias""","","7","3","4","false"');
	});

	it("uses CRLF (\\r\\n) line endings", () => {
		const csv = buildDmarcCsv([makeSource({ source_ip: "1.2.3.4" })]);
		expect(csv).toContain("\r\n");
	});
});
