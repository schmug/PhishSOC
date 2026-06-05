// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Regression for getDmarcSummary pass_count alignment semantics.
 *
 * pass_count must use dkim OR spf pass — the same rule as getDmarcAlignmentTotals,
 * getDmarcRollup, and getDmarcTimeSeries. AND semantics falsely flag major
 * providers (dkim pass / spf fail is common) as shadow-IT suspects.
 */

import { describe, expect, it } from "vitest";

type DmarcRecord = {
	count: number;
	dkim_result: string | null;
	spf_result: string | null;
};

/** Mirrors the pass_count CASE in MailboxDO.getDmarcSummary. */
function sumPassCount(records: DmarcRecord[]): number {
	return records.reduce((sum, r) => {
		const aligned = r.dkim_result === "pass" || r.spf_result === "pass";
		return sum + (aligned ? r.count : 0);
	}, 0);
}

describe("getDmarcSummary pass_count (dkim OR spf pass)", () => {
	it("counts dkim-pass / spf-fail as aligned", () => {
		const pass = sumPassCount([
			{ count: 100, dkim_result: "pass", spf_result: "fail" },
		]);
		expect(pass).toBe(100);
	});

	it("counts dkim-fail / spf-pass as aligned", () => {
		const pass = sumPassCount([
			{ count: 50, dkim_result: "fail", spf_result: "pass" },
		]);
		expect(pass).toBe(50);
	});

	it("excludes only when both mechanisms fail", () => {
		const pass = sumPassCount([
			{ count: 5, dkim_result: "pass", spf_result: "fail" },
			{ count: 3, dkim_result: "fail", spf_result: "pass" },
			{ count: 2, dkim_result: "fail", spf_result: "fail" },
		]);
		expect(pass).toBe(8);
	});
});
