// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	aggregateOrgOverview,
	bucketThreatPressure,
	computeLinkDomainRollup,
	computeP95,
	computeVerdictMix,
	pipelineSuccessRate,
	type LinkDomainUrlRow,
	type OrgMailboxSummary,
} from "../../workers/lib/dashboard-aggregation";

const NOW = new Date("2026-04-29T12:00:00Z");

function isoHoursAgo(hours: number): string {
	return new Date(NOW.getTime() - hours * 60 * 60 * 1000).toISOString();
}

function row(date: string | null, action: string | null) {
	return {
		date,
		security_verdict: action ? JSON.stringify({ action }) : null,
	};
}

describe("bucketThreatPressure", () => {
	it("returns 12 zero buckets when no rows are supplied", () => {
		const buckets = bucketThreatPressure([], { now: NOW });
		expect(buckets).toHaveLength(12);
		expect(buckets.every((v) => v === 0)).toBe(true);
	});

	it("ignores allow verdicts and unparseable JSON", () => {
		const rows = [
			row(isoHoursAgo(1), "allow"),
			{ date: isoHoursAgo(1), security_verdict: "not-json" },
			row(isoHoursAgo(1), "block"),
		];
		const buckets = bucketThreatPressure(rows, { now: NOW });
		expect(buckets.reduce((a, b) => a + b, 0)).toBe(1);
	});

	it("counts tag/quarantine/block verdicts", () => {
		const rows = [
			row(isoHoursAgo(0.5), "tag"),
			row(isoHoursAgo(0.5), "quarantine"),
			row(isoHoursAgo(0.5), "block"),
		];
		const buckets = bucketThreatPressure(rows, { now: NOW });
		expect(buckets.reduce((a, b) => a + b, 0)).toBe(3);
	});

	it("places older rows in lower-index buckets, newer rows in higher", () => {
		const rows = [
			row(isoHoursAgo(23), "block"), // oldest, bucket 0
			row(isoHoursAgo(0.5), "block"), // newest, bucket 11
		];
		const buckets = bucketThreatPressure(rows, { now: NOW });
		expect(buckets[0]).toBe(1);
		expect(buckets[11]).toBe(1);
		expect(buckets.slice(1, 11).every((v) => v === 0)).toBe(true);
	});

	it("drops rows outside the 24h window", () => {
		const rows = [
			row(isoHoursAgo(25), "block"), // too old
			row(isoHoursAgo(-1), "block"), // future
			row(isoHoursAgo(2), "block"), // in window
		];
		const buckets = bucketThreatPressure(rows, { now: NOW });
		expect(buckets.reduce((a, b) => a + b, 0)).toBe(1);
	});

	it("drops rows with unparseable dates", () => {
		const rows = [
			row("not-a-date", "block"),
			row(null, "block"),
			row(isoHoursAgo(1), "block"),
		];
		const buckets = bucketThreatPressure(rows, { now: NOW });
		expect(buckets.reduce((a, b) => a + b, 0)).toBe(1);
	});

	it("honors a custom bucket count and window", () => {
		const rows = [row(isoHoursAgo(0.25), "block")];
		const buckets = bucketThreatPressure(rows, {
			now: NOW,
			bucketCount: 4,
			windowHours: 1,
		});
		expect(buckets).toHaveLength(4);
		expect(buckets[3]).toBe(1);
	});
});

describe("pipelineSuccessRate", () => {
	it("returns null when no runs are recorded", () => {
		expect(pipelineSuccessRate({ completed: 0, failed: 0 })).toBeNull();
	});

	it("computes the success ratio when both buckets have counts", () => {
		expect(pipelineSuccessRate({ completed: 9, failed: 1 })).toBeCloseTo(0.9);
	});

	it("returns 1 when nothing failed and 0 when everything failed", () => {
		expect(pipelineSuccessRate({ completed: 5, failed: 0 })).toBe(1);
		expect(pipelineSuccessRate({ completed: 0, failed: 3 })).toBe(0);
	});
});

function verdictRow(action: string, label: string, date = NOW.toISOString()) {
	return {
		date,
		security_verdict: JSON.stringify({
			action,
			classification: { label },
		}),
	};
}

function summary(partial: Partial<OrgMailboxSummary> = {}): OrgMailboxSummary {
	return {
		threatsBlocked: 0,
		threatsBlocked7d: 0,
		openCases: 0,
		hubContributions: 0,
		pipelineScan: { completed: 0, failed: 0 },
		verdictRows: [],
		...partial,
	};
}

describe("computeVerdictMix", () => {
	it("tallies recognized labels and drops unparseable rows", () => {
		const mix = computeVerdictMix([
			verdictRow("allow", "safe"),
			verdictRow("allow", "safe"),
			verdictRow("tag", "suspicious"),
			verdictRow("quarantine", "phishing"),
			verdictRow("block", "phishing"),
			verdictRow("tag", "spam"),
			verdictRow("quarantine", "bec"),
			{ date: NOW.toISOString(), security_verdict: "not-json" },
			{ date: NOW.toISOString(), security_verdict: null },
		]);
		expect(mix).toEqual({
			safe: 2,
			suspicious: 1,
			phishing: 2,
			spam: 1,
			bec: 1,
		});
	});

	it("returns all-zeros for an empty input", () => {
		expect(computeVerdictMix([])).toEqual({
			safe: 0,
			suspicious: 0,
			phishing: 0,
			spam: 0,
			bec: 0,
		});
	});

	it("ignores labels outside the recognized set", () => {
		const mix = computeVerdictMix([verdictRow("tag", "marketing")]);
		expect(mix).toEqual({
			safe: 0,
			suspicious: 0,
			phishing: 0,
			spam: 0,
			bec: 0,
		});
	});
});

describe("aggregateOrgOverview", () => {
	it("returns zeroed counters and empty verdict mix for an empty org", () => {
		const result = aggregateOrgOverview({
			mailboxes: [],
			summaries: [],
			now: NOW.toISOString(),
		});
		expect(result).toMatchObject({
			threatsBlocked24h: 0,
			threatsBlocked7d: 0,
			openCasesTotal: 0,
			hubContributions24h: 0,
			mailboxesCount: 0,
			domainsCount: 0,
			topThreats: [],
			verdictMix: { safe: 0, suspicious: 0, phishing: 0, spam: 0, bec: 0 },
			verdictMix7d: { safe: 0, suspicious: 0, phishing: 0, spam: 0, bec: 0 },
			pipelineHealth: { successRate24h: null, p95Ms: null, runs24h: 0 },
		});
	});

	it("sums KPI counters across mailboxes and skips null (failed) summaries", () => {
		const result = aggregateOrgOverview({
			mailboxes: [
				{ id: "a@x.com", email: "a@x.com" },
				{ id: "b@x.com", email: "b@x.com" },
				{ id: "c@y.com", email: "c@y.com" },
			],
			summaries: [
				summary({
					threatsBlocked: 2,
					threatsBlocked7d: 14,
					openCases: 3,
					hubContributions: 1,
					pipelineScan: { completed: 90, failed: 10 },
				}),
				summary({
					threatsBlocked: 1,
					threatsBlocked7d: 7,
					openCases: 2,
					hubContributions: 0,
					pipelineScan: { completed: 100, failed: 0 },
				}),
				null, // c@y.com — DO call failed
			],
			now: NOW.toISOString(),
		});
		expect(result.mailboxesCount).toBe(3);
		expect(result.domainsCount).toBe(2);
		expect(result.threatsBlocked24h).toBe(3);
		expect(result.threatsBlocked7d).toBe(21);
		expect(result.openCasesTotal).toBe(5);
		expect(result.hubContributions24h).toBe(1);
		expect(result.pipelineHealth.runs24h).toBe(200);
		expect(result.pipelineHealth.successRate24h).toBeCloseTo(0.95);
		expect(result.pipelineHealth.p95Ms).toBeNull();
	});

	it("counts verdict-mix labels across all parseable rows", () => {
		const result = aggregateOrgOverview({
			mailboxes: [{ id: "m@x.com", email: "m@x.com" }],
			summaries: [
				summary({
					verdictRows: [
						verdictRow("allow", "safe"),
						verdictRow("tag", "suspicious"),
						verdictRow("quarantine", "phishing"),
						verdictRow("block", "phishing"),
						verdictRow("tag", "spam"),
						verdictRow("quarantine", "bec"),
						{ date: NOW.toISOString(), security_verdict: "not-json" },
					],
				}),
			],
			now: NOW.toISOString(),
		});
		expect(result.verdictMix).toEqual({
			safe: 1,
			suspicious: 1,
			phishing: 2,
			spam: 1,
			bec: 1,
		});
	});

	it("sums pre-aggregated 7d verdict mixes across mailboxes (#103)", () => {
		const result = aggregateOrgOverview({
			mailboxes: [
				{ id: "a@x.com", email: "a@x.com" },
				{ id: "b@x.com", email: "b@x.com" },
				{ id: "c@x.com", email: "c@x.com" },
			],
			summaries: [
				summary({
					verdictMix7d: { safe: 100, suspicious: 5, phishing: 2, spam: 3, bec: 0 },
				}),
				summary({
					verdictMix7d: { safe: 50, suspicious: 1, phishing: 4, spam: 1, bec: 1 },
				}),
				// Older DO replica without verdictMix7d — must be tolerated as zero.
				summary({}),
			],
			now: NOW.toISOString(),
		});
		expect(result.verdictMix7d).toEqual({
			safe: 150,
			suspicious: 6,
			phishing: 6,
			spam: 4,
			bec: 1,
		});
	});

	it("ranks top-threats by count and excludes safe/allow rows", () => {
		const result = aggregateOrgOverview({
			mailboxes: [{ id: "m@x.com", email: "m@x.com" }],
			summaries: [
				summary({
					verdictRows: [
						verdictRow("allow", "safe"), // excluded
						verdictRow("tag", "phishing"),
						verdictRow("quarantine", "phishing"),
						verdictRow("block", "phishing"),
						verdictRow("tag", "spam"),
						verdictRow("tag", "spam"),
						verdictRow("quarantine", "bec"),
					],
				}),
			],
			topN: 5,
			now: NOW.toISOString(),
		});
		expect(result.topThreats).toEqual([
			{ category: "phishing", count: 3 },
			{ category: "spam", count: 2 },
			{ category: "bec", count: 1 },
		]);
	});

	it("attaches per-category samples deduped by emailId across mailboxes (#101)", () => {
		const result = aggregateOrgOverview({
			mailboxes: [
				{ id: "a@x.com", email: "a@x.com" },
				{ id: "b@x.com", email: "b@x.com" },
			],
			summaries: [
				summary({
					verdictRows: [
						verdictRow("tag", "phishing"),
						verdictRow("quarantine", "phishing"),
						verdictRow("tag", "spam"),
					],
					topThreatSamples: {
						phishing: [
							{ emailId: "e1", subject: "Reset your password", sender: "fake@bank" },
							{ emailId: "e2", subject: "Invoice attached", sender: "vendor@x" },
						],
						spam: [{ emailId: "e3", subject: "Buy now", sender: "promo@x" }],
					},
				}),
				summary({
					verdictRows: [verdictRow("block", "phishing")],
					topThreatSamples: {
						// e1 also seen in mailbox A — should dedup. e4 is new.
						phishing: [
							{ emailId: "e1", subject: "Reset your password", sender: "fake@bank" },
							{ emailId: "e4", subject: "Wire transfer urgent", sender: "ceo@boss" },
						],
					},
				}),
			],
			samplesPerThreat: 3,
			now: NOW.toISOString(),
		});

		const phishing = result.topThreats.find((t) => t.category === "phishing")!;
		expect(phishing.count).toBe(3);
		expect(phishing.samples).toEqual([
			{ emailId: "e1", subject: "Reset your password", sender: "fake@bank" },
			{ emailId: "e2", subject: "Invoice attached", sender: "vendor@x" },
			{ emailId: "e4", subject: "Wire transfer urgent", sender: "ceo@boss" },
		]);

		const spam = result.topThreats.find((t) => t.category === "spam")!;
		expect(spam.count).toBe(1);
		expect(spam.samples).toEqual([
			{ emailId: "e3", subject: "Buy now", sender: "promo@x" },
		]);
	});

	it("respects samplesPerThreat and slices each category to the cap (#101)", () => {
		const result = aggregateOrgOverview({
			mailboxes: [{ id: "a@x.com", email: "a@x.com" }],
			summaries: [
				summary({
					verdictRows: [
						verdictRow("tag", "phishing"),
						verdictRow("tag", "phishing"),
					],
					topThreatSamples: {
						phishing: [
							{ emailId: "e1", subject: "s1", sender: "a" },
							{ emailId: "e2", subject: "s2", sender: "b" },
							{ emailId: "e3", subject: "s3", sender: "c" },
							{ emailId: "e4", subject: "s4", sender: "d" },
							{ emailId: "e5", subject: "s5", sender: "e" },
						],
					},
				}),
			],
			samplesPerThreat: 2,
			now: NOW.toISOString(),
		});
		const phishing = result.topThreats.find((t) => t.category === "phishing")!;
		expect(phishing.samples).toHaveLength(2);
		expect(phishing.samples).toEqual([
			{ emailId: "e1", subject: "s1", sender: "a" },
			{ emailId: "e2", subject: "s2", sender: "b" },
		]);
	});

	it("omits the samples field when no mailbox shipped any (#101 backwards compat)", () => {
		const result = aggregateOrgOverview({
			mailboxes: [{ id: "a@x.com", email: "a@x.com" }],
			summaries: [
				summary({
					verdictRows: [verdictRow("tag", "phishing")],
				}),
			],
			now: NOW.toISOString(),
		});
		expect(result.topThreats[0]).toEqual({ category: "phishing", count: 1 });
		expect(result.topThreats[0]).not.toHaveProperty("samples");
	});

	it("dedupes domain count by lowercased domain", () => {
		const result = aggregateOrgOverview({
			mailboxes: [
				{ id: "a@example.com", email: "a@example.com" },
				{ id: "b@Example.com", email: "b@Example.com" },
				{ id: "c@other.com", email: "c@other.com" },
				{ id: "no-domain", email: "no-domain" }, // ignored
			],
			summaries: [null, null, null, null],
			now: NOW.toISOString(),
		});
		expect(result.mailboxesCount).toBe(4);
		expect(result.domainsCount).toBe(2);
	});

	it("respects a custom topN", () => {
		const result = aggregateOrgOverview({
			mailboxes: [{ id: "m@x.com", email: "m@x.com" }],
			summaries: [
				summary({
					verdictRows: [
						verdictRow("tag", "phishing"),
						verdictRow("tag", "spam"),
						verdictRow("tag", "bec"),
					],
				}),
			],
			topN: 2,
			now: NOW.toISOString(),
		});
		expect(result.topThreats).toHaveLength(2);
	});

	it("unions per-mailbox pipelineDurationsMs and computes an org-wide p95", () => {
		// Two mailboxes contribute 10 + 10 samples; 2 are heavy-tailed outliers.
		// Union sorted: ten 100s, eight 200s, two 9000s. n=20, rank=0.95*19=18.05
		// → interpolate between sample[18]=9000 and sample[19]=9000 → 9000.
		const result = aggregateOrgOverview({
			mailboxes: [
				{ id: "a@x.com", email: "a@x.com" },
				{ id: "b@x.com", email: "b@x.com" },
			],
			summaries: [
				summary({
					pipelineDurationsMs: [
						100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
					],
				}),
				summary({
					pipelineDurationsMs: [200, 200, 200, 200, 200, 200, 200, 200, 9000, 9000],
				}),
			],
			now: NOW.toISOString(),
		});
		expect(result.pipelineHealth.p95Ms).toBe(9000);
	});

	it("returns null p95 when no mailbox contributes durations", () => {
		const result = aggregateOrgOverview({
			mailboxes: [{ id: "m@x.com", email: "m@x.com" }],
			summaries: [summary({})], // no pipelineDurationsMs
			now: NOW.toISOString(),
		});
		expect(result.pipelineHealth.p95Ms).toBeNull();
	});
});

describe("computeP95", () => {
	it("returns null for an empty sample", () => {
		expect(computeP95([])).toBeNull();
	});

	it("returns the single value for a one-element sample", () => {
		expect(computeP95([42])).toBe(42);
	});

	it("interpolates between adjacent ranks", () => {
		// 100 values 1..100 → rank = 0.95 * 99 = 94.05 → between sample[94]=95 and sample[95]=96
		const durations = Array.from({ length: 100 }, (_, i) => i + 1);
		expect(computeP95(durations)).toBeCloseTo(95.05, 2);
	});

	it("matches the top-tier value for a heavy-tailed distribution", () => {
		// 19 small values + 1 outlier — p95 sits in the outlier region.
		const durations = [
			...Array.from({ length: 19 }, () => 100),
			5000,
		];
		// Sorted: nineteen 100s then 5000. rank = 0.95 * 19 = 18.05 →
		// interpolate between sample[18]=100 and sample[19]=5000 = 100 + 0.05*(5000-100)
		expect(computeP95(durations)).toBeCloseTo(345, 0);
	});

	it("drops negative and non-finite values rather than counting them", () => {
		// Three 100s plus garbage that should be discarded.
		const durations = [100, 100, 100, Number.NaN, Number.POSITIVE_INFINITY, -50];
		expect(computeP95(durations)).toBe(100);
	});

	it("does not require pre-sorted input", () => {
		expect(computeP95([900, 100, 500, 200, 300])).toBeCloseTo(820, 0);
	});
});

describe("computeLinkDomainRollup", () => {
	function linkRow(
		hostname: string,
		emailId: string,
		action: string,
		label: string,
	): LinkDomainUrlRow {
		return {
			hostname,
			email_id: emailId,
			security_verdict: JSON.stringify({ action, classification: { label } }),
		};
	}

	it("dedups multiple URLs to the same host within one email", () => {
		const rows: LinkDomainUrlRow[] = [
			linkRow("evil.example.com", "e1", "block", "phishing"),
			linkRow("evil.example.com", "e1", "block", "phishing"), // second URL, same email — counts once
			linkRow("evil.example.com", "e2", "tag", "phishing"),
			linkRow("evil.example.com", "e3", "allow", "safe"),
		];
		const result = computeLinkDomainRollup(rows, 30);
		expect(result.hosts).toEqual([
			{ name: "evil.example.com", emails: 3, flagged: 2, phishing: 2, spam: 0 },
		]);
	});

	it("omits rows with fewer than 3 distinct emails", () => {
		const rows: LinkDomainUrlRow[] = [
			linkRow("rare.example.com", "e1", "tag", "phishing"),
			linkRow("rare.example.com", "e2", "tag", "phishing"),
		];
		expect(computeLinkDomainRollup(rows, 30).hosts).toEqual([]);
	});

	it("sorts by flagged desc, then emails desc", () => {
		const rows: LinkDomainUrlRow[] = [];
		// hostA: 5 emails, 1 flagged
		for (let i = 0; i < 5; i++) {
			rows.push(linkRow("a.example.com", `a${i}`, i === 0 ? "tag" : "allow", "safe"));
		}
		// hostB: 4 emails, 3 flagged
		for (let i = 0; i < 4; i++) {
			rows.push(linkRow("b.example.com", `b${i}`, i < 3 ? "tag" : "allow", "safe"));
		}
		// hostC: 10 emails, 3 flagged — ties hostB on flagged, wins on emails
		for (let i = 0; i < 10; i++) {
			rows.push(linkRow("c.example.com", `c${i}`, i < 3 ? "tag" : "allow", "safe"));
		}
		const result = computeLinkDomainRollup(rows, 30);
		expect(result.hosts.map((r) => r.name)).toEqual([
			"c.example.com",
			"b.example.com",
			"a.example.com",
		]);
	});

	it("caps each list at 50 rows", () => {
		const rows: LinkDomainUrlRow[] = [];
		for (let h = 0; h < 60; h++) {
			for (let e = 0; e < 3; e++) {
				rows.push(linkRow(`host${h}.example.com`, `e${h}-${e}`, "allow", "safe"));
			}
		}
		expect(computeLinkDomainRollup(rows, 30).hosts).toHaveLength(50);
	});

	it("rolls hosts up into their shared registrable domain", () => {
		const rows: LinkDomainUrlRow[] = [
			linkRow("www.example.com", "e1", "block", "phishing"),
			linkRow("mail.example.com", "e2", "block", "phishing"),
			linkRow("example.com", "e3", "allow", "safe"),
		];
		const result = computeLinkDomainRollup(rows, 30);
		expect(result.domains).toEqual([
			{ name: "example.com", emails: 3, flagged: 2, phishing: 2, spam: 0 },
		]);
		// Each individual host has only 1 email — below the <3 cutoff.
		expect(result.hosts).toEqual([]);
	});

	it("carries window_days through unchanged", () => {
		expect(computeLinkDomainRollup([], 7).window_days).toBe(7);
	});
});
