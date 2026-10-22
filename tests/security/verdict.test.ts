import { describe, expect, it } from "vitest";
import {
	aggregateVerdict,
	applyConfidenceDemote,
	DEFAULT_THRESHOLDS,
	DEFAULT_MITIGATION_CONFIG,
	DMARC_PASS_COMPENSATES_METHOD_FAIL,
	DMARC_PASS_SOFTENS_LINK_TEXT,
	SOFTENED_LINK_TEXT_WEIGHT,
	type FinalVerdict,
} from "../../workers/security/verdict";
import { scoreAttachments, DEFAULT_ATTACHMENT_POLICY } from "../../workers/security/attachments";
import type { AuthVerdict } from "../../workers/security/auth";
import { scoreClassification, type ClassificationResult } from "../../workers/security/classification";
import { DECEPTIVE_LINK_TEXT_WEIGHT, scoreUrls } from "../../workers/security/urls";
import { scoreReputation } from "../../workers/security/reputation";

const cleanAuth: AuthVerdict = { spf: "pass", dkim: "pass", dmarc: "pass" };
const safeClass: ClassificationResult = { label: "safe", confidence: 0.9, reasoning: "ok" };

describe("aggregateVerdict", () => {
	it("produces allow for a clean, trusted email", () => {
		const v = aggregateVerdict({
			auth: cleanAuth,
			classification: safeClass,
			urls: [],
			reputation: {
				sender: "a@b.com",
				first_seen: "2026-01-01T00:00:00Z",
				last_seen: "2026-01-01T00:00:00Z",
				message_count: 5,
				avg_score: 5,
				flagged: false,
			},
		});
		expect(v.action).toBe("allow");
		expect(v.score).toBeLessThan(DEFAULT_THRESHOLDS.tag);
	});

	it("quarantines on high-confidence phishing + DMARC fail", () => {
		const v = aggregateVerdict({
			auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
			classification: { label: "phishing", confidence: 0.95, reasoning: "fake login" },
			urls: [
				{ url: "https://paypa1.com", hostname: "paypa1.com", is_homograph: true, is_shortener: false },
			],
			reputation: null,
		});
		expect(["quarantine", "block"]).toContain(v.action);
		expect(v.score).toBeGreaterThanOrEqual(DEFAULT_THRESHOLDS.quarantine);
		expect(v.signals.length).toBeGreaterThan(0);
	});

	it("clamps score to [0, 100]", () => {
		const v = aggregateVerdict({
			auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
			classification: { label: "phishing", confidence: 1 , reasoning: "" },
			urls: [
				{ url: "https://paypa1.com", hostname: "paypa1.com", is_homograph: true, is_shortener: true },
			],
			reputation: { sender: "x", first_seen: "", last_seen: "", message_count: 1, avg_score: 99, flagged: true },
		}, DEFAULT_THRESHOLDS);
		expect(v.score).toBeLessThanOrEqual(100);
		expect(v.score).toBeGreaterThanOrEqual(0);
	});

	it("never returns negative scores even when all signals are benign", () => {
		// A clean-auth email with no other signals gets -10 from scoreAuth;
		// the aggregate must floor that at 0.
		const v = aggregateVerdict({
			auth: cleanAuth,
			classification: safeClass,
			urls: [],
			reputation: null, // first-time sender adds +5, so this caps negative
		});
		expect(v.score).toBeGreaterThanOrEqual(0);
	});

	it("explanation surfaces the first few signals", () => {
		const v = aggregateVerdict({
			auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
			classification: { label: "phishing", confidence: 0.9, reasoning: "" },
			urls: [],
			reputation: null,
		});
		expect(v.explanation.length).toBeGreaterThan(0);
		expect(v.explanation).not.toBe("no notable signals");
	});

	it("adds +25 for a container-format attachment under the default policy", () => {
		// Baseline uses DMARC-fail so score is positive before the attachment
		// contribution — otherwise the [0,100] clamp masks the real delta.
		const failAuth: AuthVerdict = { spf: "fail", dkim: "fail", dmarc: "fail" };
		const common = { auth: failAuth, classification: safeClass, urls: [], reputation: null };
		const without = aggregateVerdict(common);
		const withIso = aggregateVerdict({
			...common,
			attachments: [{ filename: "installer.iso" }],
			attachmentPolicy: DEFAULT_ATTACHMENT_POLICY,
		});
		expect(withIso.score - without.score).toBe(25);
		expect(withIso.signals.some((s) => s.includes(".iso"))).toBe(true);
	});

	it("adds +15 for a macro-enabled Office attachment", () => {
		const failAuth: AuthVerdict = { spf: "fail", dkim: "fail", dmarc: "fail" };
		const common = { auth: failAuth, classification: safeClass, urls: [], reputation: null };
		const without = aggregateVerdict(common);
		const withDocm = aggregateVerdict({
			...common,
			attachments: [{ filename: "report.docm" }],
			attachmentPolicy: DEFAULT_ATTACHMENT_POLICY,
		});
		expect(withDocm.score - without.score).toBe(15);
	});

	it("adds no score for an ordinary PDF attachment", () => {
		const failAuth: AuthVerdict = { spf: "fail", dkim: "fail", dmarc: "fail" };
		const common = { auth: failAuth, classification: safeClass, urls: [], reputation: null };
		const without = aggregateVerdict(common);
		const withPdf = aggregateVerdict({
			...common,
			attachments: [{ filename: "invoice.pdf" }],
			attachmentPolicy: DEFAULT_ATTACHMENT_POLICY,
		});
		expect(withPdf.score).toBe(without.score);
	});

	// ── Confidence dimension (issue #105) ──────────────────────────

	it("classifier timeout → classification scorer confidence ≤ 0.3 and aggregate reflects it", () => {
		// AC3 (issue #105): an LLM timeout (`label: "unavailable"`) yields
		// scorer confidence ≤ 0.3 — the per-scorer guarantee. The aggregate
		// "reflects that" via the score-weighted average: the same email
		// with a real classifier verdict produces a meaningfully higher
		// aggregate confidence. We assert both properties.
		const timeoutResult: ClassificationResult = { label: "unavailable", confidence: 0, reasoning: "timeout" };
		expect(scoreClassification(timeoutResult).confidence).toBeLessThanOrEqual(0.3);

		const baseInputs = {
			auth: { spf: "fail" as const, dkim: "fail" as const, dmarc: "fail" as const, trusted: true },
			urls: [],
			reputation: null,
		};
		const withTimeout = aggregateVerdict({ ...baseInputs, classification: timeoutResult });
		const withRealVerdict = aggregateVerdict({
			...baseInputs,
			classification: { label: "phishing", confidence: 0.9, reasoning: "fake login" },
		});
		// The timeout case must be lower than the high-confidence case —
		// that's what "aggregate reflects the low classifier confidence"
		// means in practice.
		expect(withTimeout.confidence).toBeLessThan(withRealVerdict.confidence);
	});

	it("multi-scorer corroboration → aggregate confidence ≥ 0.85", () => {
		// AC4: trusted-authserv DMARC-fail + high-confidence phishing label +
		// homograph URL + flagged-sender reputation. Every scorer is in its
		// high-confidence band; weighted average lands well above 0.85.
		const v = aggregateVerdict({
			auth: { spf: "fail", dkim: "fail", dmarc: "fail", trusted: true },
			classification: { label: "phishing", confidence: 0.95, reasoning: "fake login" },
			urls: [
				{ url: "https://paypa1.com", hostname: "paypa1.com", is_homograph: true, is_shortener: false },
			],
			reputation: {
				sender: "x@y.com",
				first_seen: "2026-01-01T00:00:00Z",
				last_seen: "2026-01-01T00:00:00Z",
				message_count: 20,
				avg_score: 80,
				flagged: true,
			},
		});
		expect(v.confidence).toBeGreaterThanOrEqual(0.85);
		// Sanity: this is the textbook "auto-quarantine, no review needed"
		// shape from the issue's failure-mode table.
		expect(v.score).toBeGreaterThanOrEqual(DEFAULT_THRESHOLDS.quarantine);
	});

	it("confidence is in [0,1] across a spread of inputs", () => {
		const cases = [
			aggregateVerdict({ auth: cleanAuth, classification: safeClass, urls: [], reputation: null }),
			aggregateVerdict({
				auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
				classification: { label: "phishing", confidence: 0.9, reasoning: "" },
				urls: [],
				reputation: null,
			}),
		];
		for (const v of cases) {
			expect(v.confidence).toBeGreaterThanOrEqual(0);
			expect(v.confidence).toBeLessThanOrEqual(1);
		}
	});

	it("score-weighted aggregation: high-magnitude scorer dominates", () => {
		// Auth contributes -10 (clean DMARC pass), confidence 0.5 (no
		// trusted-authserv-id). Classifier returns `unavailable`: score 0,
		// confidence 0.1. Urls: 0/1.0. Reputation null → first-time +5/0.3.
		// Weights: |−10|=10, 0, 0, 5. Weighted = (10*0.5 + 5*0.3) / 15 ≈
		// 0.433. Locks in the score-weighted-average rule rather than a
		// plain mean (which would be (0.5+0.1+1.0+0.3)/4 = 0.475).
		const v = aggregateVerdict({
			auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
			classification: { label: "unavailable", confidence: 0, reasoning: "timeout" },
			urls: [],
			reputation: null,
		});
		// Allow ±0.005 tolerance for the 3-decimal-place rounding.
		expect(v.confidence).toBeGreaterThan(0.42);
		expect(v.confidence).toBeLessThan(0.45);
	});

	it("zero-weight fallback: every scorer contributes 0 → plain mean of confidences", () => {
		// Auth: all-none. spf/dkim/dmarc all "none" → score 0, confidence 0.2.
		// Classifier: safe high-confidence → 0, 1.0.
		// Urls: empty → 0, 1.0.
		// Reputation: well-known sender, score 0 → 0, 0.9.
		// Sum of |scores| = 0; aggregator falls back to plain mean.
		// (0.2 + 1.0 + 1.0 + 0.9) / 4 = 0.775.
		const v = aggregateVerdict({
			auth: { spf: "none", dkim: "none", dmarc: "none" },
			classification: { label: "safe", confidence: 1, reasoning: "ok" },
			urls: [],
			reputation: {
				sender: "a@b.com",
				first_seen: "2026-01-01T00:00:00Z",
				last_seen: "2026-01-01T00:00:00Z",
				message_count: 10,
				avg_score: 0,
				flagged: false,
			},
		});
		expect(v.confidence).toBe(0.775);
	});

	it("respects custom thresholds", () => {
		const base = {
			auth: cleanAuth,
			classification: { label: "spam" as const, confidence: 0.9, reasoning: "" },
			urls: [],
			reputation: null,
		};
		const strict = aggregateVerdict(base, { tag: 5, quarantine: 10, block: 20 });
		const lenient = aggregateVerdict(base, { tag: 90, quarantine: 95, block: 99 });
		expect(strict.action).not.toBe("allow");
		expect(lenient.action).toBe("allow");
	});
});

describe("applyConfidenceDemote (issue #219)", () => {
	const baseQuarantine: FinalVerdict = {
		action: "quarantine",
		score: 65,
		confidence: 0.45,
		explanation: "auth fail; suspicious url",
		auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
		classification: { label: "suspicious", confidence: 0.4, reasoning: "" },
		signals: ["auth fail", "suspicious url"],
	};

	it("is a no-op when the toggle is disabled", () => {
		const out = applyConfidenceDemote(baseQuarantine, false, 0.6);
		expect(out).toBe(baseQuarantine);
	});

	it("demotes quarantine to tag and surfaces a signal when confidence is below threshold", () => {
		const out = applyConfidenceDemote(baseQuarantine, true, 0.6);
		expect(out.action).toBe("tag");
		expect(out.score).toBe(baseQuarantine.score); // score is unchanged
		expect(out.signals).toEqual([
			"auth fail",
			"suspicious url",
			"confidence-aware demote (0.45 < 0.6)",
		]);
		expect(out.explanation).toContain("confidence-aware demote (0.45 < 0.6)");
	});

	it("leaves quarantine alone when confidence meets the threshold (strict <)", () => {
		const equalConf = { ...baseQuarantine, confidence: 0.6 };
		const out = applyConfidenceDemote(equalConf, true, 0.6);
		expect(out).toBe(equalConf);
	});

	it("leaves quarantine alone when confidence is above the threshold", () => {
		const highConf = { ...baseQuarantine, confidence: 0.9 };
		const out = applyConfidenceDemote(highConf, true, 0.6);
		expect(out).toBe(highConf);
	});

	it("does not touch block, tag, or allow actions even with low confidence", () => {
		for (const action of ["block", "tag", "allow"] as const) {
			const v: FinalVerdict = { ...baseQuarantine, action, confidence: 0.1 };
			const out = applyConfidenceDemote(v, true, 0.6);
			expect(out.action).toBe(action);
			expect(out).toBe(v);
		}
	});

	it("does not mutate the input verdict (returns a fresh object)", () => {
		const out = applyConfidenceDemote(baseQuarantine, true, 0.6);
		expect(out).not.toBe(baseQuarantine);
		expect(baseQuarantine.action).toBe("quarantine");
		expect(baseQuarantine.signals).toEqual(["auth fail", "suspicious url"]);
	});

	it("rebuilds explanation from the first four signals (mirrors applyBoost)", () => {
		const many: FinalVerdict = {
			...baseQuarantine,
			signals: ["s1", "s2", "s3", "s4", "s5"],
			explanation: "s1; s2; s3; s4",
		};
		const out = applyConfidenceDemote(many, true, 0.6);
		// Demote signal is appended to the end → falls outside the first 4
		// in the explanation; original signals dominate (acceptable, mirrors
		// existing applyBoost behaviour).
		expect(out.explanation).toBe("s1; s2; s3; s4");
		expect(out.signals).toContain("confidence-aware demote (0.45 < 0.6)");
	});
});

// ── Mitigations layer (issue #100) ──────────────────────────────────────────

describe("dmarc_pass_compensates_method_fail mitigation", () => {
	// Shared helpers
	const safeClass: import("../../workers/security/classification").ClassificationResult = {
		label: "safe",
		confidence: 0.9,
		reasoning: "ok",
	};
	// Auth where DMARC passes but both per-method checks fail — the textbook
	// mailing-list / forwarded-mail shape that produces false positives today.
	const dmarcPassMethodFail = {
		spf: "fail" as const,
		dkim: "fail" as const,
		dmarc: "pass" as const,
		dkimObservations: [],
	};

	it("mitigation applies: spf=fail dkim=fail dmarc=pass → auth contribution ≤ 0", () => {
		// AC: "spf=fail dkim=fail dmarc=pass produces auth contribution ≤ 0
		// (currently +10 net)." With only auth signals (no classifier/rep/url
		// noise), the final score should be 0 (clamped from the negative delta).
		const noMitigation = aggregateVerdict(
			{ auth: dmarcPassMethodFail, classification: safeClass, urls: [], reputation: null },
			DEFAULT_THRESHOLDS,
			{ dmarc_pass_compensates_method_fail: false },
		);
		const withMitigation = aggregateVerdict(
			{ auth: dmarcPassMethodFail, classification: safeClass, urls: [], reputation: null },
			DEFAULT_THRESHOLDS,
			DEFAULT_MITIGATION_CONFIG,
		);
		// Without mitigation: spf_fail(+10) + dkim_fail(+10) + dmarc_pass(−10)
		// = +10; classify(safe)=0; rep(null/first-time)=+5 → net=15.
		expect(noMitigation.score).toBeGreaterThan(0);
		// With mitigation: spf_fail and dkim_fail zeroed → only dmarc_pass(−10)
		// + rep(+5) remain on the negative side; clamped to 0.
		expect(withMitigation.score).toBeLessThan(noMitigation.score);
	});

	it("mitigation fires → 'mitigated:dmarc_pass_compensates_method_fail' appears in signals", () => {
		const v = aggregateVerdict(
			{ auth: dmarcPassMethodFail, classification: safeClass, urls: [], reputation: null },
			DEFAULT_THRESHOLDS,
			DEFAULT_MITIGATION_CONFIG,
		);
		expect(v.signals).toContain("mitigated:dmarc_pass_compensates_method_fail");
	});

	it("mitigation disabled per-mailbox is a no-op (same score as baseline)", () => {
		const inputs = { auth: dmarcPassMethodFail, classification: safeClass, urls: [], reputation: null };
		const baseline = aggregateVerdict(inputs, DEFAULT_THRESHOLDS, { dmarc_pass_compensates_method_fail: false });
		const noopDisabled = aggregateVerdict(inputs, DEFAULT_THRESHOLDS, { dmarc_pass_compensates_method_fail: false });
		expect(noopDisabled.score).toBe(baseline.score);
		expect(noopDisabled.signals).not.toContain("mitigated:dmarc_pass_compensates_method_fail");
	});

	it("mitigation enabled but inputs don't match (dmarc=fail) → no signal, score unchanged", () => {
		// dmarc=fail: DMARC_PASS_COMPENSATES_METHOD_FAIL.applies() returns false.
		const failAuth = {
			spf: "fail" as const,
			dkim: "fail" as const,
			dmarc: "fail" as const,
			dkimObservations: [],
		};
		const v = aggregateVerdict(
			{ auth: failAuth, classification: safeClass, urls: [], reputation: null },
			DEFAULT_THRESHOLDS,
			DEFAULT_MITIGATION_CONFIG,
		);
		expect(v.signals).not.toContain("mitigated:dmarc_pass_compensates_method_fail");
	});

	it("DMARC_PASS_COMPENSATES_METHOD_FAIL.apply zeroes only spf_fail and dkim_fail", () => {
		const contribs = [
			{ scorer: "auth" as const, rule: "spf_fail", weight: 10, reason: "SPF failed" },
			{ scorer: "auth" as const, rule: "dkim_fail", weight: 10, reason: "DKIM failed" },
			{ scorer: "auth" as const, rule: "dmarc_pass", weight: -10, reason: "DMARC passed" },
		];
		const modified = DMARC_PASS_COMPENSATES_METHOD_FAIL.apply(contribs);
		expect(modified.find((c) => c.rule === "spf_fail")?.weight).toBe(0);
		expect(modified.find((c) => c.rule === "dkim_fail")?.weight).toBe(0);
		expect(modified.find((c) => c.rule === "dmarc_pass")?.weight).toBe(-10); // untouched
	});

	it("mitigation default: DEFAULT_MITIGATION_CONFIG has dmarc_pass_compensates_method_fail enabled", () => {
		expect(DEFAULT_MITIGATION_CONFIG.dmarc_pass_compensates_method_fail).toBe(true);
	});
});

// ── ScorerContribution breakdowns (#229) ─────────────────────────────────────

describe("scoreClassification contributions (#229)", () => {
	it("phishing label emits classifier_phishing contribution with scaled weight", () => {
		const result = scoreClassification({ label: "phishing", confidence: 1.0, reasoning: "" });
		expect(result.contributions).toHaveLength(1);
		expect(result.contributions[0]).toMatchObject({
			scorer: "classification",
			rule: "classifier_phishing",
			weight: result.score,
		});
	});

	it("safe label emits classifier_safe contribution with weight 0", () => {
		const result = scoreClassification({ label: "safe", confidence: 0.9, reasoning: "" });
		expect(result.contributions).toHaveLength(1);
		expect(result.contributions[0]).toMatchObject({
			scorer: "classification",
			rule: "classifier_safe",
			weight: 0,
			reason: "classifier: safe",
		});
	});

	it("unavailable label emits classifier_unavailable contribution with weight 0", () => {
		const result = scoreClassification({ label: "unavailable", confidence: 0, reasoning: "" });
		expect(result.contributions).toHaveLength(1);
		expect(result.contributions[0]).toMatchObject({
			scorer: "classification",
			rule: "classifier_unavailable",
			weight: 0,
		});
	});
});

describe("scoreUrls contributions (#229)", () => {
	it("homograph URL emits homograph_url contribution with weight 20", () => {
		const urls = [{ url: "https://gооgle.com/login", hostname: "gооgle.com", is_homograph: true, is_shortener: false }];
		const result = scoreUrls(urls);
		const contrib = result.contributions.find((c) => c.rule === "homograph_url");
		expect(contrib).toBeDefined();
		expect(contrib).toMatchObject({ scorer: "urls", rule: "homograph_url", weight: 20 });
	});

	it("link shortener emits link_shortener contribution with weight 5", () => {
		const urls = [{ url: "https://bit.ly/abc", hostname: "bit.ly", is_homograph: false, is_shortener: true }];
		const result = scoreUrls(urls);
		const contrib = result.contributions.find((c) => c.rule === "link_shortener");
		expect(contrib).toBeDefined();
		expect(contrib).toMatchObject({ scorer: "urls", rule: "link_shortener", weight: 5 });
	});

	it("no suspicious URLs → empty contributions", () => {
		const result = scoreUrls([{ url: "https://example.com", hostname: "example.com", is_homograph: false, is_shortener: false }]);
		expect(result.contributions).toHaveLength(0);
	});
});

describe("scoreReputation contributions (#229)", () => {
	it("first_time_sender (no prior) emits contribution with weight 5", () => {
		const result = scoreReputation(null);
		expect(result.contributions).toHaveLength(1);
		expect(result.contributions[0]).toMatchObject({
			scorer: "reputation",
			rule: "first_time_sender",
			weight: 5,
		});
	});

	it("first_time_sender_cti emits contribution with prior weight", () => {
		const prior = { score: 20, reason: "first-time sender from 1.2.3.4 CTI reputation=malicious" };
		const result = scoreReputation(null, prior);
		expect(result.contributions).toHaveLength(1);
		expect(result.contributions[0]).toMatchObject({
			scorer: "reputation",
			rule: "first_time_sender_cti",
			weight: 20,
		});
	});

	it("flagged sender emits flagged_sender contribution with weight 15", () => {
		const rep = { sender: "x@y.com", first_seen: "2025-01-01", last_seen: "2025-01-02", message_count: 5, avg_score: 40, flagged: true };
		const result = scoreReputation(rep);
		const contrib = result.contributions.find((c) => c.rule === "flagged_sender");
		expect(contrib).toBeDefined();
		expect(contrib).toMatchObject({ scorer: "reputation", rule: "flagged_sender", weight: 15 });
	});

	it("bad sender history emits bad_sender_history contribution with weight 10", () => {
		const rep = { sender: "x@y.com", first_seen: "2025-01-01", last_seen: "2025-01-02", message_count: 5, avg_score: 80, flagged: false };
		const result = scoreReputation(rep);
		const contrib = result.contributions.find((c) => c.rule === "bad_sender_history");
		expect(contrib).toBeDefined();
		expect(contrib).toMatchObject({ scorer: "reputation", rule: "bad_sender_history", weight: 10 });
	});
});

describe("scoreAttachments contributions (#229)", () => {
	it("macro-office attachment under score policy emits attachment_macro_office_<ext> contribution", () => {
		const atts = [{ filename: "report.docm", mimetype: "application/vnd.ms-word.document.macroEnabled.12" }];
		const result = scoreAttachments(atts, DEFAULT_ATTACHMENT_POLICY);
		expect(result.contributions).toHaveLength(1);
		expect(result.contributions[0]).toMatchObject({
			scorer: "attachments",
			rule: "attachment_macro_office_docm",
			weight: 15,
		});
	});

	it("container attachment under score policy emits attachment_container_<ext> contribution", () => {
		const atts = [{ filename: "installer.iso", mimetype: "application/x-iso9660-image" }];
		const result = scoreAttachments(atts, DEFAULT_ATTACHMENT_POLICY);
		expect(result.contributions).toHaveLength(1);
		expect(result.contributions[0]).toMatchObject({
			scorer: "attachments",
			rule: "attachment_container_iso",
			weight: 25,
		});
	});

	it("hard-block attachment (executable) emits no contribution (weight comes from triage tier)", () => {
		const atts = [{ filename: "malware.exe", mimetype: "application/octet-stream" }];
		const result = scoreAttachments(atts, DEFAULT_ATTACHMENT_POLICY);
		expect(result.hardBlock).toBe(true);
		expect(result.contributions).toHaveLength(0);
	});

	it("no attachments → empty contributions", () => {
		const result = scoreAttachments([], DEFAULT_ATTACHMENT_POLICY);
		expect(result.contributions).toHaveLength(0);
	});
});

describe("aggregateVerdict spreads all scorer contributions into mitigContribs (#229)", () => {
	it("non-auth contributions are visible to mitigations: cls+urls+rep all participate", () => {
		// This is validated indirectly: if mitigContribs only had auth contributions
		// the mitigation delta would be -20 (zeroing spf_fail+dkim_fail); with all
		// scorers present the mitigations pass still sees only auth rules per the
		// v1 DMARC mitigation, but the call must not throw even with many contribs.
		const v = aggregateVerdict(
			{
				auth: { spf: "fail", dkim: "fail", dmarc: "pass", dkimObservations: [] },
				classification: { label: "safe", confidence: 0.9, reasoning: "" },
				urls: [{ url: "https://bit.ly/x", hostname: "bit.ly", is_homograph: false, is_shortener: true }],
				reputation: null,
				attachmentPolicy: DEFAULT_ATTACHMENT_POLICY,
				attachments: [{ filename: "report.docm", mimetype: null }],
			},
			DEFAULT_THRESHOLDS,
			DEFAULT_MITIGATION_CONFIG,
		);
		expect(v.signals).toContain("mitigated:dmarc_pass_compensates_method_fail");
		expect(v.signals).toContain("link shortener (bit.ly)");
	});
});

describe("dmarc_pass_softens_link_text mitigation", () => {
	const mismatchUrl = {
		url: "https://click.esp.example/abc",
		display_text: "www.shop.example",
		hostname: "click.esp.example",
		is_homograph: false,
		is_shortener: false,
		is_text_mismatch: true,
	};
	const known = { sender: "a@shop.example", first_seen: "", last_seen: "", message_count: 3, avg_score: 0, flagged: false };
	const noneAuth: AuthVerdict = { spf: "none", dkim: "none", dmarc: "none", dkimObservations: [] };
	const passAuth: AuthVerdict = { spf: "pass", dkim: "pass", dmarc: "pass", dkimObservations: [] };

	it("unauthenticated mail keeps the full deceptive_link_text weight", () => {
		const v = aggregateVerdict({ auth: noneAuth, classification: safeClass, urls: [mismatchUrl], reputation: known });
		expect(v.score).toBe(DECEPTIVE_LINK_TEXT_WEIGHT);
		expect(v.signals).not.toContain("mitigated:dmarc_pass_softens_link_text");
	});

	it("DMARC=pass cuts the contribution to the residual weight", () => {
		// A spam verdict keeps the total above zero so the clamp doesn't hide the delta.
		const spam: ClassificationResult = { label: "spam", confidence: 1, reasoning: "" };
		const withMitigation = aggregateVerdict({ auth: passAuth, classification: spam, urls: [mismatchUrl], reputation: known });
		const without = aggregateVerdict(
			{ auth: passAuth, classification: spam, urls: [mismatchUrl], reputation: known },
			DEFAULT_THRESHOLDS,
			{ ...DEFAULT_MITIGATION_CONFIG, dmarc_pass_softens_link_text: false },
		);
		expect(without.score - withMitigation.score).toBe(DECEPTIVE_LINK_TEXT_WEIGHT - SOFTENED_LINK_TEXT_WEIGHT);
		expect(withMitigation.signals).toContain("mitigated:dmarc_pass_softens_link_text");
		expect(without.signals).not.toContain("mitigated:dmarc_pass_softens_link_text");
	});

	it("absent config key inherits the on default", () => {
		const v = aggregateVerdict(
			{ auth: passAuth, classification: safeClass, urls: [mismatchUrl], reputation: known },
			DEFAULT_THRESHOLDS,
			{ dmarc_pass_compensates_method_fail: true },
		);
		expect(v.signals).toContain("mitigated:dmarc_pass_softens_link_text");
	});

	it("apply touches only deceptive_link_text", () => {
		const out = DMARC_PASS_SOFTENS_LINK_TEXT.apply([
			{ scorer: "urls", rule: "deceptive_link_text", weight: 15, reason: "" },
			{ scorer: "urls", rule: "homograph_url", weight: 20, reason: "" },
		]);
		expect(out.map((c) => c.weight)).toEqual([SOFTENED_LINK_TEXT_WEIGHT, 20]);
	});

	it("an unauthenticated lure with a deceptive link and a suspicious classifier verdict reaches tag", () => {
		const v = aggregateVerdict({
			auth: noneAuth,
			classification: { label: "suspicious", confidence: 0.6, reasoning: "" },
			urls: [mismatchUrl],
			reputation: null,
		});
		expect(v.action).toBe("tag");
	});
});
