// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Verdict aggregation — pure scoring function. No LLM call here.
 *
 * An LLM-final-judge was considered and rejected: it's opaque, adds latency
 * per email, and makes the pipeline harder to audit for an open-source
 * reference. The scoring function is deterministic given its inputs and
 * users can tune thresholds in mailbox settings.
 */

import type { AuthVerdict } from "./auth";
import type { ClassificationResult } from "./classification";
import type { ExtractedUrl } from "./urls";
import type { SenderReputation, FirstTimeSenderPrior } from "./reputation";
import type { AttachmentLike, AttachmentPolicy } from "./attachments";
import { scoreAuth } from "./auth";
import { scoreClassification } from "./classification";
import { scoreUrls } from "./urls";
import { scoreReputation } from "./reputation";
import { scoreAttachments } from "./attachments";

/**
 * A single named rule contribution from one scorer. Used by the mitigations
 * layer (issue #100) to identify and rewrite specific contributions without
 * touching the scorer itself.
 *
 * `weight` is the raw per-rule value before any scorer-internal capping. The
 * mitigations pass computes a delta from the rewritten contributions and
 * applies it to the post-sum, pre-clamp score.
 *
 * v1 coverage: only `scoreAuth` emits structured contributions. The remaining
 * scorers will add breakdowns in the follow-up for #100.
 */
export interface ScorerContribution {
	scorer: "auth" | "classification" | "urls" | "reputation" | "attachments";
	rule: string;    // stable id, e.g. "spf_fail", "dkim_fail"
	weight: number;  // raw per-rule value (not capped)
	reason: string;  // matches the reasons[] string
}

/**
 * Declarative mitigation: inspects the full `VerdictInputs` plus per-scorer
 * contributions and returns a rewritten contribution list. The aggregator
 * computes the score delta from the before/after sums and applies it before
 * clamping. Mitigation names appear in `FinalVerdict.signals` with the
 * `mitigated:` prefix so operator explanations stay auditable.
 */
export interface Mitigation {
	name: string;
	applies(inputs: VerdictInputs, contribs: ScorerContribution[]): boolean;
	apply(contribs: ScorerContribution[]): ScorerContribution[];
}

/**
 * Per-mailbox mitigation toggles. Each field corresponds to one named
 * mitigation; absent or `true` means the mitigation is active, `false`
 * disables it. Mirrors the `VerdictThresholds` pattern: operator-configurable,
 * with defaults in `DEFAULT_MITIGATION_CONFIG`.
 */
export interface MitigationConfig {
	/**
	 * When DMARC=pass, zero out the SPF and DKIM per-method fail contributions.
	 * A passing DMARC is itself the compensating control — the spec says SPF OR
	 * DKIM aligning is sufficient, so a failing method alongside a passing
	 * aggregate verdict should not add suspicion. Default: true (on by default).
	 */
	dmarc_pass_compensates_method_fail: boolean;
	/**
	 * When DMARC=pass, soften the `deceptive_link_text` URL contribution to
	 * {@link SOFTENED_LINK_TEXT_WEIGHT}. Authenticated bulk mail routinely
	 * shows its own domain while the href goes through an ESP click-tracking
	 * host; the signal keeps a small residual weight because a compromised
	 * account also passes DMARC. Absent ⇒ on (absent-key-inherits).
	 */
	dmarc_pass_softens_link_text?: boolean;
}

export const DEFAULT_MITIGATION_CONFIG: MitigationConfig = {
	dmarc_pass_compensates_method_fail: true,
	dmarc_pass_softens_link_text: true,
};

/**
 * v1 mitigation: when DMARC=pass, the per-method SPF/DKIM fail contributions
 * are zeroed out. DMARC alignment already proves either SPF or DKIM validated
 * the sending domain — penalising the other method's raw result double-counts
 * the failure and produces false positives on mailing-list and forwarded mail.
 *
 * Applied by `aggregateVerdict` before the [0,100] clamp, so the delta can
 * push the score below the auth subtotal (legitimate mail scoring -10 net
 * instead of today's +10 net for spf=fail dkim=fail dmarc=pass).
 */
export const DMARC_PASS_COMPENSATES_METHOD_FAIL: Mitigation = {
	name: "dmarc_pass_compensates_method_fail",
	applies(inputs) {
		return inputs.auth.dmarc === "pass";
	},
	apply(contribs) {
		return contribs.map((c) =>
			c.scorer === "auth" && (c.rule === "spf_fail" || c.rule === "dkim_fail")
				? { ...c, weight: 0 }
				: c,
		);
	},
};

/** Residual `deceptive_link_text` weight under DMARC=pass. */
export const SOFTENED_LINK_TEXT_WEIGHT = 5;

/**
 * When DMARC=pass, the `deceptive_link_text` contribution is cut to
 * {@link SOFTENED_LINK_TEXT_WEIGHT}. See `MitigationConfig.dmarc_pass_softens_link_text`.
 */
export const DMARC_PASS_SOFTENS_LINK_TEXT: Mitigation = {
	name: "dmarc_pass_softens_link_text",
	applies(inputs) {
		return inputs.auth.dmarc === "pass";
	},
	apply(contribs) {
		return contribs.map((c) =>
			c.scorer === "urls" && c.rule === "deceptive_link_text"
				? { ...c, weight: Math.min(c.weight, SOFTENED_LINK_TEXT_WEIGHT) }
				: c,
		);
	},
};

export type VerdictAction = "allow" | "tag" | "quarantine" | "block";

export interface FinalVerdict {
	action: VerdictAction;
	score: number;
	/**
	 * Aggregate confidence in [0,1]. Independent dimension from `score`:
	 * a high-score-low-confidence verdict (LLM timed out, only one signal
	 * fired) is fundamentally different from a high-score-high-confidence
	 * verdict (multiple corroborating signals). Computed as a score-weighted
	 * average of per-scorer confidences with `|score_i|` as the weight, so
	 * scorers that contributed more to the verdict influence overall
	 * confidence more. When the sum of weights is zero (every scorer
	 * contributed zero) we fall back to the plain mean of confidences. See
	 * {@link aggregateVerdict} and issue #105.
	 */
	confidence: number;
	explanation: string;
	auth: AuthVerdict;
	classification: ClassificationResult;
	signals: string[];
	/** If a triage tier short-circuited the pipeline, which one. */
	triage?: "hard_allow" | "hard_block" | "folder_bypass" | "attachment_block";
}

export interface VerdictInputs {
	auth: AuthVerdict;
	classification: ClassificationResult;
	urls: ExtractedUrl[];
	reputation: SenderReputation | null;
	/**
	 * PostalMime-parsed attachment metadata. Only filename/mimetype is read;
	 * the bodies already live in R2 by the time the pipeline runs.
	 */
	attachments?: AttachmentLike[];
	/**
	 * Attachment-type gate policy. When omitted or null, attachments
	 * contribute no score here. Hard-blocks are handled by the triage tier
	 * before aggregation; this hook only picks up the "score" contributions
	 * (container/macro-office under the defaults).
	 */
	attachmentPolicy?: AttachmentPolicy | null;
	/**
	 * Optional CTI-informed first-time-sender prior (issue #79). Computed in
	 * `runSecurityPipeline` from a CrowdSec CTI lookup on the originating
	 * `Received:` IP. When present and the sender has no history, replaces
	 * the legacy flat `+5` with a graduated bonus. Absent ⇒ legacy behaviour.
	 */
	firstTimeSenderPrior?: FirstTimeSenderPrior;
}

export interface VerdictThresholds {
	tag: number;        // score >= this → tag
	quarantine: number; // score >= this → quarantine
	block: number;      // score >= this → block (reserved for SMTP-layer; treated as quarantine here)
}

export const DEFAULT_THRESHOLDS: VerdictThresholds = {
	tag: 30,
	quarantine: 60,
	block: 80,
};

export function aggregateVerdict(
	inputs: VerdictInputs,
	thresholds: VerdictThresholds = DEFAULT_THRESHOLDS,
	mitigations: MitigationConfig = DEFAULT_MITIGATION_CONFIG,
): FinalVerdict {
	const signals: string[] = [];
	let score = 0;
	// Per-scorer (score, confidence) pairs collected for the weighted-average
	// aggregation below. Each scorer pushes one entry; the attachment scorer
	// is skipped entirely when no policy/attachments are present (see below).
	const contributions: Array<{ score: number; confidence: number }> = [];

	const auth = scoreAuth(inputs.auth);
	score += auth.score;
	signals.push(...auth.reasons);
	contributions.push({ score: auth.score, confidence: auth.confidence });

	const cls = scoreClassification(inputs.classification);
	score += cls.score;
	signals.push(...cls.reasons);
	contributions.push({ score: cls.score, confidence: cls.confidence });

	const urls = scoreUrls(inputs.urls);
	score += urls.score;
	signals.push(...urls.reasons);
	contributions.push({ score: urls.score, confidence: urls.confidence });

	const rep = scoreReputation(inputs.reputation, inputs.firstTimeSenderPrior);
	score += rep.score;
	signals.push(...rep.reasons);
	contributions.push({ score: rep.score, confidence: rep.confidence });

	// Attachment-type gate. Hard-blocks are handled by the triage tier before
	// we ever reach aggregation; here we only pick up the "score" action
	// contributions (container / macro-office under the defaults). If a
	// policy set `executable_action: "score"`, its contribution also lands
	// here rather than short-circuiting.
	const mitigContribs: ScorerContribution[] = [
		...auth.contributions,
		...cls.contributions,
		...urls.contributions,
		...rep.contributions,
	];
	if (inputs.attachmentPolicy && inputs.attachments && inputs.attachments.length > 0) {
		const att = scoreAttachments(inputs.attachments, inputs.attachmentPolicy);
		score += att.score;
		signals.push(...att.reasons);
		contributions.push({ score: att.score, confidence: att.confidence });
		mitigContribs.push(...att.contributions);
	}

	// ── Mitigations pass (issue #100) ─────────────────────────────────────────
	// Apply each enabled mitigation, sum the weight delta, and adjust `score`
	// before the final clamp so the mitigation can push the auth subtotal
	// negative on legitimate mail.
	const enabled: Mitigation[] = [];
	if (mitigations.dmarc_pass_compensates_method_fail) enabled.push(DMARC_PASS_COMPENSATES_METHOD_FAIL);
	if (mitigations.dmarc_pass_softens_link_text !== false) enabled.push(DMARC_PASS_SOFTENS_LINK_TEXT);
	for (const m of enabled) {
		if (!m.applies(inputs, mitigContribs)) continue;
		const modified = m.apply(mitigContribs);
		const origSum = mitigContribs.reduce((s, c) => s + c.weight, 0);
		const newSum = modified.reduce((s, c) => s + c.weight, 0);
		const delta = newSum - origSum;
		if (delta !== 0) {
			score += delta;
			signals.push(`mitigated:${m.name}`);
		}
	}

	score = Math.max(0, Math.min(100, Math.round(score)));

	let action: VerdictAction = "allow";
	if (score >= thresholds.block) action = "block";
	else if (score >= thresholds.quarantine) action = "quarantine";
	else if (score >= thresholds.tag) action = "tag";

	const explanation = signals.length > 0
		? signals.slice(0, 4).join("; ")
		: "no notable signals";

	return {
		action,
		score,
		confidence: aggregateConfidence(contributions),
		explanation,
		auth: inputs.auth,
		classification: inputs.classification,
		signals,
	};
}

/**
 * Issue #219: confidence-aware action mapping. Demotes a post-aggregation
 * `quarantine` verdict to `tag` when the aggregate confidence is strictly
 * below `minConfidence`. Pure function — does NOT mutate `verdict`.
 *
 * Applies only to the `quarantine` action: `block`, `tag`, and `allow` are
 * left untouched (the issue scopes this to the high-score-low-confidence
 * demote case; the symmetric "low-score-high-confidence" path is already
 * today's behaviour). Triage-tier short-circuit verdicts carry
 * `confidence: 1` so the threshold check naturally exempts them — the
 * pipeline also returns early on the short-circuit branch.
 *
 * The demote signal is appended to `signals` and the explanation is rebuilt
 * from the first four signals, mirroring `applyBoost` in
 * `workers/security/index.ts`.
 */
export function applyConfidenceDemote(
	verdict: FinalVerdict,
	enabled: boolean,
	minConfidence: number,
): FinalVerdict {
	if (!enabled) return verdict;
	if (verdict.action !== "quarantine") return verdict;
	if (verdict.confidence >= minConfidence) return verdict;
	const reason = `confidence-aware demote (${verdict.confidence} < ${minConfidence})`;
	const signals = [...verdict.signals, reason];
	return {
		...verdict,
		action: "tag",
		signals,
		explanation: signals.slice(0, 4).join("; "),
	};
}

/**
 * Combine per-scorer confidences into a single value in [0,1].
 *
 * v1 (issue #105): score-weighted average using `|score_i|` as the weight.
 * Scorers that drove the verdict more dominate the aggregate. The absolute
 * value matters because `scoreAuth` can contribute negative score (DMARC
 * pass = -10) — that's still a strong signal worth weighting at 10, not 0.
 *
 * Edge case: every scorer contributed exactly zero (a pristine-but-uncertain
 * email — no auth headers, no urls, classifier returned safe-with-zero).
 * Sum of weights is zero so the weighted-average is undefined; we fall back
 * to the plain mean of confidences. Result is rounded to 3 decimal places
 * so JSON-serialised verdicts don't churn on float dust.
 */
function aggregateConfidence(
	contributions: ReadonlyArray<{ score: number; confidence: number }>,
): number {
	if (contributions.length === 0) return 1;
	let weightedSum = 0;
	let weightTotal = 0;
	let plainSum = 0;
	for (const c of contributions) {
		const w = Math.abs(c.score);
		weightedSum += w * c.confidence;
		weightTotal += w;
		plainSum += c.confidence;
	}
	const raw = weightTotal > 0
		? weightedSum / weightTotal
		: plainSum / contributions.length;
	return Math.round(raw * 1000) / 1000;
}
