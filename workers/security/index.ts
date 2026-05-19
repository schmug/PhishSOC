// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Synchronous security pipeline. Runs inline during `receiveEmail()` between
 * the email being stored to INBOX and the agent auto-draft trigger. Returns
 * a verdict; the caller decides whether to move to QUARANTINE.
 *
 * Staged so latency stays bounded:
 *   1. Parse SPF/DKIM/DMARC from raw headers               (µs)
 *   2. Sender reputation lookup (per-mailbox SQLite)        (ms)
 *   3. URL extraction + homograph/shortener heuristics      (ms)
 *   4. LLM classification (Workers AI, 5s timeout)          (seconds)
 *   5. Aggregate verdict (pure scoring function)            (µs)
 *   6. Persist verdict + URLs + sender reputation           (ms)
 *
 * Async deep-scan (attachment OCR, URL fetch, RDAP) is enqueued by the caller
 * once `workers/intel/deep-scan.ts` is wired up — out of scope for this
 * module so the sync path has no dependency on Queue bindings.
 */

import type { Env } from "../types";
import { getMailboxStub } from "../lib/email-helpers";
import { parseAuthResults, extractReceivedFromIp, scoreAuth } from "./auth";
import { classifyEmail, scoreClassification } from "./classification";
import { extractUrls, scoreUrls } from "./urls";
import { aggregateVerdict, applyConfidenceDemote, type FinalVerdict } from "./verdict";
import { resolveMailboxSettings } from "../lib/mailbox-settings";
import { checkUrlAgainstFeeds, type FeedMatch } from "../intel/feeds";
import { evaluateTriage, type IntelMatchInfo } from "./triage";
import type { AttachmentLike } from "./attachments";
import { scoreOffHours } from "./time-rules";
import type { VerdictThresholds } from "./verdict";
import {
	firstTimeSenderPriorFromCti,
	scoreReputation,
	type FirstTimeSenderPrior,
} from "./reputation";
import { lookupIp } from "../intel/crowdsec-cti";
import type { StageId, StageRecord, StageStatus } from "./stage-trace";
import { SenderGraphDetector } from "./detectors";

/**
 * Apply a post-aggregation score bump and recompute the action tier and
 * explanation. Used for signals that only fire after the main verdict has
 * been computed (intel feed hits, off-hours delivery).
 */
function applyBoost(
	verdict: FinalVerdict,
	boost: number,
	reason: string,
	thresholds: VerdictThresholds,
): FinalVerdict {
	const newScore = Math.min(100, verdict.score + boost);
	const action: FinalVerdict["action"] = newScore >= thresholds.block ? "block"
		: newScore >= thresholds.quarantine ? "quarantine"
		: newScore >= thresholds.tag ? "tag"
		: "allow";
	const signals = [...verdict.signals, reason];
	return {
		...verdict,
		score: newScore,
		action,
		signals,
		explanation: signals.slice(0, 4).join("; "),
	};
}

export interface RunPipelineInput {
	env: Env;
	mailboxId: string;
	messageId: string;
	/** Folder the message was delivered into. Drives the folder-bypass triage tier. */
	targetFolder: string;
	parsedEmail: {
		subject?: string;
		from?: { address?: string; name?: string };
		html?: string;
		text?: string;
		headers?: unknown;
		attachments?: AttachmentLike[];
	};
}

export interface PipelineResult {
	/** Null means the pipeline was skipped (security disabled for this mailbox). */
	verdict: FinalVerdict | null;
	skipped: boolean;
	/**
	 * Per-stage trace (issue #128). One record per stage in `STAGE_IDS`
	 * order; stages that didn't run get `status: "skipped"` (or
	 * `"short_circuited"` for the triage row that fired) with
	 * `score_contrib: 0` and `duration_ms: 0`. Empty array when the
	 * mailbox has security disabled (matches `skipped: true`).
	 */
	stageTrace: StageRecord[];
}

export async function runSecurityPipeline(input: RunPipelineInput): Promise<PipelineResult> {
	const { env, mailboxId, messageId, parsedEmail, targetFolder } = input;
	const resolved = await resolveMailboxSettings(env, mailboxId);
	const settings = resolved.security;
	if (!settings.enabled) return { verdict: null, skipped: true, stageTrace: [] };

	const sender = (parsedEmail.from?.address || "").toLowerCase();
	const senderName = (parsedEmail.from?.name || "").toLowerCase().trim();
	const bodyHtml = parsedEmail.html || parsedEmail.text || "";
	const subject = parsedEmail.subject || "";
	const attachments = parsedEmail.attachments ?? [];

	// Per-stage trace (issue #128). Stages are pushed in pipeline order
	// (auth → url → reputation → intel → triage → llm → verdict). Both
	// the short-circuit branch and the full-aggregation branch end with
	// a complete 7-row trace so the timeline UI can render uniformly.
	const tracer = new StageTracer();

	// ── Stage 1: auth ──────────────────────────────────────────────
	const auth = tracer.measure("auth", () =>
		parseAuthResults(parsedEmail.headers, {
			trustedAuthservIds: settings.trusted_authserv_ids,
		}),
	);
	const authContrib = scoreAuth(auth);
	tracer.setContrib("auth", authContrib.score, authContrib.reasons[0]);

	// DKIM selector observation rollup (#170). Best-effort — a slow / failed
	// DO write must NOT delay the verdict path. Trusted-id gating already
	// happened inside `parseAuthResults`, so anything in `auth.dkimObservations`
	// is safe to persist; the DO method de-dupes and runs the lazy 30d GC.
	if (auth.dkimObservations.length > 0) {
		const stub = getMailboxStub(env, mailboxId);
		void stub
			.recordDkimSelectorsObserved(auth.dkimObservations)
			.catch((e) =>
				console.error(
					"recordDkimSelectorsObserved failed:",
					(e as Error).message,
				),
			);
	}

	// ── Stage 2: url extraction ────────────────────────────────────
	const urls = tracer.measure("url", () => extractUrls(bodyHtml));
	const urlContrib = scoreUrls(urls);
	tracer.setContrib("url", urlContrib.score, urlContrib.reasons[0]);

	// ── Stage 3: intel-feed lookup ─────────────────────────────────
	// First confirmed hit wins. Kept early (pre-triage) so the hard-block
	// tier can short-circuit on it.
	const intelMatch = await tracer.measureAsync("intel", async () => {
		let m: FeedMatch | null = null;
		for (const u of urls) {
			const hit = await checkUrlAgainstFeeds(env, mailboxId, u.url).catch(() => null);
			if (!hit) continue;
			if (hit.confirmed) { m = hit; break; }
			if (!m) m = hit;
		}
		return m;
	});
	const intelForTriage: IntelMatchInfo | null = intelMatch?.confirmed
		? { matched: true, feedId: intelMatch.feedId, value: intelMatch.value, confirmed: true }
		: null;

	// ── Stage 4: reputation (incl. CTI prior) ──────────────────────
	const stub = getMailboxStub(env, mailboxId);
	const reputation = await tracer.measureAsync("reputation", async () =>
		sender ? await stub.getSenderReputation(sender) : null,
	);

	// First-time-sender CTI prior (issue #79). Only fired when the sender has
	// no prior history (or was never seen), so cardinality is "new senders
	// per mailbox" — well within the 12h-cached free-tier budget. When CTI
	// returns null (no API key configured, 404 clean residential, 429 rate-
	// limit, network error) we fall through and `scoreReputation` keeps the
	// legacy flat +5. The lookup must NOT fail the email path on transient
	// errors; `lookupIp` already swallows them and returns null. Folded into
	// the `reputation` stage measurement so the trace stays at 7 rows.
	let firstTimeSenderPrior: FirstTimeSenderPrior | undefined;
	if ((!reputation || reputation.message_count === 0) && env.CROWDSEC_CTI_API_KEY) {
		const senderIp = extractReceivedFromIp(parsedEmail.headers);
		if (senderIp) {
			await tracer.extend("reputation", async () => {
				const summary = await lookupIp(env, senderIp).catch(() => null);
				if (summary) firstTimeSenderPrior = firstTimeSenderPriorFromCti(senderIp, summary);
			});
		}
	}
	const repContrib = scoreReputation(reputation, firstTimeSenderPrior);
	tracer.setContrib("reputation", repContrib.score, repContrib.reasons[0]);

	// ── Sender-graph detector (issue #26) ──────────────────────────
	// BEC / display-name impersonation signal. Folded into the reputation
	// stage's wall-clock time (it's another per-mailbox DO read) so the
	// trace stays at 7 rows. Score is applied as a post-aggregation boost
	// in the verdict stage, bounded at +30.
	let detectorBoost = 0;
	let detectorReason: string | undefined;
	if (settings.detectors?.sender_graph?.enabled !== false && senderName) {
		await tracer.extend("reputation", async () => {
			const detector = new SenderGraphDetector();
			const result = await detector.score({ senderAddress: sender, senderName }, stub).catch(() => ({ score: 0, reason: undefined }));
			detectorBoost = Math.min(30, result.score);
			detectorReason = result.reason;
		});
	}

	// ── Stage 5: triage ────────────────────────────────────────────
	const triaged = tracer.measure("triage", () =>
		evaluateTriage({
			sender,
			auth,
			reputation,
			urls,
			intelMatch: intelForTriage,
			settings,
			targetFolder,
			attachments,
		}),
	);
	if (triaged.shortcircuit) {
		const sc = triaged.shortcircuit;
		let verdict: FinalVerdict = { ...sc.verdict, triage: sc.tier };
		// Learning mode still applies — even a hard-block is downgraded to tag.
		if (settings.learning_mode && (verdict.action === "quarantine" || verdict.action === "block")) {
			verdict = { ...verdict, action: "tag" };
		}
		// Triage row carries the full short-circuit verdict score; downstream
		// stages run zero work and stay at the default `skipped` filler.
		tracer.shortCircuitTriage(verdict.score, `${sc.tier}: ${sc.reason}`);
		// Intel-row hygiene on the short-circuit path: if triage fired on a
		// confirmed-intel match, the boost is already absorbed by the
		// short-circuit verdict score on the triage row. Surfacing the
		// boost a second time on the intel row would let an analyst sum
		// the visible contributions and get a number bigger than the
		// final verdict — a misleading "double count". Keep the intel
		// row informational (status: ok, score_contrib: 0, reason names
		// the matched feed/value) so the row still tells the story
		// without breaking row-sum sanity.
		if (intelMatch) {
			tracer.setContrib(
				"intel",
				0,
				`${intelMatch.feedId}:${intelMatch.value}`,
			);
		}
		tracer.completeVerdict(verdict.score);
		await persistAll(env, mailboxId, messageId, sender, senderName, verdict, urls, tracer.snapshot());
		return { verdict, skipped: false, stageTrace: tracer.snapshot() };
	}

	// ── Stage 6: LLM classifier ────────────────────────────────────
	// Full path: LLM classification (possibly skipped by folder-bypass tier) + aggregation.
	// `classifierModel` is org-level only post-#106 (per-mailbox override is a
	// follow-up; switching to a weaker classifier per mailbox is too sharp a
	// security lever to expose without UI guardrails). The resolver returns
	// the org value or the system default — never undefined.
	const classification = triaged.skipClassifier
		? { label: "safe" as const, confidence: 1.0, reasoning: "classifier skipped by folder policy" }
		: await tracer.measureAsync("llm", () =>
			classifyEmail(
				env.AI,
				{ subject, sender, bodyHtml, auth },
				{
					model: resolved.classifierModel,
					// Issue #28: per-mailbox toggle for the narrowed Rule 5 behavior.
					// `true` (default) → timeouts contribute 0 instead of failing
					// closed to `suspicious`. `false` preserves the legacy behavior.
					skipOnTimeout: settings.classification.skip_on_timeout,
				},
			),
		);
	if (triaged.skipClassifier) {
		tracer.markSkipped("llm", "classifier skipped by folder policy");
	} else {
		const llmContrib = scoreClassification(classification);
		tracer.setContrib("llm", llmContrib.score, llmContrib.reasons[0]);
	}

	// ── Stage 7: verdict aggregation + post-aggregation boosts ─────
	let verdict = await tracer.measureAsync("verdict", async () => {
		let v = aggregateVerdict(
			{
				auth,
				classification,
				urls,
				reputation,
				attachments,
				attachmentPolicy: settings.attachment_policy,
				firstTimeSenderPrior,
			},
			settings.thresholds,
			settings.mitigations,
		);
		// Intel-feed boost. Confirmed hit bumps score by 20; unconfirmed bloom-only
		// hit bumps by 5 (low-signal — bloom FPR is configured at ~1%).
		const intelBoost = intelMatch?.confirmed ? 20 : intelMatch ? 5 : 0;
		if (intelBoost > 0 && intelMatch) {
			const label = intelMatch.confirmed ? "threat-intel match" : "threat-intel match (unconfirmed)";
			const reason = `${label} (${intelMatch.feedId}: ${intelMatch.value})`;
			v = applyBoost(v, intelBoost, reason, settings.thresholds);
		}
		// Off-hours boost. Small nudge (+10) so it can only tilt borderline verdicts.
		const offHours = scoreOffHours(settings.business_hours);
		if (offHours.score > 0) {
			v = applyBoost(v, offHours.score, offHours.reasons[0], settings.thresholds);
		}
		// Sender-graph detector boost (issue #26). Capped at +30 by construction.
		if (detectorBoost > 0 && detectorReason) {
			v = applyBoost(v, detectorBoost, detectorReason, settings.thresholds);
		}
		// Learning mode never quarantines/blocks — cap at "tag".
		if (settings.learning_mode && (v.action === "quarantine" || v.action === "block")) {
			v = { ...v, action: "tag" };
		}
		// Confidence-aware action mapping (issue #219). Evaluated against the
		// post-boost state so an intel/off-hours bump that pushed the score
		// over the quarantine threshold can still be demoted when confidence
		// is low. No-op when the toggle is off (default) or the verdict
		// isn't a quarantine; learning_mode ran first so a capped verdict is
		// already `tag` and falls through unchanged.
		v = applyConfidenceDemote(
			v,
			settings.confidence_aware_actions,
			settings.min_confidence_for_quarantine,
		);
		return v;
	});
	const intelBoost = intelMatch?.confirmed ? 20 : intelMatch ? 5 : 0;
	if (intelMatch) {
		tracer.setContrib(
			"intel",
			intelBoost,
			`${intelMatch.feedId}:${intelMatch.value}`,
		);
	}
	tracer.completeVerdict(verdict.score);

	const stageTrace = tracer.snapshot();
	await persistAll(env, mailboxId, messageId, sender, senderName, verdict, urls, stageTrace);
	return { verdict, skipped: false, stageTrace };
}

/**
 * Per-pipeline-run accumulator for the issue #128 stage trace. Owns the
 * 7-row buffer and the wall-clock timing wrappers so the pipeline body
 * stays readable and both branches converge on a complete trace.
 *
 * Filler invariant: `snapshot()` always returns exactly 7 records in
 * `STAGE_IDS` order. Stages that never ran return `status: "skipped"`
 * with `score_contrib: 0` and `duration_ms: 0`, so the UI can render
 * all rows without conditional-render gymnastics.
 */
class StageTracer {
	private records = new Map<StageId, StageRecord>();

	constructor() {
		const fillers: StageId[] = [
			"auth", "url", "reputation", "intel", "triage", "llm", "verdict",
		];
		for (const id of fillers) {
			this.records.set(id, {
				stage: id,
				status: "skipped",
				score_contrib: 0,
				duration_ms: 0,
			});
		}
	}

	private setStatus(id: StageId, status: StageStatus): void {
		const cur = this.records.get(id);
		if (!cur) return;
		this.records.set(id, { ...cur, status });
	}

	measure<T>(id: StageId, fn: () => T): T {
		const start = Date.now();
		try {
			const result = fn();
			this.recordOk(id, Date.now() - start);
			return result;
		} catch (err) {
			this.recordFailed(id, Date.now() - start, (err as Error).message);
			throw err;
		}
	}

	async measureAsync<T>(id: StageId, fn: () => Promise<T>): Promise<T> {
		const start = Date.now();
		try {
			const result = await fn();
			this.recordOk(id, Date.now() - start);
			return result;
		} catch (err) {
			this.recordFailed(id, Date.now() - start, (err as Error).message);
			throw err;
		}
	}

	/** Add wall-clock time to an already-measured stage (e.g. CTI prior). */
	async extend(id: StageId, fn: () => Promise<void>): Promise<void> {
		const start = Date.now();
		await fn();
		const cur = this.records.get(id);
		if (!cur) return;
		this.records.set(id, {
			...cur,
			duration_ms: cur.duration_ms + (Date.now() - start),
		});
	}

	setContrib(id: StageId, score_contrib: number, reason?: string): void {
		const cur = this.records.get(id);
		if (!cur) return;
		this.records.set(id, {
			...cur,
			score_contrib,
			...(reason && reason.length > 0 ? { reason } : {}),
		});
	}

	markSkipped(id: StageId, reason?: string): void {
		const cur = this.records.get(id);
		if (!cur) return;
		this.records.set(id, {
			...cur,
			status: "skipped",
			score_contrib: 0,
			...(reason && reason.length > 0 ? { reason } : {}),
		});
	}

	private recordOk(id: StageId, duration_ms: number): void {
		const cur = this.records.get(id);
		if (!cur) return;
		this.records.set(id, { ...cur, status: "ok", duration_ms });
	}

	private recordFailed(id: StageId, duration_ms: number, message: string): void {
		const cur = this.records.get(id);
		if (!cur) return;
		this.records.set(id, {
			...cur,
			status: "failed",
			duration_ms,
			reason: message.slice(0, 200),
		});
	}

	shortCircuitTriage(score: number, reason: string): void {
		this.setStatus("triage", "short_circuited");
		this.setContrib("triage", score, reason);
	}

	completeVerdict(score: number): void {
		const cur = this.records.get("verdict");
		if (!cur) return;
		this.records.set("verdict", {
			...cur,
			status: "ok",
			score_contrib: score,
			// duration_ms already set by `measureAsync` for the full path;
			// short-circuit path never measured the verdict stage so leave
			// it at 0.
		});
	}

	snapshot(): StageRecord[] {
		const order: StageId[] = [
			"auth", "url", "reputation", "intel", "triage", "llm", "verdict",
		];
		return order.map((id) => this.records.get(id)!);
	}
}

/**
 * Persist verdict + URL rows + sender reputation update. Best-effort: each
 * step catches its own errors so a single failure doesn't lose the verdict
 * for the caller.
 */
async function persistAll(
	env: Env,
	mailboxId: string,
	messageId: string,
	sender: string,
	senderName: string,
	verdict: FinalVerdict,
	urls: ReturnType<typeof extractUrls>,
	stageTrace: StageRecord[],
) {
	const stub = getMailboxStub(env, mailboxId);
	try {
		await stub.persistSecurityVerdict(messageId, {
			verdict_json: JSON.stringify(verdict),
			score: verdict.score,
			explanation: verdict.explanation,
			stage_trace_json: JSON.stringify(stageTrace),
		});
	} catch (e) {
		console.error("persistSecurityVerdict failed:", (e as Error).message);
	}

	if (urls.length > 0) {
		try {
			await stub.insertUrls(
				messageId,
				urls.map((u) => ({
					url: u.url,
					display_text: u.display_text ?? null,
					is_homograph: u.is_homograph ? 1 : 0,
					is_shortener: u.is_shortener ? 1 : 0,
				})),
			);
		} catch (e) {
			console.error("insertUrls failed:", (e as Error).message);
		}
	}

	if (sender) {
		try {
			await stub.upsertSenderReputation(sender, verdict.score);
		} catch (e) {
			console.error("upsertSenderReputation failed:", (e as Error).message);
		}
	}

	if (senderName && sender) {
		try {
			await stub.upsertSenderGraph(senderName, sender);
		} catch (e) {
			console.error("upsertSenderGraph failed:", (e as Error).message);
		}
	}
}

export type { FinalVerdict } from "./verdict";
export type { AuthVerdict } from "./auth";
export type { ClassificationResult } from "./classification";
