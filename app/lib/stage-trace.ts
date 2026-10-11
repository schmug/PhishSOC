// Per-stage pipeline trace (issue #128). One record per pipeline stage in
// fixed order, written by workers/security/stage-trace.ts to
// `emails.stage_trace` and copied to `cases.stage_trace`. The case endpoint
// returns it parsed; the email endpoints return the raw JSON string.
export type StageId =
	| "auth"
	| "url"
	| "reputation"
	| "intel"
	| "triage"
	| "llm"
	| "verdict";
export type StageStatus = "ok" | "skipped" | "failed" | "short_circuited";
export interface StageRecord {
	stage: StageId;
	status: StageStatus;
	score_contrib: number;
	duration_ms: number;
	reason?: string;
}

export const STAGE_LABELS: Record<StageId, string> = {
	auth: "Authentication",
	url: "URL extraction",
	reputation: "Sender reputation",
	intel: "Threat intel",
	triage: "Triage",
	llm: "Classifier (LLM)",
	verdict: "Verdict",
};

/** Parse the raw `emails.stage_trace` JSON. Returns null for missing,
 * malformed, or empty traces so callers can hide the trace entirely. */
export function parseStageTrace(raw: string | null | undefined): StageRecord[] | null {
	if (!raw) return null;
	try {
		const parsed: unknown = JSON.parse(raw);
		if (!Array.isArray(parsed) || parsed.length === 0) return null;
		const valid = parsed.every(
			(r) =>
				r !== null &&
				typeof r === "object" &&
				typeof (r as StageRecord).stage === "string" &&
				typeof (r as StageRecord).score_contrib === "number",
		);
		return valid ? (parsed as StageRecord[]) : null;
	} catch {
		return null;
	}
}
