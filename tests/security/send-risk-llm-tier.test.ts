// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Outbound LLM verdict → send-risk tier (slice 3). `classifySend` stays pure:
 * the verdict arrives precomputed in `context.llm`, and it can only raise the
 * tier the deterministic rules chose — never lower it or drop a reason.
 */

import { describe, expect, it } from "vitest";
import { classifySend, type ClassifySendInput, type SendRiskContext } from "../../workers/security/send-risk";

const INTERNAL = "colleague@internal.example";
const EXTERNAL = "vendor@acme.example";

function make(to: string, llm: SendRiskContext["llm"], overrides: Partial<ClassifySendInput> = {}): ClassifySendInput {
	return {
		to,
		mailboxId: "operator@internal.example",
		subject: "Hello",
		body: "See you tomorrow.",
		...overrides,
		context: { llm },
	};
}

describe("label → tier", () => {
	it.each([
		["safe", INTERNAL, 0],
		["safe", EXTERNAL, 1],
		["victim_response", INTERNAL, 2],
		["victim_response", EXTERNAL, 2],
		["malicious_outbound", INTERNAL, 2],
		["malicious_outbound", EXTERNAL, 2],
		["data_exposure", INTERNAL, 1],
		["data_exposure", EXTERNAL, 2],
		["suspicious", INTERNAL, 1],
		["suspicious", EXTERNAL, 1],
	] as const)("%s to %s → tier %i", (label, to, tier) => {
		expect(classifySend(make(to, { label, confidence: 0.87 })).tier).toBe(tier);
	});

	it("names the label and confidence in the reasons", () => {
		const risk = classifySend(make(INTERNAL, { label: "victim_response", confidence: 0.87 }));
		expect(risk.reasons).toContain("AI classifier: victim_response (0.87)");
	});

	it("adds no reason for safe", () => {
		expect(classifySend(make(INTERNAL, { label: "safe", confidence: 0.99 })).reasons).toEqual([]);
	});
});

describe("fail modes", () => {
	it("timeout records llm_unavailable and adds no tier", () => {
		const risk = classifySend(make(INTERNAL, { label: "unavailable", confidence: 0 }));
		expect(risk).toEqual({ tier: 0, reasons: ["llm_unavailable"] });
	});

	it("error fails closed to tier 1", () => {
		const risk = classifySend(make(INTERNAL, { label: "error", confidence: 0 }));
		expect(risk.tier).toBe(1);
		expect(risk.reasons).toContain("llm_error: classifier failed, treated as suspicious");
	});
});

describe("raise-only", () => {
	it("safe never lowers a deterministic tier 2 or removes its reason", () => {
		const input = make(EXTERNAL, { label: "safe", confidence: 1 }, { body: "Please send the wire transfer today." });
		const withLlm = classifySend(input);
		const without = classifySend({ ...input, context: {} });
		expect(without.tier).toBe(2);
		expect(withLlm).toEqual(without);
	});

	it("keeps every deterministic reason when the LLM raises", () => {
		const input = make(EXTERNAL, { label: "malicious_outbound", confidence: 0.9 });
		const without = classifySend({ ...input, context: {} });
		const withLlm = classifySend(input);
		expect(withLlm.reasons).toEqual(expect.arrayContaining(without.reasons));
		expect(withLlm.tier).toBe(2);
	});

	it("absent verdict (classifier disabled) changes nothing", () => {
		const input = make(INTERNAL, undefined);
		expect(classifySend(input)).toEqual({ tier: 0, reasons: [] });
	});

	it("the agent bump still applies after the LLM result", () => {
		const risk = classifySend(make(INTERNAL, { label: "suspicious", confidence: 0.6 }, { createdBy: "agent" }));
		expect(risk.tier).toBe(2);
		expect(risk.reasons).toEqual(["AI classifier: suspicious (0.60)", "Agent-authored draft"]);
	});
});
