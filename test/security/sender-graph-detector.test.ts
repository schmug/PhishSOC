// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, it, expect, afterEach } from "vitest";
import { SenderGraphDetector } from "../../workers/security/detectors";
import { runSecurityPipeline } from "../../workers/security/index";
import { __setClassifier } from "../../workers/security/classification";
import { createFakeMailboxStub, makeFakeEnv } from "./fakes";

afterEach(() => {
	__setClassifier(null);
});

// ── SenderGraphDetector unit tests ────────────────────────────────────────────

describe("SenderGraphDetector.score", () => {
	it("returns 0 for empty sender name", async () => {
		const det = new SenderGraphDetector();
		const result = await det.score(
			{ senderAddress: "attacker@evil.com", senderName: "" },
			{ async getSenderGraphByName() { return []; } },
		);
		expect(result.score).toBe(0);
	});

	it("returns 0 when display name has no history (fresh mailbox)", async () => {
		const det = new SenderGraphDetector();
		const result = await det.score(
			{ senderAddress: "attacker@evil.com", senderName: "john smith" },
			{ async getSenderGraphByName() { return []; } },
		);
		expect(result.score).toBe(0);
	});

	it("returns 0 when sender address is already known for this display name", async () => {
		const det = new SenderGraphDetector();
		const result = await det.score(
			{ senderAddress: "boss@company.com", senderName: "john smith" },
			{
				async getSenderGraphByName(name) {
					if (name === "john smith") return [{ sender_address: "boss@company.com", message_count: 5 }];
					return [];
				},
			},
		);
		expect(result.score).toBe(0);
	});

	it("BEC hit: new address claiming a known display name scores > 0 and ≤ 30", async () => {
		const det = new SenderGraphDetector();
		const result = await det.score(
			{ senderAddress: "attacker@gmail.com", senderName: "john smith" },
			{
				async getSenderGraphByName(name) {
					if (name === "john smith") return [{ sender_address: "boss@company.com", message_count: 5 }];
					return [];
				},
			},
		);
		expect(result.score).toBeGreaterThan(0);
		expect(result.score).toBeLessThanOrEqual(30);
		expect(result.reason).toBeTruthy();
	});

	it("score is 10 for 1 prior message (low confidence)", async () => {
		const det = new SenderGraphDetector();
		const result = await det.score(
			{ senderAddress: "attacker@gmail.com", senderName: "alice" },
			{ async getSenderGraphByName() { return [{ sender_address: "alice@real.com", message_count: 1 }]; } },
		);
		expect(result.score).toBe(10);
	});

	it("score is 15 for 2–4 prior messages", async () => {
		const det = new SenderGraphDetector();
		const result = await det.score(
			{ senderAddress: "attacker@gmail.com", senderName: "alice" },
			{ async getSenderGraphByName() { return [{ sender_address: "alice@real.com", message_count: 3 }]; } },
		);
		expect(result.score).toBe(15);
	});

	it("score is 25 for ≥5 prior messages (high confidence)", async () => {
		const det = new SenderGraphDetector();
		const result = await det.score(
			{ senderAddress: "attacker@gmail.com", senderName: "alice" },
			{ async getSenderGraphByName() { return [{ sender_address: "alice@real.com", message_count: 10 }]; } },
		);
		expect(result.score).toBe(25);
	});

	it("history aggregates across multiple known addresses", async () => {
		const det = new SenderGraphDetector();
		const result = await det.score(
			{ senderAddress: "new@attacker.com", senderName: "bob" },
			{
				async getSenderGraphByName() {
					return [
						{ sender_address: "bob@work.com", message_count: 2 },
						{ sender_address: "bob@personal.com", message_count: 2 },
					];
				},
			},
		);
		// totalHistory=4 → score 15; result.reason mentions 2 known addresses
		expect(result.score).toBe(15);
		expect(result.reason).toMatch(/2 known address/);
	});
});

// ── Pipeline integration tests ────────────────────────────────────────────────

const MAILBOX = "test@example.com";

function safeClassifier() {
	return { label: "safe" as const, confidence: 0.9, reasoning: "stubbed" };
}

/** Build a minimal parsed email with the given from field. */
function makeEmail(from: { address: string; name: string }) {
	return {
		subject: "Urgent: wire transfer needed",
		from,
		html: "<p>Please approve the transfer.</p>",
		headers: {},
		attachments: [],
	};
}

describe("runSecurityPipeline — sender graph integration", () => {
	it("fresh mailbox: BEC impersonation email does not trigger detector (no history)", async () => {
		__setClassifier(async () => safeClassifier());
		const { stub } = createFakeMailboxStub();
		const env = makeFakeEnv({
			mailboxId: MAILBOX,
			stub,
			settings: { enabled: true, detectors: { sender_graph: { enabled: true } } },
		});

		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-bec-fresh",
			targetFolder: "inbox",
			parsedEmail: makeEmail({ address: "attacker@evil.com", name: "John Smith" }),
		});

		// No sender graph history → detector contributes 0
		expect(result.verdict?.signals.join(" ")).not.toMatch(/BEC signal/i);
	});

	it("mailbox with history: impersonating known sender triggers detector", async () => {
		__setClassifier(async () => safeClassifier());
		const { stub, senderGraph } = createFakeMailboxStub();
		// Seed 5 prior messages from the real "John Smith" address
		senderGraph.set("john smith", [
			{ sender_address: "jsmith@company.com", message_count: 5 },
		]);

		const env = makeFakeEnv({
			mailboxId: MAILBOX,
			stub,
			settings: { enabled: true, detectors: { sender_graph: { enabled: true } } },
		});

		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-bec-known",
			targetFolder: "inbox",
			parsedEmail: makeEmail({ address: "attacker@evil.com", name: "John Smith" }),
		});

		expect(result.verdict?.signals.join(" ")).toMatch(/BEC signal/i);
		expect(result.verdict?.score ?? 0).toBeGreaterThan(0);
	});

	it("known sender emailing again does not trigger detector", async () => {
		__setClassifier(async () => safeClassifier());
		const { stub, senderGraph } = createFakeMailboxStub();
		senderGraph.set("john smith", [
			{ sender_address: "jsmith@company.com", message_count: 5 },
		]);

		const env = makeFakeEnv({
			mailboxId: MAILBOX,
			stub,
			settings: { enabled: true, detectors: { sender_graph: { enabled: true } } },
		});

		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-bec-legit",
			targetFolder: "inbox",
			parsedEmail: makeEmail({ address: "jsmith@company.com", name: "John Smith" }),
		});

		expect(result.verdict?.signals.join(" ")).not.toMatch(/BEC signal/i);
	});

	it("detector disabled: impersonation email does not add BEC signal", async () => {
		__setClassifier(async () => safeClassifier());
		const { stub, senderGraph } = createFakeMailboxStub();
		senderGraph.set("john smith", [
			{ sender_address: "jsmith@company.com", message_count: 10 },
		]);

		const env = makeFakeEnv({
			mailboxId: MAILBOX,
			stub,
			settings: { enabled: true, detectors: { sender_graph: { enabled: false } } },
		});

		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-bec-disabled",
			targetFolder: "inbox",
			parsedEmail: makeEmail({ address: "attacker@evil.com", name: "John Smith" }),
		});

		expect(result.verdict?.signals.join(" ")).not.toMatch(/BEC signal/i);
	});

	it("upsertSenderGraph is called after pipeline run (sender graph is updated)", async () => {
		__setClassifier(async () => safeClassifier());
		const { stub, senderGraph } = createFakeMailboxStub();

		const env = makeFakeEnv({
			mailboxId: MAILBOX,
			stub,
			settings: { enabled: true },
		});

		await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-graph-update",
			targetFolder: "inbox",
			parsedEmail: makeEmail({ address: "boss@company.com", name: "Alice Boss" }),
		});

		const records = senderGraph.get("alice boss") ?? [];
		expect(records.some((r) => r.sender_address === "boss@company.com")).toBe(true);
	});
});
