// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * End-to-end harness for `runSecurityPipeline`. Each `.eml` fixture is parsed
 * with PostalMime (the same parser the production receiver uses) and then fed
 * through the pipeline against in-memory fakes for MAILBOX/BUCKET. The LLM
 * classifier is stubbed via the `__setClassifier` seam so the suite has no
 * network dependencies.
 *
 * What these tests DON'T cover:
 *   - Real Workers AI behaviour (deferred to staging).
 *   - Intel-feed bloom lookups (BLOOM_KV binding is intentionally absent; the
 *     feeds module early-returns null without it).
 *   - Deep-scan enqueueing (the sync pipeline doesn't touch the queue).
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import PostalMime, { type Email } from "postal-mime";

import { runSecurityPipeline } from "../../workers/security/index";
import { __setClassifier } from "../../workers/security/classification";
import type { ClassificationResult } from "../../workers/security/classification";
import { isDmarcReport } from "../../workers/dmarc/ingest";
import { createFakeMailboxStub, makeFakeEnv } from "./fakes";
import type { MailboxSecuritySettings } from "../../workers/security/settings";

const FIXTURE_DIR = join(__dirname, "..", "fixtures", "security");
const MAILBOX = "test@example.com";

async function loadFixture(name: string): Promise<Email> {
	const raw = await readFile(join(FIXTURE_DIR, name), "utf8");
	return new PostalMime().parse(raw);
}

function stub(result: Partial<ClassificationResult>): ClassificationResult {
	return {
		label: result.label ?? "safe",
		confidence: result.confidence ?? 0.9,
		reasoning: result.reasoning ?? "stubbed",
	};
}

function settings(
	overrides: Partial<MailboxSecuritySettings> = {},
): Partial<MailboxSecuritySettings> {
	return { enabled: true, ...overrides };
}

afterEach(() => {
	__setClassifier(null);
});

describe("runSecurityPipeline — fixture verdicts", () => {
	it("benign-newsletter: allow, score < 30", async () => {
		__setClassifier(async () => stub({ label: "safe", confidence: 0.95 }));
		const { stub: mailbox } = createFakeMailboxStub();
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub: mailbox, settings: settings() });
		const parsed = await loadFixture("benign-newsletter.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-newsletter", targetFolder: "inbox", parsedEmail: parsed,
		});
		expect(result.skipped).toBe(false);
		expect(result.verdict?.action).toBe("allow");
		expect(result.verdict?.score ?? 0).toBeLessThan(30);
	});

	it("dmarc-fail-phish: tag or stricter, score ≥ 30", async () => {
		__setClassifier(async () => stub({ label: "phishing", confidence: 0.9 }));
		const { stub: mailbox } = createFakeMailboxStub();
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub: mailbox, settings: settings() });
		const parsed = await loadFixture("dmarc-fail-phish.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-phish", targetFolder: "inbox", parsedEmail: parsed,
		});
		expect(result.verdict?.score ?? 0).toBeGreaterThanOrEqual(30);
		expect(["tag", "quarantine", "block"]).toContain(result.verdict?.action);
		expect(result.verdict?.signals.join(" ")).toMatch(/DMARC failed/);
	});

	it("homograph-url: Cyrillic hostname detected, tag or stricter", async () => {
		// A suspicious classification is the realistic outcome — the LLM sees
		// a login-confirmation message from an unfamiliar sender. This is what
		// tips the score over the tag threshold together with the homograph URL.
		__setClassifier(async () => stub({ label: "suspicious", confidence: 0.7 }));
		const { stub: mailbox } = createFakeMailboxStub();
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub: mailbox, settings: settings() });
		const parsed = await loadFixture("homograph-url.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-homograph", targetFolder: "inbox", parsedEmail: parsed,
		});
		expect(result.verdict?.score ?? 0).toBeGreaterThanOrEqual(30);
		expect(["tag", "quarantine", "block"]).toContain(result.verdict?.action);
		expect(result.verdict?.signals.join(" ")).toMatch(/homograph/i);
	});

	it("shortener: bit.ly contributes to signals (+5)", async () => {
		__setClassifier(async () => stub({ label: "safe", confidence: 0.9 }));
		const { stub: mailbox } = createFakeMailboxStub();
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub: mailbox, settings: settings() });
		const parsed = await loadFixture("shortener.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-shortener", targetFolder: "inbox", parsedEmail: parsed,
		});
		expect(result.verdict?.signals.join(" ")).toMatch(/link shortener \(bit\.ly\)/);
	});

	it("first-time-sender: 'first-time sender' signal recorded", async () => {
		// Current scoring only adds +5 for first-time senders, which sits below
		// the default tag threshold (30). We assert on the signal rather than
		// the action so this test stays stable if thresholds ever move.
		__setClassifier(async () => stub({ label: "safe", confidence: 0.85 }));
		const { stub: mailbox } = createFakeMailboxStub();
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub: mailbox, settings: settings() });
		const parsed = await loadFixture("first-time-sender.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-firsttime", targetFolder: "inbox", parsedEmail: parsed,
		});
		expect(result.verdict?.signals.join(" ")).toMatch(/first-time sender/);
	});

	it("prompt-injection: pipeline completes (classifier-side guard lives in agent)", async () => {
		// `isPromptInjection` is an agent-side guard, not part of the security
		// pipeline. This test only verifies the pipeline produces a verdict
		// without throwing on the injected content.
		__setClassifier(async () => stub({ label: "suspicious", confidence: 0.6 }));
		const { stub: mailbox } = createFakeMailboxStub();
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub: mailbox, settings: settings() });
		const parsed = await loadFixture("prompt-injection.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-pi", targetFolder: "inbox", parsedEmail: parsed,
		});
		expect(result.skipped).toBe(false);
		expect(result.verdict).not.toBeNull();
	});
});

describe("triage short-circuits", () => {
	it("hard_block: flagged sender never touches the classifier", async () => {
		// Classifier throws — if the pipeline reaches it we'll surface a failure.
		__setClassifier(async () => { throw new Error("classifier must not be called"); });
		const { stub: mailbox, reputation } = createFakeMailboxStub();
		const sender = "newsletter@acme-example.com";
		reputation.set(sender, {
			sender,
			first_seen: "2026-01-01T00:00:00Z",
			last_seen: "2026-04-01T00:00:00Z",
			message_count: 20,
			avg_score: 5,
			flagged: true,
		});
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub: mailbox, settings: settings() });
		const parsed = await loadFixture("benign-newsletter.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-block", targetFolder: "inbox", parsedEmail: parsed,
		});
		expect(result.verdict?.triage).toBe("hard_block");
		expect(result.verdict?.action).toBe("quarantine");
		expect(result.verdict?.signals.join(" ")).toMatch(/flagged/);
	});

	it("hard_allow: allowlisted DMARC-pass sender never touches the classifier", async () => {
		__setClassifier(async () => { throw new Error("classifier must not be called"); });
		const { stub: mailbox } = createFakeMailboxStub();
		const env = makeFakeEnv({
			mailboxId: MAILBOX,
			stub: mailbox,
			settings: settings({
				allowlist_senders: ["newsletter@acme-example.com"],
				trusted_auto_allow: true,
				// Hard-allow requires a DMARC pass from a TRUSTED authserv-id
				// (F-004). The benign-newsletter fixture's Authentication-Results
				// authserv-id is mx.example.com; trust it so the verdict is marked
				// trusted and the short-circuit fires.
				trusted_authserv_ids: ["mx.example.com"],
			}),
		});
		const parsed = await loadFixture("benign-newsletter.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-allow", targetFolder: "inbox", parsedEmail: parsed,
		});
		expect(result.verdict?.triage).toBe("hard_allow");
		expect(result.verdict?.action).toBe("allow");
		expect(result.verdict?.signals.join(" ")).toMatch(/allowlist/);
	});

	it("hard_allow requires DMARC pass — allowlist alone is insufficient", async () => {
		// The DMARC-fail fixture uses paypal.com as the From. Even if we
		// allowlist it, the hard-allow invariant requires DMARC pass, so the
		// pipeline must fall through to the full scoring path.
		let called = false;
		__setClassifier(async () => { called = true; return stub({ label: "phishing", confidence: 0.9 }); });
		const { stub: mailbox } = createFakeMailboxStub();
		const env = makeFakeEnv({
			mailboxId: MAILBOX,
			stub: mailbox,
			settings: settings({
				allowlist_senders: ["service@paypal.com"],
				allowlist_domains: ["paypal.com"],
				trusted_auto_allow: true,
			}),
		});
		const parsed = await loadFixture("dmarc-fail-phish.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-bypass", targetFolder: "inbox", parsedEmail: parsed,
		});
		expect(called).toBe(true);
		expect(result.verdict?.triage).not.toBe("hard_allow");
	});

	it("persistence: verdict + urls + reputation are written on the full path", async () => {
		__setClassifier(async () => stub({ label: "safe", confidence: 0.9 }));
		const { stub: mailbox, verdicts, urls, reputation } = createFakeMailboxStub();
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub: mailbox, settings: settings() });
		const parsed = await loadFixture("shortener.eml");
		await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-persist", targetFolder: "inbox", parsedEmail: parsed,
		});
		expect(verdicts.has("m-persist")).toBe(true);
		expect(urls.get("m-persist")?.some((u) => u.url.includes("bit.ly"))).toBe(true);
		expect(reputation.has("jordan@friendly-sender.example")).toBe(true);
	});
});

describe("folder-bypass triage (sibling work)", () => {
	it("skip_all on INBOX returns a synthetic allow verdict tagged folder_bypass", async () => {
		__setClassifier(async () => { throw new Error("classifier must not be called"); });
		const { stub: mailbox } = createFakeMailboxStub();
		const env = makeFakeEnv({
			mailboxId: MAILBOX,
			stub: mailbox,
			settings: settings({
				folder_policies: { inbox: { mode: "skip_all" } },
			}),
		});
		const parsed = await loadFixture("benign-newsletter.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-skip", targetFolder: "inbox", parsedEmail: parsed,
		});
		expect(result.verdict?.triage).toBe("folder_bypass");
		expect(result.verdict?.action).toBe("allow");
	});

	it("skip_classifier runs triage + scoring but not the LLM", async () => {
		__setClassifier(async () => { throw new Error("classifier must not be called"); });
		const { stub: mailbox } = createFakeMailboxStub();
		const env = makeFakeEnv({
			mailboxId: MAILBOX,
			stub: mailbox,
			settings: settings({
				folder_policies: { inbox: { mode: "skip_classifier" } },
			}),
		});
		const parsed = await loadFixture("benign-newsletter.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-skipcls", targetFolder: "inbox", parsedEmail: parsed,
		});
		// A synthetic "safe" is substituted for the classification, so the
		// aggregated action comes from the remaining signals (all favourable).
		expect(result.verdict?.action).toBe("allow");
	});
});

describe("LLM timeout — narrowed Rule 5 (issue #28)", () => {
	it("clean email + classifier timeout → reaches allow (acceptance criterion)", async () => {
		// Headline acceptance from the issue: with the LLM artificially failing
		// (timeout), a clean inbound scored well by SPF/DKIM/DMARC + URL +
		// reputation reaches `allow` and is delivered normally. The benign
		// newsletter fixture passes DMARC; without the LLM contribution the
		// verdict floor is dominated by other signals (no homograph, no
		// shortener, etc.) and lands well below the tag threshold.
		__setClassifier(async () => {
			throw new Error("classify-timeout");
		});
		const { stub: mailbox } = createFakeMailboxStub();
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub: mailbox, settings: settings() });
		const parsed = await loadFixture("benign-newsletter.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-llm-timeout", targetFolder: "inbox", parsedEmail: parsed,
		});
		expect(result.skipped).toBe(false);
		expect(result.verdict?.action).toBe("allow");
		// The `llm_unavailable` tag should be visible in the signals so an
		// operator can tell the verdict was assembled without the classifier.
		expect(result.verdict?.signals).toContain("llm_unavailable");
	});

	it("legacy mode (skip_on_timeout=false) → timeout reverts to fail-closed suspicious", async () => {
		// Backward-compat for operators who explicitly want the old behavior.
		__setClassifier(async () => {
			throw new Error("classify-timeout");
		});
		const { stub: mailbox } = createFakeMailboxStub();
		const env = makeFakeEnv({
			mailboxId: MAILBOX,
			stub: mailbox,
			settings: settings({
				classification: { skip_on_timeout: false },
			}),
		});
		const parsed = await loadFixture("benign-newsletter.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-legacy", targetFolder: "inbox", parsedEmail: parsed,
		});
		// With the old fail-closed behavior, the classifier contributes at the
		// `suspicious` weight; combined with a clean email's other signals
		// (≈0), 30*(0.5+0.5*0.3)≈10 sits below the tag threshold but the
		// classifier label itself must read `suspicious`, not `unavailable`.
		expect(result.verdict?.classification.label).toBe("suspicious");
		expect(result.verdict?.signals).not.toContain("llm_unavailable");
	});

	it("downstream-tightens invariant: real LLM 'suspicious' verdict still contributes (not relaxed)", async () => {
		// Critical invariant: the new path must not relax a real `suspicious`
		// verdict. If the classifier actually returned `suspicious` (for
		// real reasons, not a timeout), the score contribution must persist.
		__setClassifier(async () => stub({ label: "suspicious", confidence: 0.9 }));
		const { stub: mailbox } = createFakeMailboxStub();
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub: mailbox, settings: settings() });
		const parsed = await loadFixture("benign-newsletter.eml");
		const result = await runSecurityPipeline({
			env, mailboxId: MAILBOX, messageId: "m-real-suspicious", targetFolder: "inbox", parsedEmail: parsed,
		});
		expect(result.verdict?.classification.label).toBe("suspicious");
		expect(result.verdict?.signals.join(" ")).toMatch(/classifier: suspicious/);
		expect(result.verdict?.signals).not.toContain("llm_unavailable");
	});
});

// These sibling extensions reference scoring signals that exist in the
// codebase but need dedicated coverage. Kept as `.todo` placeholders until
// someone writes the end-to-end fixtures.
describe.todo("off-hours boost (business_hours + time-rules)");
describe.todo("attachment_block on executable MIME type");

describe("DMARC report detector", () => {
	it("isDmarcReport returns true for a google.com aggregate report", async () => {
		const parsed = await loadFixture("dmarc-report.eml");
		expect(isDmarcReport(parsed)).toBe(true);
	});

	it("isDmarcReport returns false for an ordinary newsletter", async () => {
		const parsed = await loadFixture("benign-newsletter.eml");
		expect(isDmarcReport(parsed)).toBe(false);
	});
});
