// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Coverage for `RunPipelineInput.stateless` (issue #32, Task 9). The
 * gateway-passthrough path scores mail for recipients with no registered
 * mailbox; `stateless: true` must guarantee the pipeline never touches the
 * MailboxDO — no DKIM-observation write, reputation stays `null`, the
 * sender-graph detector is skipped, and `persistAll` never runs. Default
 * (absent/false) behavior must stay byte-for-byte identical to
 * `run-pipeline.test.ts`, which this suite runs alongside as a regression
 * guard.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import PostalMime, { type Email } from "postal-mime";

import { runSecurityPipeline } from "../../workers/security/index";
import { __setClassifier } from "../../workers/security/classification";
import { createFakeMailboxStub, makeFakeEnv } from "./fakes";
import type { FakeMailboxStub } from "./fakes";
import type { MailboxSecuritySettings } from "../../workers/security/settings";

const MAILBOX = "nobody@example.com";
const FIXTURE_DIR = join(__dirname, "..", "fixtures", "security");

async function loadFixture(name: string): Promise<Email> {
	const raw = await readFile(join(FIXTURE_DIR, name), "utf8");
	return new PostalMime().parse(raw);
}

function settings(
	overrides: Partial<MailboxSecuritySettings> = {},
): Partial<MailboxSecuritySettings> {
	return { enabled: true, ...overrides };
}

/** Wrap a fake stub so every method invocation is recorded by name. */
function recordingStub(inner: FakeMailboxStub): { stub: FakeMailboxStub; calls: string[] } {
	const calls: string[] = [];
	const stub = new Proxy(inner, {
		get(target, prop, receiver) {
			const value = Reflect.get(target, prop, receiver);
			if (typeof value !== "function") return value;
			return (...args: unknown[]) => {
				calls.push(String(prop));
				return (value as (...a: unknown[]) => unknown).apply(target, args);
			};
		},
	});
	return { stub, calls };
}

function parsedEmail() {
	return {
		subject: "hello",
		from: { address: "sender@origin.test", name: "Sender Name" },
		text: "plain body",
		headers: [],
	};
}

afterEach(() => {
	__setClassifier(null);
});

describe("runSecurityPipeline stateless mode", () => {
	it("produces a verdict without touching the MailboxDO", async () => {
		__setClassifier(async () => ({ label: "safe", confidence: 0.9, reasoning: "stubbed" }));
		const { stub: innerStub } = createFakeMailboxStub();
		const { stub, calls } = recordingStub(innerStub);
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub, settings: { enabled: true } });

		const result = await runSecurityPipeline({
			env,
			mailboxId: MAILBOX,
			messageId: "m1",
			targetFolder: "inbox",
			stateless: true,
			parsedEmail: parsedEmail(),
		});

		expect(result.skipped).toBe(false);
		expect(result.verdict).not.toBeNull();
		expect(result.verdict?.triage).toBeUndefined();
		expect(calls).toEqual([]); // no DO method was invoked
	});

	it("stateless verdict does not include a sender-graph detector boost", async () => {
		// Guards against a silent fallback where the detector still runs and
		// reads/writes the DO despite `stateless: true`.
		__setClassifier(async () => ({ label: "safe", confidence: 0.9, reasoning: "stubbed" }));
		const { stub: innerStub } = createFakeMailboxStub();
		const { stub, calls } = recordingStub(innerStub);
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub, settings: { enabled: true } });

		await runSecurityPipeline({
			env,
			mailboxId: MAILBOX,
			messageId: "m2",
			targetFolder: "inbox",
			stateless: true,
			parsedEmail: parsedEmail(),
		});

		expect(calls).not.toContain("getSenderGraphByName");
		expect(calls).not.toContain("upsertSenderGraph");
	});

	it("stateful default still persists (regression guard)", async () => {
		__setClassifier(async () => ({ label: "safe", confidence: 0.9, reasoning: "stubbed" }));
		const { stub: innerStub } = createFakeMailboxStub();
		const { stub, calls } = recordingStub(innerStub);
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub, settings: { enabled: true } });

		await runSecurityPipeline({
			env,
			mailboxId: MAILBOX,
			messageId: "m3",
			targetFolder: "inbox",
			parsedEmail: parsedEmail(),
		});

		expect(calls).toContain("persistSecurityVerdict");
	});

	it("stateful default (stateless: false) still persists (regression guard)", async () => {
		__setClassifier(async () => ({ label: "safe", confidence: 0.9, reasoning: "stubbed" }));
		const { stub: innerStub } = createFakeMailboxStub();
		const { stub, calls } = recordingStub(innerStub);
		const env = makeFakeEnv({ mailboxId: MAILBOX, stub, settings: { enabled: true } });

		await runSecurityPipeline({
			env,
			mailboxId: MAILBOX,
			messageId: "m4",
			targetFolder: "inbox",
			stateless: false,
			parsedEmail: parsedEmail(),
		});

		expect(calls).toContain("persistSecurityVerdict");
	});

	it("stateless mode still short-circuits triage without touching the DO", async () => {
		// hard_allow short-circuit persists via a separate `persistAll` call
		// site (line 259) distinct from the full-path call (line 353) — both
		// must be guarded, so exercise the short-circuit branch explicitly.
		// evaluateHardAllow (triage.ts:189-198) requires DMARC pass AND trusted
		// authserv-id, so mirror the fixture + settings from run-pipeline.test.ts
		// "hard_allow: allowlisted DMARC-pass sender" test.
		__setClassifier(async () => {
			throw new Error("classifier must not be called");
		});
		const { stub: innerStub } = createFakeMailboxStub();
		const { stub, calls } = recordingStub(innerStub);
		const env = makeFakeEnv({
			mailboxId: MAILBOX,
			stub,
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
			env,
			mailboxId: MAILBOX,
			messageId: "m5",
			targetFolder: "inbox",
			stateless: true,
			parsedEmail: parsed,
		});

		expect(result.verdict?.triage).toBe("hard_allow");
		expect(calls).toEqual([]);
	});
});
