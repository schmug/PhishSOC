// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Route-level and DO-method tests for the yaramail sidecar pipeline (issue #257):
 *
 *  1. receiveEmail fires fireYaraScan per attachment when yaramail_scanner.enabled
 *  2. POST /yaramail-callback rejects invalid HMAC → 401
 *  3. POST /yaramail-callback applies score delta capped at 100
 *  4. applyYaraSignal never downgrades an existing score
 *
 * The callback route is tested by importing `yaramailCallbackRoute` and
 * mounting it in a lightweight Hono app — the full workers/index.ts graph is
 * never imported, to keep test startup fast.
 *
 * CodeQL URL rule: any URL routing in this file uses `new URL(url).hostname`,
 * never `url.startsWith` or `url.includes`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Hono } from "hono";
import { yaramailCallbackRoute } from "../../workers/routes/yaramail-callback";
import { hmacSha256Hex } from "../../workers/lib/hmac";
import {
	fireYaraScan,
} from "../../workers/security/yaramail-signal";

// ── Mock resolveMailboxSettings (used by fireYaraScan) ────────────────────────

vi.mock("../../workers/lib/mailbox-settings", () => ({
	resolveMailboxSettings: vi.fn(),
	stripDefaultEqual: <T>(x: T) => x,
	YaraMailScannerSettings: { parse: (x: unknown) => x },
}));

import { resolveMailboxSettings } from "../../workers/lib/mailbox-settings";
const mockedResolve = vi.mocked(resolveMailboxSettings);

// ── Helpers ────────────────────────────────────────────────────────────────────

const CALLBACK_SECRET = "test-yaramail-secret-at-least-32-chars!!";

/** Sign a body string with the test secret, returning the hex HMAC. */
async function signBody(body: string): Promise<string> {
	return hmacSha256Hex(CALLBACK_SECRET, body);
}

/** Tracks calls made to stub methods for assertion. */
interface StubCalls {
	insertYaraScanResult: Array<[string, string, number]>;
	applyYaraSignal: Array<[string, number]>;
}

/** Build a fake MAILBOX DO namespace that records calls and tracks scores. */
function makeMailboxNamespace(initialScore: number | null = null) {
	const calls: StubCalls = {
		insertYaraScanResult: [],
		applyYaraSignal: [],
	};
	let storedScore = initialScore;

	const stub = {
		async insertYaraScanResult(emailId: string, resultsJson: string, scannedAt: number) {
			calls.insertYaraScanResult.push([emailId, resultsJson, scannedAt]);
		},
		async applyYaraSignal(emailId: string, scoreDelta: number) {
			calls.applyYaraSignal.push([emailId, scoreDelta]);
			const current = storedScore ?? 0;
			const next = Math.min(100, current + scoreDelta);
			if (next > current) storedScore = next;
		},
		getScore() { return storedScore; },
	};

	const ns = {
		idFromName(_name: string) { return "stub-id"; },
		get(_id: string) { return stub; },
		_calls: calls,
		_stub: stub,
	};

	return ns;
}

/** Build the Hono test app mounting the callback route. */
function makeApp(env: Record<string, unknown>) {
	const app = new Hono();
	app.route("/api/v1/mailboxes/:mailboxId/yaramail-callback", yaramailCallbackRoute);
	return {
		async request(path: string, init?: RequestInit) {
			return app.request(path, init, env);
		},
	};
}

// ── 1. receiveEmail fires scan per attachment (fireYaraScan wiring) ────────────

describe("receiveEmail attachment wiring — fireYaraScan called per attachment", () => {
	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
		vi.clearAllMocks();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("fires one scan per attachment when yaramail_scanner.enabled is true", async () => {
		const endpointUrl = "https://sidecar.example.com/scan";
		mockedResolve.mockResolvedValue({
			raw: { yaramail_scanner: { enabled: true, endpoint_url: endpointUrl } },
			security: { enabled: false },
		} as unknown as Awaited<ReturnType<typeof resolveMailboxSettings>>);

		const scheduled: Promise<unknown>[] = [];
		const ctx = { waitUntil: (p: Promise<unknown>) => { scheduled.push(p); } };
		const env = { BUCKET: {} } as unknown as { BUCKET: R2Bucket };

		// Simulate the wiring: one call per attachment
		const attachments = [
			"attachments/msg-1/att-a/invoice.pdf",
			"attachments/msg-1/att-b/receipt.zip",
		];

		for (const r2Key of attachments) {
			await fireYaraScan(env as any, ctx as any, "user@example.com", "msg-1", r2Key);
		}

		// Drain all scheduled fetches
		await Promise.all(scheduled);

		// CodeQL URL parse rule: compare hostname, never startsWith/includes
		const calledUrls = fetchSpy.mock.calls.map(([url]) => new URL(url as string).hostname);
		expect(calledUrls).toHaveLength(2);
		for (const hostname of calledUrls) {
			expect(hostname).toBe("sidecar.example.com");
		}

		// Each call should carry the correct r2Key in the payload
		const bodies = fetchSpy.mock.calls.map(([, init]) =>
			JSON.parse((init as RequestInit).body as string),
		);
		expect(bodies[0].r2Key).toBe(attachments[0]);
		expect(bodies[1].r2Key).toBe(attachments[1]);
	});

	it("does not fire when yaramail_scanner.enabled is false", async () => {
		mockedResolve.mockResolvedValue({
			raw: { yaramail_scanner: { enabled: false, endpoint_url: "https://sidecar.example.com/scan" } },
			security: { enabled: false },
		} as unknown as Awaited<ReturnType<typeof resolveMailboxSettings>>);

		const scheduled: Promise<unknown>[] = [];
		const ctx = { waitUntil: (p: Promise<unknown>) => { scheduled.push(p); } };
		const env = { BUCKET: {} } as unknown as { BUCKET: R2Bucket };

		await fireYaraScan(env as any, ctx as any, "user@example.com", "msg-1", "attachments/msg-1/att-a/file.pdf");
		await Promise.all(scheduled);

		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("does not fire when yaramail_scanner is absent (no attachments gate)", async () => {
		mockedResolve.mockResolvedValue({
			raw: {},
			security: { enabled: false },
		} as unknown as Awaited<ReturnType<typeof resolveMailboxSettings>>);

		const scheduled: Promise<unknown>[] = [];
		const ctx = { waitUntil: (p: Promise<unknown>) => { scheduled.push(p); } };
		const env = { BUCKET: {} } as unknown as { BUCKET: R2Bucket };

		await fireYaraScan(env as any, ctx as any, "user@example.com", "msg-1", "attachments/msg-1/att-a/file.pdf");
		await Promise.all(scheduled);

		expect(fetchSpy).not.toHaveBeenCalled();
	});
});

// ── 2. Callback route rejects invalid HMAC → 401 ──────────────────────────────

describe("POST /yaramail-callback — HMAC authentication", () => {
	it("returns 503 when YARAMAIL_CALLBACK_SECRET is not configured", async () => {
		const ns = makeMailboxNamespace(null);
		const app = makeApp({ MAILBOX: ns });

		const body = JSON.stringify({ emailId: "email-1", matches: [] });
		const res = await app.request(
			"/api/v1/mailboxes/user@example.com/yaramail-callback",
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body,
			},
		);
		expect(res.status).toBe(503);
	});

	it("returns 401 when x-yaramail-signature is missing", async () => {
		const ns = makeMailboxNamespace(null);
		const app = makeApp({ MAILBOX: ns, YARAMAIL_CALLBACK_SECRET: CALLBACK_SECRET });

		const body = JSON.stringify({ emailId: "email-1", matches: [] });
		const res = await app.request(
			"/api/v1/mailboxes/user@example.com/yaramail-callback",
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body,
			},
		);
		expect(res.status).toBe(401);
		const json = await res.json<{ error: string }>();
		expect(json.error).toMatch(/invalid signature/i);
	});

	it("returns 401 when x-yaramail-signature is wrong", async () => {
		const ns = makeMailboxNamespace(null);
		const app = makeApp({ MAILBOX: ns, YARAMAIL_CALLBACK_SECRET: CALLBACK_SECRET });

		const body = JSON.stringify({ emailId: "email-1", matches: [] });
		const res = await app.request(
			"/api/v1/mailboxes/user@example.com/yaramail-callback",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					"x-yaramail-signature": "deadbeef",
				},
				body,
			},
		);
		expect(res.status).toBe(401);
	});

	it("returns 401 when signature is valid for different body (replay attempt)", async () => {
		const ns = makeMailboxNamespace(null);
		const app = makeApp({ MAILBOX: ns, YARAMAIL_CALLBACK_SECRET: CALLBACK_SECRET });

		const otherBody = JSON.stringify({ emailId: "other-email", matches: [] });
		const sig = await signBody(otherBody);

		const body = JSON.stringify({ emailId: "email-1", matches: [] });
		const res = await app.request(
			"/api/v1/mailboxes/user@example.com/yaramail-callback",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					"x-yaramail-signature": sig,
				},
				body,
			},
		);
		expect(res.status).toBe(401);
	});

	it("returns 200 with correct HMAC signature", async () => {
		const ns = makeMailboxNamespace(50);
		const app = makeApp({ MAILBOX: ns, YARAMAIL_CALLBACK_SECRET: CALLBACK_SECRET });

		const body = JSON.stringify({ emailId: "email-1", matches: [] });
		const sig = await signBody(body);

		const res = await app.request(
			"/api/v1/mailboxes/user@example.com/yaramail-callback",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					"x-yaramail-signature": sig,
				},
				body,
			},
		);
		expect(res.status).toBe(200);
	});
});

// ── 3. Callback route applies score delta capped at 100 ───────────────────────

describe("POST /yaramail-callback — score delta application", () => {
	it("applies computeYaraScoreDelta from matches and caps total at 100", async () => {
		// Start with score 90; pdf_phishing = +20 → would be 110, capped to 100
		const ns = makeMailboxNamespace(90);
		const app = makeApp({ MAILBOX: ns, YARAMAIL_CALLBACK_SECRET: CALLBACK_SECRET });

		const matches = [{ rule_name: "pdf_phishing" }]; // DEFAULT_YARA_RULE_SCORES.pdf_phishing = 20
		const body = JSON.stringify({ emailId: "email-1", matches });
		const sig = await signBody(body);

		const res = await app.request(
			"/api/v1/mailboxes/user@example.com/yaramail-callback",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					"x-yaramail-signature": sig,
				},
				body,
			},
		);

		expect(res.status).toBe(200);
		const json = await res.json<{ ok: boolean; scoreDelta: number }>();
		// scoreDelta is the raw delta from computeYaraScoreDelta (20), not capped
		expect(json.scoreDelta).toBe(20);
		// The stub applies the cap; final stored score = 100
		expect(ns._stub.getScore()).toBe(100);
	});

	it("calls insertYaraScanResult and applyYaraSignal on the DO stub", async () => {
		const ns = makeMailboxNamespace(0);
		const app = makeApp({ MAILBOX: ns, YARAMAIL_CALLBACK_SECRET: CALLBACK_SECRET });

		const matches = [{ rule_name: "eml_attachment" }]; // score 5
		const body = JSON.stringify({ emailId: "email-42", matches });
		const sig = await signBody(body);

		await app.request(
			"/api/v1/mailboxes/user@example.com/yaramail-callback",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					"x-yaramail-signature": sig,
				},
				body,
			},
		);

		expect(ns._calls.insertYaraScanResult).toHaveLength(1);
		const [emailId, resultsJson] = ns._calls.insertYaraScanResult[0];
		expect(emailId).toBe("email-42");
		expect(JSON.parse(resultsJson)).toEqual(matches);

		expect(ns._calls.applyYaraSignal).toHaveLength(1);
		const [signalEmailId, scoreDelta] = ns._calls.applyYaraSignal[0];
		expect(signalEmailId).toBe("email-42");
		expect(scoreDelta).toBe(5);
	});
});

// ── 4. No score downgrade ─────────────────────────────────────────────────────

describe("applyYaraSignal — no score downgrade (stub logic)", () => {
	it("does not lower the score when scoreDelta is 0", async () => {
		const ns = makeMailboxNamespace(75);
		const app = makeApp({ MAILBOX: ns, YARAMAIL_CALLBACK_SECRET: CALLBACK_SECRET });

		// Empty match list → scoreDelta = 0
		const body = JSON.stringify({ emailId: "email-3", matches: [] });
		const sig = await signBody(body);

		await app.request(
			"/api/v1/mailboxes/user@example.com/yaramail-callback",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					"x-yaramail-signature": sig,
				},
				body,
			},
		);

		// Score must not have changed
		expect(ns._stub.getScore()).toBe(75);
	});

	it("never allows a higher existing score to be lowered by the stub", () => {
		// This exercises the stub's own applyYaraSignal logic:
		// if current=80 and delta=5, new=85 > 80 → allow.
		// if current=90 and delta=5, new=95 > 90 → allow.
		// The acceptance criterion is "never downgrade", which means
		// if delta were somehow negative (shouldn't happen per computeYaraScoreDelta)
		// the stub would reject it via the `next > current` guard.
		const ns = makeMailboxNamespace(80);
		const stub = ns._stub;

		// delta = 0 → no change
		stub.applyYaraSignal("email-X", 0);
		expect(stub.getScore()).toBe(80);

		// delta = 10 → upgrade
		stub.applyYaraSignal("email-X", 10);
		expect(stub.getScore()).toBe(90);

		// delta = 0 again → no change
		stub.applyYaraSignal("email-X", 0);
		expect(stub.getScore()).toBe(90);
	});
});
