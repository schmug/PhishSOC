// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../../workers/index", () => ({
	receiveEmail: vi.fn(),
}));

import { receiveEmail } from "../../workers/index";
import { pollWorkspaceMailbox, MAX_MESSAGES_PER_POLL, POLL_LEASE_TTL_MS } from "../../workers/providers/workspace";
import type { SidecarConfig } from "../../workers/lib/sidecar-config";

const mockedReceive = vi.mocked(receiveEmail);

const CFG: SidecarConfig = {
	provider: "workspace",
	credentials_secret_name: "SIDECAR_SECRET_test",
	mode: "observe",
	quarantine_behavior: "label-only",
	retention_days: 7,
};

// Build a raw RFC-5322 message and its base64url encoding for messages.get.
function rawMessage(msgId: string, subject: string): string {
	const raw = `Message-ID: <${msgId}>\r\nSubject: ${subject}\r\nFrom: a@evil.example\r\nTo: user@tenant.example\r\n\r\nbody`;
	return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Same, but with NO Message-ID header — adversarial mail omits it on purpose
// to dodge Message-ID-keyed dedupe (#593).
function rawMessageNoMsgId(subject: string): string {
	const raw = `Subject: ${subject}\r\nFrom: a@evil.example\r\nTo: user@tenant.example\r\n\r\nbody`;
	return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function makeStub(state: Record<string, unknown> | null) {
	return {
		getSidecarState: vi.fn().mockResolvedValue(state),
		acquirePollLease: vi.fn().mockResolvedValue(true),
		putSidecarState: vi.fn().mockResolvedValue(undefined),
		appendSidecarAudit: vi.fn().mockResolvedValue(undefined),
		appendSidecarEvent: vi.fn().mockResolvedValue(undefined),
		findEmailIdByMessageId: vi.fn().mockResolvedValue(null),
		findEmailIdByProviderMessageId: vi.fn().mockResolvedValue(null),
		findSidecarAuditPendingLabels: vi.fn().mockResolvedValue(null),
		updateSidecarAuditLabels: vi.fn().mockResolvedValue(undefined),
		createCase: vi.fn().mockResolvedValue({ id: "case-1" }),
	};
}

function makeEnv(stub: ReturnType<typeof makeStub>) {
	return {
		MAILBOX: { idFromName: vi.fn().mockReturnValue("do-id"), get: vi.fn().mockReturnValue(stub) },
		BUCKET: { get: vi.fn(), head: vi.fn(), put: vi.fn(), list: vi.fn() },
		SIDECAR_SECRET_test: JSON.stringify({
			client_email: "svc@p.iam.gserviceaccount.com",
			// Tests never reach real signing when access_token is cached in state;
			// tests that DO mint use the generated key helper from gmail-client.test.ts.
			private_key: "-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----",
		}),
	} as never;
}

const ctx = { waitUntil: vi.fn() } as never;

/** Cached-token state so no token minting happens in most tests. */
function freshState(cursor: string | null, pageToken: string | null = null) {
	return {
		history_cursor: cursor,
		history_page_token: pageToken,
		access_token: "cached-tok",
		token_expires_at: Date.now() + 3600_000,
		label_ids: null,
		last_poll_at: null,
		last_error: null,
		consecutive_failures: 0,
		poll_lease_until: null,
		label_error: null,
		label_failure_count: 0,
	};
}

function gmailFetch(routes: Record<string, (u: URL, init?: RequestInit) => Response>) {
	vi.stubGlobal("fetch", vi.fn(async (url: string | URL, init?: RequestInit) => {
		const u = new URL(String(url));
		if (u.hostname !== "gmail.googleapis.com") throw new Error(`unexpected host ${u.hostname}`);
		for (const [prefix, handler] of Object.entries(routes)) {
			if (u.pathname.startsWith(`/gmail/v1/users/me${prefix}`)) return handler(u, init);
		}
		throw new Error(`unexpected path ${u.pathname}`);
	}));
}

afterEach(() => { vi.unstubAllGlobals(); vi.clearAllMocks(); });

describe("pollWorkspaceMailbox", () => {
	it("first run initializes the cursor from getProfile and processes nothing", async () => {
		const stub = makeStub(freshState(null));
		gmailFetch({ "/profile": () => new Response(JSON.stringify({ emailAddress: "u@t", historyId: "500" }), { status: 200 }) });
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r).toEqual({ processed: 0, deduped: 0, error: null });
		expect(mockedReceive).not.toHaveBeenCalled();
		const patch = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch.history_cursor).toBe("500");
		expect(patch.consecutive_failures).toBe(0);
	});

	it("steady state: fetches new messages, calls receiveEmail with providerMessageId, advances cursor", async () => {
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-1", verdict: null });
		gmailFetch({
			"/history": () => new Response(JSON.stringify({
				historyId: "200",
				history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }],
			}), { status: 200 }),
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "hello") }), { status: 200 }),
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r.processed).toBe(1);
		expect(mockedReceive).toHaveBeenCalledTimes(1);
		const normalized = mockedReceive.mock.calls[0][0];
		expect(normalized.kind).toBe("mailbox");
		expect(normalized.mailboxId).toBe("user@tenant.example");
		expect(normalized.providerMessageId).toBe("g1");
		expect(stub.putSidecarState.mock.calls.at(-1)![0].history_cursor).toBe("200");
	});

	it("dedupes on RFC Message-ID and still advances the cursor", async () => {
		const stub = makeStub(freshState("100"));
		stub.findEmailIdByMessageId.mockResolvedValue("already-there");
		gmailFetch({
			"/history": () => new Response(JSON.stringify({
				historyId: "200",
				history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }],
			}), { status: 200 }),
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "hello") }), { status: 200 }),
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r).toMatchObject({ processed: 0, deduped: 1 });
		expect(mockedReceive).not.toHaveBeenCalled();
	});

	it("observe mode: quarantine verdict writes audit + case but NO Gmail modify", async () => {
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-1", verdict: { action: "quarantine", score: 85, confidence: 0.8, explanation: "", signals: [] } as never });
		const modifyCalls: string[] = [];
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "200", history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }] }), { status: 200 }),
			"/messages/g1/modify": (u) => { modifyCalls.push(u.pathname); return new Response("{}", { status: 200 }); },
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "phish!") }), { status: 200 }),
			"/labels": () => new Response(JSON.stringify({ labels: [] }), { status: 200 }),
		});
		await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(modifyCalls).toEqual([]); // observe mode never touches the tenant
		expect(stub.appendSidecarAudit).toHaveBeenCalledWith(expect.objectContaining({
			gmail_message_id: "g1", action: "quarantine", mode: "observe", labels_applied: "[]",
		}));
		expect(stub.createCase).toHaveBeenCalledWith(expect.objectContaining({ emailId: "local-1", score: 85 }));
	});

	it("active mode: quarantine verdict ensures labels and modifies the message", async () => {
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-1", verdict: { action: "block", score: 95, confidence: 0.9, explanation: "", signals: [] } as never });
		let modified: unknown = null;
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "200", history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }] }), { status: 200 }),
			"/messages/g1/modify": (_u, init) => { modified = JSON.parse(String(init?.body)); return new Response("{}", { status: 200 }); },
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "phish!") }), { status: 200 }),
			"/labels": (_u, init) => init?.method === "POST"
				? new Response(JSON.stringify({ id: "NEW", name: JSON.parse(String(init.body)).name }), { status: 200 })
				: new Response(JSON.stringify({ labels: [{ id: "LQ", name: "PhishPilot/Quarantine" }, { id: "LS", name: "PhishPilot/Suspicious" }, { id: "LA", name: "PhishPilot/Allow" }] }), { status: 200 }),
		});
		await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", { ...CFG, mode: "active" });
		expect(modified).toEqual({ addLabelIds: ["LQ"], removeLabelIds: [] });
		expect(stub.appendSidecarAudit).toHaveBeenCalledWith(expect.objectContaining({
			mode: "active", labels_applied: JSON.stringify(["PhishPilot/Quarantine"]),
		}));
	});

	it("active mode label 403 across polls (#590): containment + a durable failure signal that a label-clean poll cannot flap back to healthy", async () => {
		// -- Poll 1: the wrong-scope grant (gmail.readonly) 403s the label write. --
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-1", verdict: { action: "quarantine", score: 90, confidence: 0.9, explanation: "", signals: [] } as never });
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "200", history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }] }), { status: 200 }),
			// modify listed BEFORE /messages/g1 — startsWith prefix matching.
			"/messages/g1/modify": () => new Response("insufficient scope", { status: 403 }),
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "phish!") }), { status: 200 }),
			"/labels": () => new Response(JSON.stringify({ labels: [{ id: "LQ", name: "PhishPilot/Quarantine" }, { id: "LS", name: "PhishPilot/Suspicious" }, { id: "LA", name: "PhishPilot/Allow" }] }), { status: 200 }),
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", { ...CFG, mode: "active" });
		// Ingest succeeded → not a batch error; the label write failed in isolation.
		expect(r.error).toBeNull();
		expect(r.processed).toBe(1);
		// Audit row written despite the label 403, with an empty labels list.
		expect(stub.appendSidecarAudit).toHaveBeenCalledWith(expect.objectContaining({
			gmail_message_id: "g1", action: "quarantine", mode: "active", labels_applied: "[]",
		}));
		// Case still created (containment: the flag isn't lost).
		expect(stub.createCase).toHaveBeenCalledWith(expect.objectContaining({ emailId: "local-1" }));
		const patch = stub.putSidecarState.mock.calls.at(-1)![0];
		// Ingest complete → cursor advances (Fix 1 rules still apply).
		expect(patch.history_cursor).toBe("200");
		// But the wrong-scope grant surfaces in health, not silently reset.
		expect(patch.consecutive_failures).toBe(1);
		expect(patch.last_error).toMatch(/label write failed/);
		// ...and durably (#590): decoupled from the transient counters.
		expect(patch.label_error).toMatch(/label write failed/);
		expect(patch.label_failure_count).toBe(1);

		// -- Poll 2 (label-clean: nothing flagged, nothing labeled): the
		// transient counters reset — the pre-#590 flap — but the patch must NOT
		// touch label_error/label_failure_count, so putSidecarState's patch-only
		// semantics keep the persisted signal raised until a write SUCCEEDS. --
		vi.clearAllMocks();
		mockedReceive.mockResolvedValue({ messageId: "local-2", verdict: null });
		const stub2 = makeStub({
			...freshState("200"),
			label_error: "label write failed for 1 message(s): gmail modify 403", label_failure_count: 1,
		});
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "300", history: [{ messagesAdded: [{ message: { id: "g2", labelIds: ["INBOX"] } }] }] }), { status: 200 }),
			"/messages/g2": () => new Response(JSON.stringify({ id: "g2", raw: rawMessage("m2@x", "benign") }), { status: 200 }),
		});
		const r2 = await pollWorkspaceMailbox(makeEnv(stub2), ctx, "user@tenant.example", { ...CFG, mode: "active" });
		expect(r2).toMatchObject({ processed: 1, error: null });
		const patch2 = stub2.putSidecarState.mock.calls.at(-1)![0];
		expect(patch2.last_error).toBeNull();
		expect(patch2.consecutive_failures).toBe(0);
		expect("label_error" in patch2).toBe(false);
		expect("label_failure_count" in patch2).toBe(false);
	});

	it("label backfill on dedupe (#590): 403 batch then fixed-grant replay → message labeled, exactly one audit row, signal cleared", async () => {
		const history = () => new Response(JSON.stringify({ historyId: "200", history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }] }), { status: 200 });
		const labels = () => new Response(JSON.stringify({ labels: [{ id: "LQ", name: "PhishPilot/Quarantine" }, { id: "LS", name: "PhishPilot/Suspicious" }, { id: "LA", name: "PhishPilot/Allow" }] }), { status: 200 });

		// -- Poll 1: ingest lands, label write 403s (wrong-scope grant). --
		const stub1 = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-1", verdict: { action: "quarantine", score: 90, confidence: 0.9, explanation: "", signals: [] } as never });
		gmailFetch({
			"/history": history,
			"/messages/g1/modify": () => new Response("insufficient scope", { status: 403 }),
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "phish!") }), { status: 200 }),
			"/labels": labels,
		});
		await pollWorkspaceMailbox(makeEnv(stub1), ctx, "user@tenant.example", { ...CFG, mode: "active" });
		expect(stub1.appendSidecarAudit).toHaveBeenCalledTimes(1);
		expect(stub1.putSidecarState.mock.calls.at(-1)![0].label_failure_count).toBe(1);

		// -- Poll 2: grant fixed; the same id is re-listed (at-least-once) and
		// dedupes. The audit row shows the label never landed → retry the label
		// write ONLY: no receiveEmail, no new audit row, no new Case. --
		vi.clearAllMocks();
		const stub2 = makeStub({
			...freshState("100"),
			label_error: "label write failed for 1 message(s): gmail modify 403", label_failure_count: 1,
		});
		stub2.findEmailIdByMessageId.mockResolvedValue("local-1"); // dedupe hit
		stub2.findSidecarAuditPendingLabels.mockResolvedValue({ id: 7, action: "quarantine" });
		let modified: unknown = null;
		gmailFetch({
			"/history": history,
			"/messages/g1/modify": (_u, init) => { modified = JSON.parse(String(init?.body)); return new Response("{}", { status: 200 }); },
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "phish!") }), { status: 200 }),
			"/labels": labels,
		});
		const r2 = await pollWorkspaceMailbox(makeEnv(stub2), ctx, "user@tenant.example", { ...CFG, mode: "active" });
		expect(r2).toMatchObject({ processed: 0, deduped: 1, error: null });
		// At-least-once preserved: the backfill never re-ingests or re-audits.
		expect(mockedReceive).not.toHaveBeenCalled();
		expect(stub2.appendSidecarAudit).not.toHaveBeenCalled();
		expect(stub2.createCase).not.toHaveBeenCalled();
		// The label write itself landed, quarantine label only...
		expect(modified).toEqual({ addLabelIds: ["LQ"], removeLabelIds: [] });
		// ...and the ONE existing audit row was updated in place.
		expect(stub2.findSidecarAuditPendingLabels).toHaveBeenCalledWith("g1");
		expect(stub2.updateSidecarAuditLabels).toHaveBeenCalledTimes(1);
		expect(stub2.updateSidecarAuditLabels).toHaveBeenCalledWith(7, JSON.stringify(["PhishPilot/Quarantine"]));
		// A successful label write clears the durable signal.
		const patch2 = stub2.putSidecarState.mock.calls.at(-1)![0];
		expect(patch2.label_error).toBeNull();
		expect(patch2.label_failure_count).toBe(0);
	});

	it("label backfill retry that still 403s keeps the durable signal raised and accumulates the count", async () => {
		const stub = makeStub({
			...freshState("100"),
			label_error: "label write failed for 1 message(s): gmail modify 403", label_failure_count: 1,
		});
		stub.findEmailIdByMessageId.mockResolvedValue("local-1"); // dedupe hit
		stub.findSidecarAuditPendingLabels.mockResolvedValue({ id: 7, action: "quarantine" });
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "200", history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }] }), { status: 200 }),
			"/messages/g1/modify": () => new Response("insufficient scope", { status: 403 }),
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "phish!") }), { status: 200 }),
			"/labels": () => new Response(JSON.stringify({ labels: [{ id: "LQ", name: "PhishPilot/Quarantine" }, { id: "LS", name: "PhishPilot/Suspicious" }, { id: "LA", name: "PhishPilot/Allow" }] }), { status: 200 }),
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", { ...CFG, mode: "active" });
		// Still contained: the failed retry is not a batch error.
		expect(r).toMatchObject({ processed: 0, deduped: 1, error: null });
		expect(stub.updateSidecarAuditLabels).not.toHaveBeenCalled();
		const patch = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch.label_error).toMatch(/label write failed/);
		expect(patch.label_failure_count).toBe(2); // 1 persisted + 1 new failure
	});

	it("observe mode never backfills labels on dedupe hits (writes nothing, by design)", async () => {
		const stub = makeStub(freshState("100"));
		stub.findEmailIdByMessageId.mockResolvedValue("local-1"); // dedupe hit
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "200", history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }] }), { status: 200 }),
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "phish!") }), { status: 200 }),
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG); // observe
		expect(r).toMatchObject({ processed: 0, deduped: 1, error: null });
		// Not even the audit probe runs: observe mode must never touch Gmail,
		// and the probe would be a wasted DO round-trip.
		expect(stub.findSidecarAuditPendingLabels).not.toHaveBeenCalled();
		expect(stub.updateSidecarAuditLabels).not.toHaveBeenCalled();
	});

	it("null verdict: no audit row, no case, no label", async () => {
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-1", verdict: null });
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "200", history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }] }), { status: 200 }),
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "ok") }), { status: 200 }),
		});
		await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(stub.appendSidecarAudit).not.toHaveBeenCalled();
		expect(stub.createCase).not.toHaveBeenCalled();
	});

	it("expired cursor (404): reinitializes from getProfile, records gap, does not count a failure", async () => {
		const stub = makeStub(freshState("1"));
		gmailFetch({
			"/history": () => new Response("Not Found", { status: 404 }),
			"/profile": () => new Response(JSON.stringify({ emailAddress: "u@t", historyId: "900" }), { status: 200 }),
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r.error).toBeNull();
		const patch = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch.history_cursor).toBe("900");
		expect(patch.consecutive_failures).toBe(0);
		expect(patch.last_error).toMatch(/history gap/);
		// Durable record (#594): the gap lands in sidecar_events with the
		// cursor jump, not just the transient last_error field.
		expect(stub.appendSidecarEvent).toHaveBeenCalledTimes(1);
		expect(stub.appendSidecarEvent).toHaveBeenCalledWith(expect.objectContaining({
			kind: "history-gap", old_cursor: "1", new_cursor: "900", ts: expect.any(String),
		}));
	});

	it("history-gap record survives the next clean poll (#594): last_error resets to null, the event stays", async () => {
		// Poll 1: expired cursor → re-anchor + durable gap event.
		const stub = makeStub(freshState("1"));
		gmailFetch({
			"/history": () => new Response("Not Found", { status: 404 }),
			"/profile": () => new Response(JSON.stringify({ emailAddress: "u@t", historyId: "900" }), { status: 200 }),
		});
		await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(stub.appendSidecarEvent).toHaveBeenCalledTimes(1);
		expect(stub.putSidecarState.mock.calls.at(-1)![0].last_error).toMatch(/history gap/);

		// Poll 2 (~1 minute later, clean): the state patch overwrites
		// last_error with null — the pre-#594 behavior that erased all gap
		// evidence — but the durable event is append-only: nothing in the
		// clean-poll path clears or rewrites sidecar_events.
		stub.getSidecarState.mockResolvedValue(freshState("900"));
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "901", history: [] }), { status: 200 }),
		});
		const r2 = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r2.error).toBeNull();
		const patch = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch.last_error).toBeNull();
		expect(patch.history_cursor).toBe("901");
		// Still exactly one gap event: the clean poll neither re-appended nor
		// erased it. (No stub method deletes events; DO-level survival is
		// pinned in test/durableObject/sidecar-state.test.ts.)
		expect(stub.appendSidecarEvent).toHaveBeenCalledTimes(1);
	});

	it("a Gmail failure freezes the cursor, increments consecutive_failures, records last_error", async () => {
		const stub = makeStub({ ...freshState("100"), consecutive_failures: 1 });
		gmailFetch({ "/history": () => new Response("upstream boom", { status: 503 }) });
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r.error).toMatch(/503/);
		const patch = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch.consecutive_failures).toBe(2);
		expect(patch.history_cursor).toBeUndefined(); // cursor key absent from the patch = frozen
	});

	it("backoff: >=5 consecutive failures + recent poll → skips without calling Gmail", async () => {
		const stub = makeStub({ ...freshState("100"), consecutive_failures: 5, last_poll_at: Date.now() - 60_000 });
		vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("must not fetch"); }));
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r).toEqual({ processed: 0, deduped: 0, error: null });
		// Backoff gate sits BEFORE the lease: a backed-off mailbox burns no
		// lease write per minute (#591).
		expect(stub.acquirePollLease).not.toHaveBeenCalled();
	});

	it("poll lease held (#591): overlapping tick returns immediately — zero Gmail fetches, zero state writes", async () => {
		const stub = makeStub(freshState("100"));
		stub.acquirePollLease.mockResolvedValue(false); // another tick holds the lease
		vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("must not fetch"); }));
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r).toEqual({ processed: 0, deduped: 0, error: null });
		expect(mockedReceive).not.toHaveBeenCalled();
		expect(stub.putSidecarState).not.toHaveBeenCalled();
		expect(stub.appendSidecarAudit).not.toHaveBeenCalled();
		// The skip cost exactly one DO round-trip (the check-and-set itself).
		expect(stub.acquirePollLease).toHaveBeenCalledTimes(1);
	});

	it("poll lease (#591): acquired once per poll with the 5-minute TTL and released in the success patch", async () => {
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-1", verdict: null });
		gmailFetch({
			"/history": () => new Response(JSON.stringify({
				historyId: "200",
				history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }],
			}), { status: 200 }),
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "hello") }), { status: 200 }),
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r.error).toBeNull();
		// One acquire round-trip, TTL comfortably above a worst-case tick.
		expect(stub.acquirePollLease).toHaveBeenCalledTimes(1);
		expect(stub.acquirePollLease).toHaveBeenCalledWith(expect.any(Number), POLL_LEASE_TTL_MS);
		expect(POLL_LEASE_TTL_MS).toBe(5 * 60 * 1000);
		// One in-loop heartbeat + one success patch that releases the lease.
		expect(stub.putSidecarState).toHaveBeenCalledTimes(2);
		expect(stub.putSidecarState.mock.calls.at(-1)![0].poll_lease_until).toBeNull();
	});

	it("poll lease (#591): the failure path releases too — a failing poll never wedges the mailbox for the TTL", async () => {
		const stub = makeStub(freshState("100"));
		gmailFetch({ "/history": () => new Response("upstream boom", { status: 503 }) });
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r.error).toMatch(/503/);
		const patch = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch.poll_lease_until).toBeNull();
	});

	it("poll lease (#591): first-run and history-gap early returns release via their state patch", async () => {
		// First run (cursor anchor).
		const stub1 = makeStub(freshState(null));
		gmailFetch({ "/profile": () => new Response(JSON.stringify({ emailAddress: "u@t", historyId: "500" }), { status: 200 }) });
		await pollWorkspaceMailbox(makeEnv(stub1), ctx, "user@tenant.example", CFG);
		expect(stub1.putSidecarState.mock.calls.at(-1)![0].poll_lease_until).toBeNull();

		// History-gap re-anchor.
		const stub2 = makeStub(freshState("1"));
		gmailFetch({
			"/history": () => new Response("Not Found", { status: 404 }),
			"/profile": () => new Response(JSON.stringify({ emailAddress: "u@t", historyId: "900" }), { status: 200 }),
		});
		await pollWorkspaceMailbox(makeEnv(stub2), ctx, "user@tenant.example", CFG);
		expect(stub2.putSidecarState.mock.calls.at(-1)![0].poll_lease_until).toBeNull();
	});

	it("poll lease (#591): heartbeat renewed once per listed message so long batches cannot expire mid-loop", async () => {
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-x", verdict: null });
		const three = Array.from({ length: 3 }, (_, i) => ({ message: { id: `g${i}`, labelIds: ["INBOX"] } }));
		gmailFetch({
			"/history": () => new Response(JSON.stringify({
				historyId: "200",
				history: [{ messagesAdded: three }],
			}), { status: 200 }),
			"/messages/": (u) => {
				const id = u.pathname.split("/").pop()!;
				return new Response(JSON.stringify({ id, raw: rawMessage(`${id}@x`, "s") }), { status: 200 });
			},
		});
		await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		const heartbeats = stub.putSidecarState.mock.calls.filter(
			(c) => Object.keys(c[0]).length === 1 && c[0].poll_lease_until != null,
		);
		expect(heartbeats).toHaveLength(3);
		expect(stub.putSidecarState.mock.calls.at(-1)![0].poll_lease_until).toBeNull();
	});

	it("caps at MAX_MESSAGES_PER_POLL PROCESSED messages and freezes the cursor when capped", async () => {
		// 30 FRESH ids (none deduped): the cap counts processed messages, so
		// exactly MAX are processed and the cursor stays frozen.
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-x", verdict: null });
		const many = Array.from({ length: MAX_MESSAGES_PER_POLL + 5 }, (_, i) => ({ message: { id: `g${i}`, labelIds: ["INBOX"] } }));
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "999", history: [{ messagesAdded: many }] }), { status: 200 }),
			"/messages/": (u) => {
				const id = u.pathname.split("/").pop()!;
				return new Response(JSON.stringify({ id, raw: rawMessage(`${id}@x`, "s") }), { status: 200 });
			},
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r.processed).toBe(MAX_MESSAGES_PER_POLL);
		expect(stub.putSidecarState.mock.calls.at(-1)![0].history_cursor).toBeUndefined();
	});

	it("regression: a >MAX burst converges — deduped messages do NOT consume the cap, cursor advances once the tail is worked", async () => {
		// 30 ids listed on BOTH polls. Poll 1 processes the first 25 (all fresh)
		// and freezes the cursor. Poll 2 must dedupe those 25 for FREE and
		// process the remaining 5, then advance — proving no permanent wedge.
		const N = MAX_MESSAGES_PER_POLL + 5; // 30
		const many = Array.from({ length: N }, (_, i) => ({ message: { id: `g${i}`, labelIds: ["INBOX"] } }));
		const history = () => new Response(JSON.stringify({ historyId: "999", history: [{ messagesAdded: many }] }), { status: 200 });
		const messages = (u: URL) => {
			const id = u.pathname.split("/").pop()!;
			return new Response(JSON.stringify({ id, raw: rawMessage(`${id}@x`, "s") }), { status: 200 });
		};

		// -- Poll 1: nothing deduped --
		const stub1 = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-x", verdict: null });
		gmailFetch({ "/history": history, "/messages/": messages });
		const r1 = await pollWorkspaceMailbox(makeEnv(stub1), ctx, "user@tenant.example", CFG);
		expect(r1).toMatchObject({ processed: MAX_MESSAGES_PER_POLL, deduped: 0 });
		expect(stub1.putSidecarState.mock.calls.at(-1)![0].history_cursor).toBeUndefined();

		// -- Poll 2: the first 25 RFC Message-IDs are now already stored --
		const stub2 = makeStub(freshState("100"));
		// gmail id gN → RFC Message-ID gN@x (see rawMessage). The first 25 dedupe.
		const seen = new Set(Array.from({ length: MAX_MESSAGES_PER_POLL }, (_, i) => `g${i}@x`));
		stub2.findEmailIdByMessageId.mockImplementation(async (mid: string) => (seen.has(mid) ? "already" : null));
		gmailFetch({ "/history": history, "/messages/": messages });
		const r2 = await pollWorkspaceMailbox(makeEnv(stub2), ctx, "user@tenant.example", CFG);
		expect(r2).toMatchObject({ processed: 5, deduped: MAX_MESSAGES_PER_POLL });
		expect(stub2.putSidecarState.mock.calls.at(-1)![0].history_cursor).toBe("999");
	});

	it("mid-batch throw: at-least-once — processed>0 with the cursor frozen", async () => {
		// g1 succeeds, g2's messages.get 500s: the batch aborts AFTER g1 was
		// ingested. processed must be 1 (g1 is stored) AND the cursor must be
		// frozen so g2+ are retried next poll — at-least-once, never skip.
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-x", verdict: null });
		const many = [0, 1, 2].map((i) => ({ message: { id: `g${i}`, labelIds: ["INBOX"] } }));
		gmailFetch({
			"/history": () => new Response(JSON.stringify({ historyId: "777", history: [{ messagesAdded: many }] }), { status: 200 }),
			"/messages/g1": () => new Response("boom", { status: 500 }),
			"/messages/": (u) => {
				const id = u.pathname.split("/").pop()!;
				return new Response(JSON.stringify({ id, raw: rawMessage(`${id}@x`, "s") }), { status: 200 });
			},
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r.error).not.toBeNull();
		expect(r.processed).toBe(1); // g0 ingested before g1 threw
		const patch = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch.history_cursor).toBeUndefined(); // frozen
		expect(patch.consecutive_failures).toBe(1);
	});

	it("regression (#593): replayed poll dedupes a Message-ID-less message via the provider id — no duplicate email/audit/case", async () => {
		const many = [0, 1].map((i) => ({ message: { id: `g${i}`, labelIds: ["INBOX"] } }));
		const history = () => new Response(JSON.stringify({ historyId: "777", history: [{ messagesAdded: many }] }), { status: 200 });

		// -- Poll 1: g0 (NO Message-ID header) ingests and is flagged; g1's
		// messages.get 500s mid-batch, so the cursor freezes and the next
		// poll re-lists BOTH ids. --
		const stub1 = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-g0", verdict: { action: "quarantine", score: 90, confidence: 0.9, explanation: "", signals: [] } as never });
		gmailFetch({
			"/history": history,
			"/messages/g1": () => new Response("boom", { status: 500 }),
			"/messages/g0": () => new Response(JSON.stringify({ id: "g0", raw: rawMessageNoMsgId("no-msgid phish") }), { status: 200 }),
		});
		const r1 = await pollWorkspaceMailbox(makeEnv(stub1), ctx, "user@tenant.example", CFG);
		expect(r1.error).not.toBeNull();
		expect(r1.processed).toBe(1); // g0 ingested before g1 threw
		expect(stub1.putSidecarState.mock.calls.at(-1)![0].history_cursor).toBeUndefined(); // frozen
		expect(stub1.appendSidecarAudit).toHaveBeenCalledTimes(1);
		expect(stub1.createCase).toHaveBeenCalledTimes(1);

		// -- Poll 2 (replay): g0 is already stored under its Gmail id. The
		// RFC Message-ID lookup can never match (there is no Message-ID), so
		// the dedupe must fall back to the provider-native id. --
		vi.clearAllMocks();
		const stub2 = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-g1", verdict: null });
		stub2.findEmailIdByProviderMessageId.mockImplementation(async (gid: string) => (gid === "g0" ? "local-g0" : null));
		gmailFetch({
			"/history": history,
			"/messages/g1": () => new Response(JSON.stringify({ id: "g1", raw: rawMessage("g1@x", "ok") }), { status: 200 }),
			"/messages/g0": () => new Response(JSON.stringify({ id: "g0", raw: rawMessageNoMsgId("no-msgid phish") }), { status: 200 }),
		});
		const r2 = await pollWorkspaceMailbox(makeEnv(stub2), ctx, "user@tenant.example", CFG);
		expect(r2).toMatchObject({ processed: 1, deduped: 1, error: null });
		// g0 was NOT re-ingested: receiveEmail ran only for g1.
		expect(mockedReceive).toHaveBeenCalledTimes(1);
		expect(mockedReceive.mock.calls[0][0].providerMessageId).toBe("g1");
		// No duplicate audit row or Case for the replayed g0.
		expect(stub2.appendSidecarAudit).not.toHaveBeenCalled();
		expect(stub2.createCase).not.toHaveBeenCalled();
		// Dedupe stays ONE DO call per message: the provider-id lookup only
		// runs for the Message-ID-less message, never in addition to the
		// Message-ID lookup.
		expect(stub2.findEmailIdByProviderMessageId).toHaveBeenCalledTimes(1);
		expect(stub2.findEmailIdByProviderMessageId).toHaveBeenCalledWith("g0");
		expect(stub2.findEmailIdByMessageId).toHaveBeenCalledTimes(1); // g1 only
		// Replay fully worked → cursor advances past the wedge.
		expect(stub2.putSidecarState.mock.calls.at(-1)![0].history_cursor).toBe("777");
	});

	it("token mint gate: near-expiry token is refreshed and the new token is persisted", async () => {
		const { makeTestServiceAccount } = await import("./helpers");
		const { sa } = await makeTestServiceAccount();
		// Token inside the 5-minute refresh margin → mint a fresh one.
		const stub = makeStub({ ...freshState("100"), token_expires_at: Date.now() + 60_000 });
		mockedReceive.mockResolvedValue({ messageId: "local-x", verdict: null });

		let tokenFetched = false;
		vi.stubGlobal("fetch", vi.fn(async (url: string | URL, init?: RequestInit) => {
			const u = new URL(String(url));
			if (u.hostname === "oauth2.googleapis.com" && u.pathname === "/token") {
				tokenFetched = true;
				return new Response(JSON.stringify({ access_token: "fresh-tok", expires_in: 3600, token_type: "Bearer" }), { status: 200 });
			}
			if (u.hostname === "gmail.googleapis.com") {
				if (u.pathname.startsWith("/gmail/v1/users/me/history")) {
					return new Response(JSON.stringify({ historyId: "200", history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }] }), { status: 200 });
				}
				if (u.pathname.startsWith("/gmail/v1/users/me/messages/")) {
					return new Response(JSON.stringify({ id: "g1", raw: rawMessage("m1@x", "s") }), { status: 200 });
				}
			}
			throw new Error(`unexpected fetch ${u.hostname}${u.pathname}`);
		}));

		const env = makeEnv(stub);
		(env as unknown as Record<string, unknown>).SIDECAR_SECRET_test = JSON.stringify(sa);
		const r = await pollWorkspaceMailbox(env, ctx, "user@tenant.example", CFG);
		expect(r.error).toBeNull();
		expect(tokenFetched).toBe(true);
		const patch = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch.access_token).toBe("fresh-tok");
		expect(patch.token_expires_at).toBeGreaterThan(Date.now() + 3000_000);
	});

	it("truncated history (page cap) freezes the cursor even when processed < MAX", async () => {
		// listNewMessageIds reports truncated:true; only a couple ids processed,
		// but the cursor must NOT advance past an incomplete listing.
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-x", verdict: null });
		let pages = 0;
		gmailFetch({
			"/history": () => {
				pages += 1;
				return new Response(JSON.stringify({
					historyId: "999",
					nextPageToken: `p${pages}`, // always dangles → truncated
					history: [{ messagesAdded: [{ message: { id: `g${pages}`, labelIds: ["INBOX"] } }] }],
				}), { status: 200 });
			},
			"/messages/": (u) => {
				const id = u.pathname.split("/").pop()!;
				return new Response(JSON.stringify({ id, raw: rawMessage(`${id}@x`, "s") }), { status: 200 });
			},
		});
		const r = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r.processed).toBeLessThan(MAX_MESSAGES_PER_POLL);
		expect(r.processed).toBeGreaterThan(0);
		const patch = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch.history_cursor).toBeUndefined();
		expect(patch.history_page_token).toBe("p3");
	});

	it("truncated history with all pages deduped saves history_page_token to resume past the cap (#667)", async () => {
		// Deadlock scenario: pages 1–3 fully deduped, page 4+ never fetched.
		// Poll 1: truncated listing, all ids deduped → save resume token.
		// Poll 2: resume from saved token, tail id ingested, cursor advances.
		const stub = makeStub(freshState("100"));
		mockedReceive.mockResolvedValue({ messageId: "local-tail", verdict: null });
		let historyCalls = 0;
		gmailFetch({
			"/history": (u) => {
				historyCalls += 1;
				const pageToken = u.searchParams.get("pageToken");
				if (!pageToken) {
					return new Response(JSON.stringify({
						historyId: "200",
						nextPageToken: "p2",
						history: [{ messagesAdded: [{ message: { id: "g1", labelIds: ["INBOX"] } }] }],
					}), { status: 200 });
				}
				if (pageToken === "p2") {
					return new Response(JSON.stringify({
						historyId: "250",
						nextPageToken: "p3",
						history: [{ messagesAdded: [{ message: { id: "g2", labelIds: ["INBOX"] } }] }],
					}), { status: 200 });
				}
				if (pageToken === "p3") {
					return new Response(JSON.stringify({
						historyId: "280",
						nextPageToken: "p4",
						history: [{ messagesAdded: [{ message: { id: "g3", labelIds: ["INBOX"] } }] }],
					}), { status: 200 });
				}
				if (pageToken === "p4") {
					return new Response(JSON.stringify({
						historyId: "300",
						history: [{ messagesAdded: [{ message: { id: "g-tail", labelIds: ["INBOX"] } }] }],
					}), { status: 200 });
				}
				throw new Error(`unexpected pageToken ${pageToken}`);
			},
			"/messages/": (u) => {
				const id = u.pathname.split("/").pop()!;
				return new Response(JSON.stringify({ id, raw: rawMessage(`${id}@x`, "s") }), { status: 200 });
			},
		});
		stub.findEmailIdByMessageId.mockImplementation(async (msgId: string) =>
			["g1@x", "g2@x", "g3@x"].includes(msgId) ? `existing-${msgId}` : null,
		);

		const r1 = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r1).toEqual({ processed: 0, deduped: 3, error: null });
		const patch1 = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch1.history_cursor).toBeUndefined();
		expect(patch1.history_page_token).toBe("p4");

		stub.getSidecarState.mockResolvedValue(freshState("100", "p4"));
		const r2 = await pollWorkspaceMailbox(makeEnv(stub), ctx, "user@tenant.example", CFG);
		expect(r2).toEqual({ processed: 1, deduped: 0, error: null });
		expect(historyCalls).toBe(4); // 3 pages on poll 1 + 1 resumed page on poll 2
		const patch2 = stub.putSidecarState.mock.calls.at(-1)![0];
		expect(patch2.history_cursor).toBe("300");
		expect(patch2.history_page_token).toBeNull();
	});
});
