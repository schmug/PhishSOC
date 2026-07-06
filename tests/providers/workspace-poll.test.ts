// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../workers/index", () => ({
	receiveEmail: vi.fn(),
}));

import { receiveEmail } from "../../workers/index";
import { pollWorkspaceMailbox, MAX_MESSAGES_PER_POLL } from "../../workers/providers/workspace";
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

function makeStub(state: Record<string, unknown> | null) {
	return {
		getSidecarState: vi.fn().mockResolvedValue(state),
		putSidecarState: vi.fn().mockResolvedValue(undefined),
		appendSidecarAudit: vi.fn().mockResolvedValue(undefined),
		findEmailIdByMessageId: vi.fn().mockResolvedValue(null),
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
function freshState(cursor: string | null) {
	return {
		history_cursor: cursor,
		access_token: "cached-tok",
		token_expires_at: Date.now() + 3600_000,
		label_ids: null,
		last_poll_at: null,
		last_error: null,
		consecutive_failures: 0,
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
	});

	it("caps the batch at MAX_MESSAGES_PER_POLL and does not advance the cursor when capped", async () => {
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
});
