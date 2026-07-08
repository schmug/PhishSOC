// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { afterEach, describe, expect, it, vi } from "vitest";

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
		appendSidecarEvent: vi.fn().mockResolvedValue(undefined),
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

	it("active mode label 403: audit row + case survive, cursor advances, failure surfaces in health", async () => {
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
		expect(stub.putSidecarState.mock.calls.at(-1)![0].history_cursor).toBeUndefined();
	});
});
