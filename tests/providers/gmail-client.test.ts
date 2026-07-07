// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	parseServiceAccountJson,
	mintAccessToken,
	GmailApiError,
} from "../../workers/providers/gmail-client";
import { makeTestServiceAccount } from "./helpers";

function b64urlToBytes(s: string): Uint8Array {
	const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
	return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

describe("parseServiceAccountJson", () => {
	it("accepts a JSON string with client_email and private_key", () => {
		const sa = parseServiceAccountJson(JSON.stringify({ client_email: "a@b.iam", private_key: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----" }));
		expect(sa?.client_email).toBe("a@b.iam");
	});
	it("returns null on malformed JSON, missing fields, or non-string input", () => {
		expect(parseServiceAccountJson("{nope")).toBeNull();
		expect(parseServiceAccountJson(JSON.stringify({ client_email: "a@b" }))).toBeNull();
		expect(parseServiceAccountJson(42)).toBeNull();
	});
});

describe("mintAccessToken", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("POSTs a signed RS256 assertion to oauth2.googleapis.com and returns the token", async () => {
		const { sa, publicKey } = await makeTestServiceAccount();
		let capturedBody = "";
		vi.stubGlobal("fetch", vi.fn(async (url: string | URL, init?: RequestInit) => {
			const u = new URL(String(url));
			if (u.hostname === "oauth2.googleapis.com" && u.pathname === "/token") {
				capturedBody = String(init?.body);
				return new Response(JSON.stringify({ access_token: "tok-123", expires_in: 3600, token_type: "Bearer" }), { status: 200 });
			}
			throw new Error(`unexpected fetch: ${u.hostname}`);
		}));

		const before = Date.now();
		const { token, expiresAt } = await mintAccessToken(sa, "user@tenant.example");
		expect(token).toBe("tok-123");
		expect(expiresAt).toBeGreaterThan(before + 3000_000); // ~3600s minus safety margin

		// Decode + verify the assertion we sent.
		const params = new URLSearchParams(capturedBody);
		expect(params.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
		const assertion = params.get("assertion")!;
		const [h, c, sig] = assertion.split(".");
		const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h)));
		const claims = JSON.parse(new TextDecoder().decode(b64urlToBytes(c)));
		expect(header).toEqual({ alg: "RS256", typ: "JWT" });
		expect(claims.iss).toBe(sa.client_email);
		expect(claims.sub).toBe("user@tenant.example");
		expect(claims.aud).toBe("https://oauth2.googleapis.com/token");
		expect(claims.scope).toBe("https://www.googleapis.com/auth/gmail.modify");
		expect(claims.exp - claims.iat).toBeLessThanOrEqual(3600);
		const ok = await crypto.subtle.verify(
			"RSASSA-PKCS1-v1_5", publicKey,
			b64urlToBytes(sig).buffer as ArrayBuffer,
			new TextEncoder().encode(`${h}.${c}`),
		);
		expect(ok).toBe(true);
	});

	it("throws GmailApiError with the response status on a non-200 token response", async () => {
		const { sa } = await makeTestServiceAccount();
		vi.stubGlobal("fetch", vi.fn(async (url: string | URL) => {
			const u = new URL(String(url));
			if (u.hostname === "oauth2.googleapis.com") {
				return new Response(JSON.stringify({ error: "unauthorized_client" }), { status: 401 });
			}
			throw new Error("unexpected fetch");
		}));
		await expect(mintAccessToken(sa, "user@tenant.example")).rejects.toThrowError(GmailApiError);
		await expect(mintAccessToken(sa, "user@tenant.example")).rejects.toMatchObject({ status: 401 });
	});
});

function gmailDispatcher(routes: Record<string, (u: URL, init?: RequestInit) => Response | Promise<Response>>) {
	return vi.fn(async (url: string | URL, init?: RequestInit) => {
		const u = new URL(String(url));
		if (u.hostname !== "gmail.googleapis.com") throw new Error(`unexpected host: ${u.hostname}`);
		for (const [prefix, handler] of Object.entries(routes)) {
			if (u.pathname.startsWith(`/gmail/v1/users/me${prefix}`)) return handler(u, init);
		}
		throw new Error(`unexpected path: ${u.pathname}`);
	});
}

describe("getProfile", () => {
	afterEach(() => vi.unstubAllGlobals());
	it("returns emailAddress and historyId", async () => {
		vi.stubGlobal("fetch", gmailDispatcher({
			"/profile": () => new Response(JSON.stringify({ emailAddress: "u@t.example", historyId: "4711", messagesTotal: 9 }), { status: 200 }),
		}));
		const { getProfile } = await import("../../workers/providers/gmail-client");
		expect(await getProfile("tok")).toEqual({ emailAddress: "u@t.example", historyId: "4711" });
	});
});

describe("listNewMessageIds", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("collects messagesAdded across pages, skipping DRAFT/SENT/CHAT, deduped", async () => {
		let page = 0;
		vi.stubGlobal("fetch", gmailDispatcher({
			"/history": (u) => {
				expect(u.searchParams.get("startHistoryId")).toBe("100");
				expect(u.searchParams.get("historyTypes")).toBe("messageAdded");
				expect(u.searchParams.get("labelId")).toBe("INBOX");
				page += 1;
				if (page === 1) {
					return new Response(JSON.stringify({
						historyId: "200",
						nextPageToken: "p2",
						history: [{ messagesAdded: [
							{ message: { id: "m1", labelIds: ["INBOX"] } },
							{ message: { id: "m2", labelIds: ["SENT"] } },
						] }],
					}), { status: 200 });
				}
				return new Response(JSON.stringify({
					historyId: "200",
					history: [{ messagesAdded: [
						{ message: { id: "m1", labelIds: ["INBOX"] } }, // dupe
						{ message: { id: "m3", labelIds: ["INBOX", "UNREAD"] } },
					] }],
				}), { status: 200 });
			},
		}));
		const { listNewMessageIds } = await import("../../workers/providers/gmail-client");
		const r = await listNewMessageIds("tok", "100");
		expect(r).toEqual({ ok: true, messageIds: ["m1", "m3"], historyId: "200", truncated: false });
	});

	it("reports truncated: true when the page cap is hit with a pending nextPageToken", async () => {
		let pages = 0;
		vi.stubGlobal("fetch", gmailDispatcher({
			"/history": () => {
				pages += 1;
				// Every page dangles a nextPageToken so the loop can only stop on
				// the page cap — never because the listing was exhausted.
				return new Response(JSON.stringify({
					historyId: "300",
					nextPageToken: `p${pages}`,
					history: [{ messagesAdded: [{ message: { id: `m${pages}`, labelIds: ["INBOX"] } }] }],
				}), { status: 200 });
			},
		}));
		const { listNewMessageIds } = await import("../../workers/providers/gmail-client");
		const r = await listNewMessageIds("tok", "100");
		expect(r).toEqual({ ok: true, messageIds: ["m1", "m2", "m3"], historyId: "300", truncated: true });
		expect(pages).toBe(3); // MAX_HISTORY_PAGES — the 4th page is never fetched
	});

	it("returns { ok: false, expired: true } on a 404 (cursor too old)", async () => {
		vi.stubGlobal("fetch", gmailDispatcher({
			"/history": () => new Response("Not Found", { status: 404 }),
		}));
		const { listNewMessageIds } = await import("../../workers/providers/gmail-client");
		expect(await listNewMessageIds("tok", "1")).toEqual({ ok: false, expired: true });
	});

	it("returns an empty list when the history response has no history key", async () => {
		vi.stubGlobal("fetch", gmailDispatcher({
			"/history": () => new Response(JSON.stringify({ historyId: "150" }), { status: 200 }),
		}));
		const { listNewMessageIds } = await import("../../workers/providers/gmail-client");
		expect(await listNewMessageIds("tok", "100")).toEqual({ ok: true, messageIds: [], historyId: "150", truncated: false });
	});
});

describe("getRawMessage", () => {
	afterEach(() => vi.unstubAllGlobals());
	it("decodes the base64url raw payload to bytes", async () => {
		const raw = "Subject: hi\r\n\r\nbody";
		const b64 = btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
		vi.stubGlobal("fetch", gmailDispatcher({
			"/messages/m1": (u) => {
				expect(u.searchParams.get("format")).toBe("raw");
				return new Response(JSON.stringify({ id: "m1", raw: b64 }), { status: 200 });
			},
		}));
		const { getRawMessage } = await import("../../workers/providers/gmail-client");
		const bytes = await getRawMessage("tok", "m1");
		expect(new TextDecoder().decode(bytes)).toBe(raw);
	});
});

describe("ensureLabels", () => {
	afterEach(() => vi.unstubAllGlobals());
	it("returns the cache when it already covers every name (no fetch)", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("must not fetch"); }));
		const { ensureLabels } = await import("../../workers/providers/gmail-client");
		const cached = { "PhishPilot/Allow": "L1", "PhishPilot/Suspicious": "L2", "PhishPilot/Quarantine": "L3" };
		expect(await ensureLabels("tok", Object.keys(cached), cached)).toEqual(cached);
	});
	it("lists existing labels and creates only the missing ones", async () => {
		const created: string[] = [];
		vi.stubGlobal("fetch", gmailDispatcher({
			"/labels": async (u, init) => {
				if (init?.method === "POST") {
					const body = JSON.parse(String(init.body)) as { name: string };
					created.push(body.name);
					return new Response(JSON.stringify({ id: `NEW-${body.name}`, name: body.name }), { status: 200 });
				}
				return new Response(JSON.stringify({ labels: [{ id: "L1", name: "PhishPilot/Allow" }, { id: "X", name: "INBOX" }] }), { status: 200 });
			},
		}));
		const { ensureLabels } = await import("../../workers/providers/gmail-client");
		const map = await ensureLabels("tok", ["PhishPilot/Allow", "PhishPilot/Quarantine"], null);
		expect(map["PhishPilot/Allow"]).toBe("L1");
		expect(map["PhishPilot/Quarantine"]).toBe("NEW-PhishPilot/Quarantine");
		expect(created).toEqual(["PhishPilot/Quarantine"]);
	});
});

describe("modifyMessage", () => {
	afterEach(() => vi.unstubAllGlobals());
	it("POSTs addLabelIds/removeLabelIds and throws GmailApiError on failure", async () => {
		let body: unknown;
		vi.stubGlobal("fetch", gmailDispatcher({
			"/messages/m1/modify": async (_u, init) => {
				body = JSON.parse(String(init?.body));
				return new Response("{}", { status: 200 });
			},
		}));
		const { modifyMessage } = await import("../../workers/providers/gmail-client");
		await modifyMessage("tok", "m1", ["L3"], ["INBOX"]);
		expect(body).toEqual({ addLabelIds: ["L3"], removeLabelIds: ["INBOX"] });

		vi.stubGlobal("fetch", gmailDispatcher({
			"/messages/m1/modify": () => new Response("denied", { status: 403 }),
		}));
		await expect(modifyMessage("tok", "m1", ["L3"], [])).rejects.toMatchObject({ status: 403 });
	});
});
