// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for issue #31 (Task 9): GET /api/v1/mailboxes gains a `sidecar`
 * flag and a `sidecar_health` object per mailbox, and GET
 * /api/v1/mailboxes/:mailboxId gains `sidecar_health` too. Exercises the
 * real production handlers in workers/index.ts (same pattern as
 * tests/routes/honeypots.test.ts) rather than a hand-rolled mirror, so a
 * regression in the actual annotation code is caught here.
 */

import { describe, expect, it } from "vitest";
import { app } from "../../workers/index";

/** Minimal in-memory R2 supporting head/get/put/list. */
function makeR2(initial: Record<string, string> = {}) {
	const store = new Map<string, string>(Object.entries(initial));
	return {
		store,
		async head(key: string) {
			return store.has(key) ? { key } : null;
		},
		async get(key: string) {
			if (!store.has(key)) return null;
			const val = store.get(key)!;
			return { etag: "etag-1", async json() { return JSON.parse(val); } };
		},
		async put(key: string, val: string) {
			store.set(key, val);
		},
		async delete(key: string | string[]) {
			for (const k of Array.isArray(key) ? key : [key]) store.delete(k);
		},
		async list({ prefix }: { prefix: string }) {
			return {
				objects: [...store.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key })),
			};
		},
	};
}

function makeMailboxNs(sidecarStates: Record<string, unknown> = {}) {
	return {
		idFromName: (n: string) => ({ toString: () => n }),
		get: (id: { toString: () => string }) => ({
			async getSidecarState() {
				const id_ = id.toString();
				return sidecarStates[id_] ?? null;
			},
			async getFolders() {
				return [];
			},
		}),
	};
}

const sidecarBlock = {
	sidecar: { provider: "workspace", credentials_secret_name: "SIDECAR_SECRET_x" },
};

describe("GET /api/v1/mailboxes — sidecar annotation (#31)", () => {
	it("marks a plain mailbox sidecar:false with null health", async () => {
		const bucket = makeR2({
			"org/settings.json": JSON.stringify({}),
			"mailboxes/plain@acme.example.json": JSON.stringify({}),
		});
		const env = {
			BUCKET: bucket,
			MAILBOX: makeMailboxNs(),
		} as unknown as Parameters<typeof app.request>[2];

		const res = await app.request("/api/v1/mailboxes", {}, env);
		expect(res.status).toBe(200);
		const body = (await res.json()) as Array<{ id: string; sidecar: boolean; sidecar_health: unknown }>;
		const m = body.find((x) => x.id === "plain@acme.example");
		expect(m?.sidecar).toBe(false);
		expect(m?.sidecar_health).toBeNull();
	});

	it("marks a sidecar mailbox sidecar:true and healthy:true when never polled", async () => {
		const bucket = makeR2({
			"org/settings.json": JSON.stringify({}),
			"mailboxes/side@acme.example.json": JSON.stringify(sidecarBlock),
		});
		const env = {
			BUCKET: bucket,
			MAILBOX: makeMailboxNs({ "side@acme.example": null }),
		} as unknown as Parameters<typeof app.request>[2];

		const res = await app.request("/api/v1/mailboxes", {}, env);
		expect(res.status).toBe(200);
		const body = (await res.json()) as Array<{
			id: string;
			sidecar: boolean;
			sidecar_health: { healthy: boolean; last_poll_at: number | null; last_error: string | null } | null;
		}>;
		const m = body.find((x) => x.id === "side@acme.example");
		expect(m?.sidecar).toBe(true);
		expect(m?.sidecar_health).toEqual({ healthy: true, last_poll_at: null, last_error: null });
	});

	it("marks a sidecar mailbox unhealthy after 3+ consecutive failures", async () => {
		const bucket = makeR2({
			"org/settings.json": JSON.stringify({}),
			"mailboxes/side@acme.example.json": JSON.stringify(sidecarBlock),
		});
		const env = {
			BUCKET: bucket,
			MAILBOX: makeMailboxNs({
				"side@acme.example": { consecutive_failures: 3, last_poll_at: Date.now(), last_error: "token exchange failed" },
			}),
		} as unknown as Parameters<typeof app.request>[2];

		const res = await app.request("/api/v1/mailboxes", {}, env);
		const body = (await res.json()) as Array<{
			id: string;
			sidecar_health: { healthy: boolean; last_error: string | null } | null;
		}>;
		const m = body.find((x) => x.id === "side@acme.example");
		expect(m?.sidecar_health?.healthy).toBe(false);
		expect(m?.sidecar_health?.last_error).toBe("token exchange failed");
	});

	it("marks a sidecar mailbox unhealthy when the last poll is older than 15 minutes", async () => {
		const bucket = makeR2({
			"org/settings.json": JSON.stringify({}),
			"mailboxes/side@acme.example.json": JSON.stringify(sidecarBlock),
		});
		const staleTs = Date.now() - 16 * 60 * 1000;
		const env = {
			BUCKET: bucket,
			MAILBOX: makeMailboxNs({
				"side@acme.example": { consecutive_failures: 0, last_poll_at: staleTs, last_error: null },
			}),
		} as unknown as Parameters<typeof app.request>[2];

		const res = await app.request("/api/v1/mailboxes", {}, env);
		const body = (await res.json()) as Array<{ id: string; sidecar_health: { healthy: boolean } | null }>;
		const m = body.find((x) => x.id === "side@acme.example");
		expect(m?.sidecar_health?.healthy).toBe(false);
	});

	it("does not leak honeypot mailboxes even when they also carry a sidecar block", async () => {
		const bucket = makeR2({
			"org/settings.json": JSON.stringify({}),
			"mailboxes/hp@acme.example.json": JSON.stringify({ ...sidecarBlock, honeypot: { enabled: true } }),
		});
		const env = {
			BUCKET: bucket,
			MAILBOX: makeMailboxNs({ "hp@acme.example": null }),
		} as unknown as Parameters<typeof app.request>[2];

		const res = await app.request("/api/v1/mailboxes", {}, env);
		const body = (await res.json()) as Array<{ id: string }>;
		expect(body.find((x) => x.id === "hp@acme.example")).toBeUndefined();
	});
});

describe("POST /api/v1/mailboxes — sidecar block validation (#31)", () => {
	function makeEnv() {
		const bucket = makeR2({ "org/settings.json": JSON.stringify({}) });
		return {
			bucket,
			env: { BUCKET: bucket, MAILBOX: makeMailboxNs() } as unknown as Parameters<typeof app.request>[2],
		};
	}

	function post(env: Parameters<typeof app.request>[2], body: unknown) {
		return app.request(
			"/api/v1/mailboxes",
			{ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) },
			env,
		);
	}

	it("rejects a malformed sidecar block (bad secret-name prefix) with 400", async () => {
		const { env } = makeEnv();
		const res = await post(env, {
			name: "Side",
			email: "new@acme.example",
			settings: { sidecar: { provider: "workspace", credentials_secret_name: "WRONG_PREFIX_x" } },
		});
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toMatch(/sidecar/i);
	});

	it("creates a mailbox when the sidecar block is valid", async () => {
		const { env, bucket } = makeEnv();
		const res = await post(env, {
			name: "Side",
			email: "valid@acme.example",
			settings: { sidecar: { provider: "workspace", credentials_secret_name: "SIDECAR_SECRET_ok" } },
		});
		expect(res.status).toBe(201);
		expect(bucket.store.has("mailboxes/valid@acme.example.json")).toBe(true);
	});
});

describe("GET /api/v1/mailboxes/:mailboxId — sidecar_health (#31)", () => {
	it("returns sidecar_health: null for a plain mailbox", async () => {
		const bucket = makeR2({
			"org/settings.json": JSON.stringify({}),
			"mailboxes/plain@acme.example.json": JSON.stringify({}),
		});
		const env = {
			BUCKET: bucket,
			MAILBOX: makeMailboxNs(),
		} as unknown as Parameters<typeof app.request>[2];

		const res = await app.request("/api/v1/mailboxes/plain@acme.example", {}, env);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { sidecar_health: unknown };
		expect(body.sidecar_health).toBeNull();
	});

	it("returns sidecar_health with poll state for a sidecar-configured mailbox", async () => {
		const recentTs = Date.now() - 60_000; // 1 minute ago — within the 15-minute window
		const bucket = makeR2({
			"org/settings.json": JSON.stringify({}),
			"mailboxes/side@acme.example.json": JSON.stringify(sidecarBlock),
		});
		const env = {
			BUCKET: bucket,
			MAILBOX: makeMailboxNs({
				"side@acme.example": { consecutive_failures: 1, last_poll_at: recentTs, last_error: "temp" },
			}),
		} as unknown as Parameters<typeof app.request>[2];

		const res = await app.request("/api/v1/mailboxes/side@acme.example", {}, env);
		expect(res.status).toBe(200);
		const body = (await res.json()) as {
			sidecar_health: { healthy: boolean; last_poll_at: number | null; last_error: string | null };
		};
		expect(body.sidecar_health).toEqual({ healthy: true, last_poll_at: recentTs, last_error: "temp" });
	});

	it("returns sidecar_health with healthy:false when the last poll is stale", async () => {
		const staleTs = Date.now() - 16 * 60 * 1000;
		const bucket = makeR2({
			"org/settings.json": JSON.stringify({}),
			"mailboxes/side@acme.example.json": JSON.stringify(sidecarBlock),
		});
		const env = {
			BUCKET: bucket,
			MAILBOX: makeMailboxNs({
				"side@acme.example": { consecutive_failures: 0, last_poll_at: staleTs, last_error: null },
			}),
		} as unknown as Parameters<typeof app.request>[2];

		const res = await app.request("/api/v1/mailboxes/side@acme.example", {}, env);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { sidecar_health: { healthy: boolean } };
		expect(body.sidecar_health.healthy).toBe(false);
	});
});
