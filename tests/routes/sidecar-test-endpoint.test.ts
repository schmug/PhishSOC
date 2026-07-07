// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for POST /api/v1/mailboxes/:mailboxId/sidecar/test (issue #31,
 * Task 9). The endpoint resolves the sidecar config, mints a DWD token,
 * and calls users.getProfile — reporting exactly which stage failed.
 * Always 200 (even on failure) so the settings UI can render the stage;
 * see workers/routes/sidecar.ts for the stage taxonomy.
 *
 * Scaffolding mirrors tests/routes/dmarc-rollup.test.ts: requireMailbox is
 * mocked to a no-op so the route runs without a real ACL/DO round-trip,
 * and a minimal in-memory BUCKET stub backs getMailboxSettings.
 */

import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../../workers/lib/mailbox", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/mailbox")>();
	return {
		...original,
		requireMailbox: createMiddleware(async (_c, next) => {
			await next();
		}),
	};
});

import { sidecarRoutes } from "../../workers/routes/sidecar";
import type { MailboxContext } from "../../workers/lib/mailbox";
import { makeTestServiceAccount } from "../providers/helpers";

function makeBucket(store: Record<string, string>) {
	return {
		async get(key: string) {
			const val = store[key];
			if (val === undefined) return null;
			return { json: async <T>() => JSON.parse(val) as T };
		},
		async head(key: string) {
			return store[key] !== undefined ? { key } : null;
		},
		async put(key: string, value: string) {
			store[key] = value;
		},
	};
}

function makeApp() {
	const app = new Hono<MailboxContext>();
	app.route("/api/v1/mailboxes/:mailboxId/sidecar", sidecarRoutes);
	return app;
}

async function request(
	app: Hono<MailboxContext>,
	path: string,
	env: Record<string, unknown>,
) {
	return app.request(
		`/api/v1/mailboxes/${path}`,
		{ method: "POST" },
		env as unknown as Parameters<typeof app.request>[2],
	);
}

const validSidecarBlock = {
	sidecar: {
		provider: "workspace",
		credentials_secret_name: "SIDECAR_SECRET_t",
	},
};

describe("POST /sidecar/test", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("returns ok:false stage:config when the mailbox has no sidecar block", async () => {
		const app = makeApp();
		const store = { "mailboxes/plain@t.example.json": "{}" };
		const res = await request(app, "plain@t.example/sidecar/test", {
			BUCKET: makeBucket(store),
		});
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ ok: false, stage: "config" });
	});

	it("returns ok:false stage:secret when the named secret is unset", async () => {
		const app = makeApp();
		const store = {
			"mailboxes/side@t.example.json": JSON.stringify(validSidecarBlock),
		};
		const res = await request(app, "side@t.example/sidecar/test", {
			BUCKET: makeBucket(store),
			// SIDECAR_SECRET_t intentionally absent from env.
		});
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ ok: false, stage: "secret" });
	});

	it("returns ok:false stage:auth when the token exchange is rejected", async () => {
		const { sa } = await makeTestServiceAccount();
		vi.stubGlobal(
			"fetch",
			vi.fn(async (url: string | URL) => {
				const u = new URL(String(url));
				if (u.hostname === "oauth2.googleapis.com") return new Response("denied", { status: 401 });
				throw new Error(`unexpected ${u.hostname}`);
			}),
		);
		const app = makeApp();
		const store = {
			"mailboxes/side@t.example.json": JSON.stringify(validSidecarBlock),
		};
		const res = await request(app, "side@t.example/sidecar/test", {
			BUCKET: makeBucket(store),
			SIDECAR_SECRET_t: JSON.stringify(sa),
		});
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ ok: false, stage: "auth" });
	});

	it("returns ok:false stage:api when getProfile fails after a successful token exchange", async () => {
		const { sa } = await makeTestServiceAccount();
		vi.stubGlobal(
			"fetch",
			vi.fn(async (url: string | URL) => {
				const u = new URL(String(url));
				if (u.hostname === "oauth2.googleapis.com") {
					return new Response(JSON.stringify({ access_token: "t", expires_in: 3600 }), { status: 200 });
				}
				if (u.hostname === "gmail.googleapis.com") return new Response("nope", { status: 403 });
				throw new Error(`unexpected ${u.hostname}`);
			}),
		);
		const app = makeApp();
		const store = {
			"mailboxes/side@t.example.json": JSON.stringify(validSidecarBlock),
		};
		const res = await request(app, "side@t.example/sidecar/test", {
			BUCKET: makeBucket(store),
			SIDECAR_SECRET_t: JSON.stringify(sa),
		});
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ ok: false, stage: "api" });
	});

	it("returns ok:true with profile fields when auth and getProfile succeed", async () => {
		const { sa } = await makeTestServiceAccount();
		vi.stubGlobal(
			"fetch",
			vi.fn(async (url: string | URL) => {
				const u = new URL(String(url));
				if (u.hostname === "oauth2.googleapis.com") {
					return new Response(JSON.stringify({ access_token: "t", expires_in: 3600 }), { status: 200 });
				}
				if (u.hostname === "gmail.googleapis.com") {
					return new Response(JSON.stringify({ emailAddress: "side@t.example", historyId: "42" }), { status: 200 });
				}
				throw new Error(`unexpected ${u.hostname}`);
			}),
		);
		const app = makeApp();
		const store = {
			"mailboxes/side@t.example.json": JSON.stringify(validSidecarBlock),
		};
		const res = await request(app, "side@t.example/sidecar/test", {
			BUCKET: makeBucket(store),
			SIDECAR_SECRET_t: JSON.stringify(sa),
		});
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true, emailAddress: "side@t.example", historyId: "42" });
	});
});
