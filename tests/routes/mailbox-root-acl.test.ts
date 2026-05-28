// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Regression: GET/PUT on the exact `/api/v1/mailboxes/:mailboxId` path must
 * run requireMailbox. Hono's `/:mailboxId/*` wildcard does not match when
 * there is no trailing segment, which previously let any CF Access user read
 * or overwrite another mailbox's settings JSON.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { requireMailbox, type MailboxContext } from "../../workers/lib/mailbox";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";

function makeR2Stub(initial: Record<string, string> = {}) {
	const store = { ...initial };
	return {
		async head(key: string) {
			return store[key] !== undefined ? { key } : null;
		},
		async get(key: string) {
			const val = store[key];
			if (!val) return null;
			return { json: async <T>() => JSON.parse(val) as T };
		},
		async put(key: string, value: string) {
			store[key] = value;
		},
		_store: store,
	};
}

function makeRootMailboxApp(bucketStore: Record<string, string>, callerEmail: string | null) {
	const bucket = makeR2Stub(bucketStore);
	const MAILBOX = {
		idFromName: (_: string) => "fake-id",
		get: (_: unknown) => ({}),
	};

	const app = new Hono<MailboxContext>();
	app.use("/api/v1/mailboxes/:mailboxId", requireMailbox as Parameters<typeof app.use>[1]);
	app.use("/api/v1/mailboxes/:mailboxId/*", requireMailbox as Parameters<typeof app.use>[1]);

	app.get("/api/v1/mailboxes/:mailboxId", async (c) => {
		const mailboxId = c.req.param("mailboxId")!;
		const obj = await c.env.BUCKET.get(`mailboxes/${mailboxId}.json`);
		if (!obj) return c.json({ error: "Not found" }, 404);
		return c.json({ id: mailboxId, settings: await obj.json() });
	});

	app.put("/api/v1/mailboxes/:mailboxId", async (c) => {
		const mailboxId = c.req.param("mailboxId")!;
		const body = (await c.req.json()) as { settings?: unknown };
		const key = `mailboxes/${mailboxId}.json`;
		if (!(await c.env.BUCKET.head(key))) return c.json({ error: "Not found" }, 404);
		await c.env.BUCKET.put(key, JSON.stringify(body.settings ?? {}));
		return c.json({ id: mailboxId });
	});

	return {
		fetch(path: string, options?: RequestInit) {
			const hdrs = new Headers(options?.headers);
			if (callerEmail) hdrs.set("cf-access-authenticated-user-email", callerEmail);
			return app.request(path, { ...options, headers: hdrs }, {
				BUCKET: bucket as unknown as R2Bucket,
				MAILBOX: MAILBOX as unknown as DurableObjectNamespace,
			});
		},
		bucket,
	};
}

const mailboxId = "alice@example.com";
const mailboxKey = `mailboxes/${mailboxId}.json`;
const aclKey = `mailboxes-acl/${mailboxId}.json`;
const aliceAcl: MailboxAcl = {
	owner: "alice@example.com",
	members: ["alice@example.com"],
};

describe("mailbox root path — requireMailbox on exact :mailboxId", () => {
	it("GET returns 403 for a caller not in the scoped ACL", async () => {
		const store = {
			[mailboxKey]: JSON.stringify({ agentModel: "gpt-4" }),
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const { fetch } = makeRootMailboxApp(store, "eve@example.com");
		const res = await fetch(`/api/v1/mailboxes/${mailboxId}`);
		expect(res.status).toBe(403);
	});

	it("GET returns settings for an ACL member", async () => {
		const store = {
			[mailboxKey]: JSON.stringify({ agentModel: "gpt-4" }),
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const { fetch } = makeRootMailboxApp(store, "alice@example.com");
		const res = await fetch(`/api/v1/mailboxes/${mailboxId}`);
		expect(res.status).toBe(200);
		const body = await res.json() as { settings: { agentModel: string } };
		expect(body.settings.agentModel).toBe("gpt-4");
	});

	it("PUT returns 403 for a caller not in the scoped ACL", async () => {
		const store = {
			[mailboxKey]: JSON.stringify({ agentModel: "gpt-4" }),
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const { fetch, bucket } = makeRootMailboxApp(store, "eve@example.com");
		const res = await fetch(`/api/v1/mailboxes/${mailboxId}`, {
			method: "PUT",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ settings: { agentModel: "hacked" } }),
		});
		expect(res.status).toBe(403);
		expect(JSON.parse(bucket._store[mailboxKey]).agentModel).toBe("gpt-4");
	});
});
