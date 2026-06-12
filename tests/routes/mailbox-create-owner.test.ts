// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Owner-ACL bootstrap on mailbox creation (f17).
 *
 * POST /api/v1/mailboxes seeds `mailboxes-acl/<id>.json` with the creator as
 * owner. The owner identity MUST come from the `email` claim of the verified
 * `cf-access-jwt-assertion` token — never from the forgeable
 * `cf-access-authenticated-user-email` header (advisory finding f17).
 *
 * Same replica pattern as tests/routes/me.test.ts: the full
 * `workers/index.ts` graph needs live env bindings just to be evaluated, so
 * we mirror the owner-bootstrap section of the production handler here.
 * Keep in sync with POST /api/v1/mailboxes in workers/index.ts.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { writeMailboxAcl, callerEmailFromJwt } from "../../workers/lib/mailbox-acl";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";

// Helper: build a fake (unsigned) JWT carrying arbitrary claims.
function makeFakeJwt(claims: Record<string, unknown>): string {
	const b64url = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
	return `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify(claims))}.`;
}

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
		async delete(key: string) {
			delete store[key];
		},
		_store: store,
	};
}

function makeCreateApp(bucketStore: Record<string, string> = {}) {
	const bucket = makeR2Stub(bucketStore);
	const app = new Hono<{ Bindings: { BUCKET: R2Bucket } }>();

	app.post("/api/v1/mailboxes", async (c) => {
		const { email: rawEmail } = (await c.req.json()) as { email: string };
		const email = rawEmail.toLowerCase();
		const key = `mailboxes/${email}.json`;
		if (await c.env.BUCKET.head(key)) return c.json({ error: "Mailbox already exists" }, 409);
		await c.env.BUCKET.put(key, "{}");

		// Mirror of the production owner bootstrap in workers/index.ts (f17).
		// Keep in sync: owner identity from the VERIFIED JWT, never the header.
		const creatorEmail = callerEmailFromJwt(c.req.header("cf-access-jwt-assertion"));
		if (creatorEmail) {
			const owner = creatorEmail.toLowerCase();
			await writeMailboxAcl(c.env, email, { owner, members: [owner] });
		}

		return c.json({ id: email, email }, 201);
	});

	return {
		create(email: string, headers: Record<string, string> = {}) {
			return app.request(
				"/api/v1/mailboxes",
				{
					method: "POST",
					headers: { "Content-Type": "application/json", ...headers },
					body: JSON.stringify({ email }),
				},
				{ BUCKET: bucket as unknown as R2Bucket },
			);
		},
		bucket,
	};
}

const newMailbox = "team@example.com";
const newAclKey = `mailboxes-acl/${newMailbox}.json`;

describe("POST /api/v1/mailboxes — owner ACL from the verified JWT (f17)", () => {
	it("sets the ACL owner from the JWT email claim", async () => {
		const { create, bucket } = makeCreateApp();
		const res = await create(newMailbox, {
			"cf-access-jwt-assertion": makeFakeJwt({ email: "Creator@Example.com" }),
		});
		expect(res.status).toBe(201);
		const stored = JSON.parse(bucket._store[newAclKey]) as MailboxAcl;
		expect(stored.owner).toBe("creator@example.com");
		expect(stored.members).toEqual(["creator@example.com"]);
	});

	it("ignores a forged cf-access-authenticated-user-email header — JWT email wins", async () => {
		const { create, bucket } = makeCreateApp();
		const res = await create(newMailbox, {
			"cf-access-jwt-assertion": makeFakeJwt({ email: "creator@example.com" }),
			"cf-access-authenticated-user-email": "mallory@example.com",
		});
		expect(res.status).toBe(201);
		const stored = JSON.parse(bucket._store[newAclKey]) as MailboxAcl;
		expect(stored.owner).toBe("creator@example.com");
		expect(stored.members).not.toContain("mallory@example.com");
	});

	it("does not seed an ACL from a forged header when the JWT has no email claim", async () => {
		const { create, bucket } = makeCreateApp();
		const res = await create(newMailbox, {
			"cf-access-jwt-assertion": makeFakeJwt({ common_name: "svc-token" }),
			"cf-access-authenticated-user-email": "mallory@example.com",
		});
		expect(res.status).toBe(201);
		// No identity → no owner ACL (dev / pre-#27 backwards-compat path).
		expect(bucket._store[newAclKey]).toBeUndefined();
	});
});
