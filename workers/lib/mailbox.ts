// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Hono middleware to handle repetitive Mailbox Durable Object instantiation.
 * Checks if the mailbox exists in R2, then instantiates the DO stub
 * and attaches it to the Hono context (`c.var.mailboxStub`).
 */
import { createMiddleware } from "hono/factory";
import type { MailboxDO } from "../durableObject";
import type { Env } from "../types";
import {
	readMailboxAcl,
	callerInAcl,
	callerGroupsFromJwt,
	callerEmailFromJwt,
} from "./mailbox-acl";

export type MailboxContext = {
	Bindings: Env;
	Variables: {
		mailboxStub: DurableObjectStub<MailboxDO>;
	};
};

export const requireMailbox = createMiddleware<MailboxContext>(async (c, next) => {
	const rawId = c.req.param("mailboxId");
	if (!rawId) return c.json({ error: "Mailbox ID required" }, 400);
	const mailboxId = decodeURIComponent(rawId);

	// Identity and groups sourced from the VERIFIED CF Access JWT (signature
	// already checked by the global middleware in workers/app.ts) — never from
	// the cf-access-authenticated-user-email header, which is decoupled from
	// the token and forgeable on a direct-to-origin request (f17).
	const jwtToken = c.req.header("cf-access-jwt-assertion");
	const callerEmail = callerEmailFromJwt(jwtToken);
	const callerGroups = callerGroupsFromJwt(jwtToken);
	const key = `mailboxes/${mailboxId}.json`;

	// Parallel: existence check + ACL read (#27)
	const [obj, acl] = await Promise.all([
		c.env.BUCKET.head(key),
		readMailboxAcl(c.env, mailboxId),
	]);

	if (!obj) return c.json({ error: "Not found" }, 404);
	// Fail closed in production when no JWT email is present (f17); local dev
	// (no CF Access in front → no token) keeps the legacy allow.
	if (!callerInAcl(acl, callerEmail, callerGroups, import.meta.env.DEV)) {
		return c.json({ error: "Forbidden" }, 403);
	}

	const ns = c.env.MAILBOX;
	const id = ns.idFromName(mailboxId);
	const stub = ns.get(id);

	c.set("mailboxStub", stub);
	await next();
});
