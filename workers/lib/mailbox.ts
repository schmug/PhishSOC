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
import { readMailboxAcl, callerInAcl, callerGroupsFromJwt } from "./mailbox-acl";

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

	const callerEmail = c.req.header("cf-access-authenticated-user-email") ?? null;
	// Groups sourced from the verified CF Access JWT (already checked by the global middleware).
	const callerGroups = callerGroupsFromJwt(c.req.header("cf-access-jwt-assertion"));
	const key = `mailboxes/${mailboxId}.json`;

	// Parallel: existence check + ACL read (#27)
	const [obj, acl] = await Promise.all([
		c.env.BUCKET.head(key),
		readMailboxAcl(c.env, mailboxId),
	]);

	if (!obj) return c.json({ error: "Not found" }, 404);
	if (!callerInAcl(acl, callerEmail, callerGroups)) return c.json({ error: "Forbidden" }, 403);

	const ns = c.env.MAILBOX;
	const id = ns.idFromName(mailboxId);
	const stub = ns.get(id);

	c.set("mailboxStub", stub);
	await next();
});
