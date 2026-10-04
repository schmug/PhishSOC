// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * "Not phish" feedback endpoint (issue #751). Mounted under
 * `/api/v1/mailboxes/:mailboxId/emails`. Records a durable false-positive
 * label in the mailbox Durable Object; it never changes the verdict,
 * score, sender reputation or any blocklist, and is never sent to the hub.
 */

import { Hono } from "hono";
import { requireMailbox, type MailboxContext } from "../lib/mailbox";

export const emailFeedbackRoutes = new Hono<MailboxContext>();

emailFeedbackRoutes.use("*", requireMailbox);

emailFeedbackRoutes.post("/:id/not-phish", async (c) => {
	const feedback = await c.var.mailboxStub.markNotPhish(c.req.param("id"));
	if (!feedback) return c.json({ error: "Email not found" }, 404);
	return c.json({ feedback });
});
