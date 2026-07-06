// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sidecar operator endpoints (issue #31). Mounted under
 * /api/v1/mailboxes/:mailboxId/sidecar — behind the same CF Access + ACL
 * middleware as every other mailbox-scoped route (mount order in
 * workers/index.ts is the guarantee; keep this mount adjacent to `cases`).
 *
 * POST /test — resolve the sidecar config, mint a DWD token, call
 * users.getProfile, and report exactly which stage failed. Never persists
 * anything; safe to call repeatedly from the settings UI.
 */

import { Hono } from "hono";
import { requireMailbox, type MailboxContext } from "../lib/mailbox";
import { sidecarConfigOf } from "../lib/sidecar-config";
import { getMailboxSettings } from "../lib/mailbox-settings";
import { GmailApiError, getProfile, mintAccessToken, parseServiceAccountJson } from "../providers/gmail-client";

export const sidecarRoutes = new Hono<MailboxContext>();

sidecarRoutes.use("*", requireMailbox);

sidecarRoutes.post("/test", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const raw = await getMailboxSettings(c.env, mailboxId).catch(() => null);
	const cfg = sidecarConfigOf(raw);
	if (!cfg) return c.json({ ok: false, stage: "config", error: "mailbox has no valid sidecar configuration" });

	const secret = (c.env as unknown as Record<string, unknown>)[cfg.credentials_secret_name];
	const sa = parseServiceAccountJson(secret);
	if (!sa) return c.json({ ok: false, stage: "secret", error: `worker secret ${cfg.credentials_secret_name} is unset or is not service-account JSON` });

	let token: string;
	try {
		token = (await mintAccessToken(sa, mailboxId)).token;
	} catch (e) {
		const detail = e instanceof GmailApiError ? `token exchange failed (HTTP ${e.status}) — check the DWD grant and scopes` : (e as Error).message;
		return c.json({ ok: false, stage: "auth", error: detail });
	}

	try {
		const profile = await getProfile(token);
		return c.json({ ok: true, emailAddress: profile.emailAddress, historyId: profile.historyId });
	} catch (e) {
		const detail = e instanceof GmailApiError ? `Gmail API error (HTTP ${e.status})` : (e as Error).message;
		return c.json({ ok: false, stage: "api", error: detail });
	}
});
