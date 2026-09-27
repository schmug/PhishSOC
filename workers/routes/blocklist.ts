// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Sender blocklist endpoints (spec 2026-09-27-sender-blocklist). These are
 * the ONLY writers of the top-level `blocklist` settings field; the general
 * settings PUTs preserve it. Every write runs stripDefaultEqual.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import { requireMailbox, type MailboxContext } from "../lib/mailbox";
import type { Env } from "../types";
import { validateBlockRuleInput, type BlockRule, type BlockRuleInput } from "../../shared/blocklist";
import { stripDefaultEqual } from "../lib/mailbox-settings";
import { getOrgSettings, putOrgSettings } from "../lib/org-settings";
import { getDomainSettings, putDomainSettings } from "../lib/domain-settings";
import { Folders } from "../../shared/folders";
import { getOwnedDomains } from "../providers/cf-routing";

export function appendRule(existing: readonly BlockRule[] | undefined, rule: Omit<BlockRule, "id" | "created_at">, now: string, id: string): BlockRule[] {
	const kept = (existing ?? []).filter((r) => r.match !== rule.match);
	return [...kept, { ...rule, id, created_at: now }];
}

async function parseRule(c: Context): Promise<{ ok: true; rule: Omit<BlockRule, "id" | "created_at">; body: BlockRuleInput & { move_existing?: boolean } } | { ok: false; res: Response }> {
	const body = (await c.req.json().catch(() => ({}))) as BlockRuleInput & { move_existing?: boolean };
	const v = validateBlockRuleInput(body);
	if (!v.ok) return { ok: false, res: c.json({ error: v.error, code: v.code }, 400) };
	return { ok: true, rule: v.rule, body };
}

// ── Mailbox tier ────────────────────────────────────────────────────
export const mailboxBlocklistRoutes = new Hono<MailboxContext>();
// Scoped to this router's own paths: mounted at /api/v1/mailboxes/:mailboxId,
// a "*" middleware would re-run the ACL check on every mailbox route.
mailboxBlocklistRoutes.use("/blocklist", requireMailbox);
mailboxBlocklistRoutes.use("/blocklist/*", requireMailbox);
mailboxBlocklistRoutes.use("/blocked-log", requireMailbox);

mailboxBlocklistRoutes.post("/blocklist", async (c) => {
	const mailboxId = decodeURIComponent(c.req.param("mailboxId")!);
	const parsed = await parseRule(c);
	if (!parsed.ok) return parsed.res;
	const key = `mailboxes/${mailboxId}.json`;
	const obj = await c.env.BUCKET.get(key);
	if (!obj) return c.json({ error: "Not found" }, 404);
	const current = (await obj.json().catch(() => ({}))) as Record<string, unknown> & { blocklist?: BlockRule[] };
	const blocklist = appendRule(current.blocklist, parsed.rule, new Date().toISOString(), crypto.randomUUID());
	await c.env.BUCKET.put(key, JSON.stringify(stripDefaultEqual({ ...current, blocklist })));
	const rule = blocklist[blocklist.length - 1];
	let moved = 0;
	if (parsed.body.move_existing) {
		moved = await (c.var.mailboxStub as any).moveEmailsFromSender(rule.match, Folders.SPAM);
	}
	return c.json({ rule, moved }, 201);
});

mailboxBlocklistRoutes.delete("/blocklist/:ruleId", async (c) => {
	const mailboxId = decodeURIComponent(c.req.param("mailboxId")!);
	const key = `mailboxes/${mailboxId}.json`;
	const obj = await c.env.BUCKET.get(key);
	if (!obj) return c.json({ error: "Not found" }, 404);
	const current = (await obj.json().catch(() => ({}))) as Record<string, unknown> & { blocklist?: BlockRule[] };
	const next = (current.blocklist ?? []).filter((r) => r.id !== c.req.param("ruleId"));
	if (next.length === (current.blocklist ?? []).length) return c.json({ error: "Rule not found" }, 404);
	await c.env.BUCKET.put(key, JSON.stringify(stripDefaultEqual({ ...current, blocklist: next })));
	return c.body(null, 204);
});

mailboxBlocklistRoutes.get("/blocked-log", async (c) => {
	const limit = Number.parseInt(c.req.query("limit") ?? "50", 10);
	const rows = await (c.var.mailboxStub as any).listBlockedLog(Number.isFinite(limit) ? limit : 50);
	return c.json({ rows });
});

// ── Org tier ────────────────────────────────────────────────────────
export const orgBlocklistRoutes = new Hono<{ Bindings: Env }>();

orgBlocklistRoutes.post("/", async (c) => {
	const parsed = await parseRule(c);
	if (!parsed.ok) return parsed.res;
	const current = await getOrgSettings(c.env);
	const blocklist = appendRule(current.blocklist, parsed.rule, new Date().toISOString(), crypto.randomUUID());
	await putOrgSettings(c.env, stripDefaultEqual({ ...current, blocklist }));
	return c.json({ rule: blocklist[blocklist.length - 1] }, 201);
});

orgBlocklistRoutes.delete("/:ruleId", async (c) => {
	const current = await getOrgSettings(c.env);
	const next = (current.blocklist ?? []).filter((r) => r.id !== c.req.param("ruleId"));
	if (next.length === (current.blocklist ?? []).length) return c.json({ error: "Rule not found" }, 404);
	await putOrgSettings(c.env, stripDefaultEqual({ ...current, blocklist: next }));
	return c.body(null, 204);
});

// ── Domain tier ─────────────────────────────────────────────────────
export const domainBlocklistRoutes = new Hono<{ Bindings: Env }>();

domainBlocklistRoutes.use("*", async (c, next) => {
	const domain = c.req.param("domain")!.toLowerCase();
	if (!(await getOwnedDomains(c.env)).includes(domain)) {
		return c.json({ error: "Domain is not in this org's domains; add it via POST /api/v1/org/domains first." }, 403);
	}
	await next();
});

domainBlocklistRoutes.post("/", async (c) => {
	const domain = c.req.param("domain")!.toLowerCase();
	const parsed = await parseRule(c);
	if (!parsed.ok) return parsed.res;
	const current = await getDomainSettings(c.env, domain);
	const blocklist = appendRule(current.blocklist, parsed.rule, new Date().toISOString(), crypto.randomUUID());
	await putDomainSettings(c.env, domain, stripDefaultEqual({ ...current, blocklist }));
	return c.json({ rule: blocklist[blocklist.length - 1] }, 201);
});

domainBlocklistRoutes.delete("/:ruleId", async (c) => {
	const domain = c.req.param("domain")!.toLowerCase();
	const current = await getDomainSettings(c.env, domain);
	const next = (current.blocklist ?? []).filter((r) => r.id !== c.req.param("ruleId"));
	if (next.length === (current.blocklist ?? []).length) return c.json({ error: "Rule not found" }, 404);
	await putDomainSettings(c.env, domain, stripDefaultEqual({ ...current, blocklist: next }));
	return c.body(null, 204);
});
