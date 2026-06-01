// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * DMARC dashboard REST endpoints. Mounted under
 * `/api/v1/mailboxes/:mailboxId/dmarc`.
 */

import { Hono } from "hono";
import { requireMailbox, type MailboxContext } from "../lib/mailbox";

export const dmarcRoutes = new Hono<MailboxContext>();

dmarcRoutes.use("*", requireMailbox);

dmarcRoutes.get("/reports", async (c) => {
	const domain = c.req.query("domain") ?? undefined;
	const limit = Number(c.req.query("limit") ?? 50);
	const offset = Number(c.req.query("offset") ?? 0);
	const reports = await c.var.mailboxStub.listDmarcReports({ domain, limit, offset });
	return c.json({ reports });
});

dmarcRoutes.get("/reports/:reportId/records", async (c) => {
	const reportId = c.req.param("reportId");
	const raw = await c.var.mailboxStub.getDmarcRecords(reportId);
	const records = raw.map((r) => {
		const { auth_results_json, ...rest } = r as typeof r & { auth_results_json?: string | null };
		let auth_results: unknown = null;
		if (auth_results_json) {
			try { auth_results = JSON.parse(auth_results_json); } catch { /* malformed — leave null */ }
		}
		return { ...rest, auth_results };
	});
	return c.json({ records });
});

const DMARC_SUMMARY_DEFAULT_DAYS = 90;
const DMARC_SUMMARY_MAX_DAYS = 365;

dmarcRoutes.get("/summary", async (c) => {
	const domain = c.req.query("domain");
	if (!domain) return c.json({ error: "domain query param required" }, 400);
	const rawDays = Number(c.req.query("days") ?? DMARC_SUMMARY_DEFAULT_DAYS);
	const days = Math.min(Math.max(Number.isFinite(rawDays) ? rawDays : DMARC_SUMMARY_DEFAULT_DAYS, 1), DMARC_SUMMARY_MAX_DAYS);
	const sinceIso = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
	const summary = await c.var.mailboxStub.getDmarcSummary(domain, sinceIso);
	return c.json({ domain, sources: summary });
});

const ROLLUP_MAX_DAYS = 365;
const ROLLUP_DEFAULT_DAYS = 90;

dmarcRoutes.get("/rollup", async (c) => {
	const rawDays = Number(c.req.query("days") ?? ROLLUP_DEFAULT_DAYS);
	const days = Number.isFinite(rawDays) && rawDays > 0
		? Math.min(rawDays, ROLLUP_MAX_DAYS)
		: ROLLUP_DEFAULT_DAYS;
	const sinceIso = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
	const domains = await c.var.mailboxStub.getDmarcRollup(sinceIso);
	return c.json({ window_days: days, since: sinceIso, domains });
});

function isValidIp(ip: string): boolean {
	if (ip.length > 45) return false;
	if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
		return ip.split(".").every((o) => Number(o) <= 255);
	}
	return /^[0-9a-fA-F:.]{2,45}$/.test(ip) && ip.includes(":");
}

dmarcRoutes.patch("/sources/:sourceIp", async (c) => {
	const sourceIp = decodeURIComponent(c.req.param("sourceIp"));
	if (!isValidIp(sourceIp)) return c.json({ error: "invalid source_ip" }, 400);
	let body: unknown;
	try {
		body = await c.req.json();
	} catch {
		return c.json({ error: "invalid JSON body" }, 400);
	}
	if (typeof (body as { legitimate?: unknown }).legitimate !== "boolean") {
		return c.json({ error: "legitimate must be boolean" }, 400);
	}
	const { legitimate, notes } = body as { legitimate: boolean; notes?: string };
	await c.var.mailboxStub.setSourceLegitimate(sourceIp, legitimate, notes ?? null);
	return c.json({ ok: true });
});

dmarcRoutes.get("/timeseries", async (c) => {
	const domain = c.req.query("domain");
	if (!domain) return c.json({ error: "domain query param required" }, 400);
	const rawDays = Number(c.req.query("days") ?? DMARC_SUMMARY_DEFAULT_DAYS);
	const days = Math.min(Math.max(Number.isFinite(rawDays) ? rawDays : DMARC_SUMMARY_DEFAULT_DAYS, 1), DMARC_SUMMARY_MAX_DAYS);
	const sinceIso = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
	const timeseries = await c.var.mailboxStub.getDmarcTimeSeries(domain, sinceIso);
	return c.json({ domain, timeseries });
});
