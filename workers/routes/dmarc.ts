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
	const records = await c.var.mailboxStub.getDmarcRecords(reportId);
	return c.json({ records });
});

dmarcRoutes.get("/summary", async (c) => {
	const domain = c.req.query("domain");
	if (!domain) return c.json({ error: "domain query param required" }, 400);
	const summary = await c.var.mailboxStub.getDmarcSummary(domain);
	return c.json({ domain, sources: summary });
});

/**
 * Cross-domain DMARC RUA rollup (#383).
 *
 * Returns per-domain alignment totals aggregated from ingested
 * dmarc_reports/dmarc_records — distinct from the posture-based
 * comparison in #141 which uses live DoH lookups.
 *
 * Query params:
 *   - since  ISO-8601 lower bound (defaults to 90 days ago in the DO)
 *
 * Response: { rollup: Array<{ domain, total, aligned, failing }> }
 *   sorted by failing count desc (worst-alignment domain first).
 */
dmarcRoutes.get("/rollup", async (c) => {
	const since = c.req.query("since") ?? undefined;
	const rollup = await c.var.mailboxStub.getDmarcCrossDomainRollup(since);
	return c.json({ rollup });
});
