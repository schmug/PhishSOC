// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Case REST endpoints. Mounted under
 * `/api/v1/mailboxes/:mailboxId/cases`.
 *
 * The report-as-phish flow also triggers an optional hub push — see
 * `workers/intel/report.ts` + `workers/intel/misp-client.ts`. That's wired up
 * in M7 once the hub project exists; for now cases are local-only and
 * `shared_to_hub = 0`.
 */

import { Hono } from "hono";
import { z } from "zod";
import type { EmailFull } from "../lib/schemas";
import { requireMailbox, type MailboxContext } from "../lib/mailbox";
import { extractUrls } from "../security/urls";
import { stripHtmlToText } from "../lib/email-helpers";
import { buildMispEvent } from "../intel/report";
import { MispClient } from "../intel/misp-client";
import { loadHubConfig } from "../lib/hub-config";
import { callerEmailFromJwt } from "../lib/mailbox-acl";
import {
	ALLOWED_CATEGORIES,
	CATEGORY_PHISHING,
	getDomainSubmission,
	isBlockedDomain,
	isCategorizeConfigured,
	listCaseSubmissions,
	monthlyCap,
	monthlyCount,
	recordSubmission,
	registrableDomain,
	sendCategorization,
} from "../intel/cloudflare-categorize";

export const caseRoutes = new Hono<MailboxContext>();

caseRoutes.use("*", requireMailbox);

const CreateCaseBody = z.object({
	title: z.string().min(1).max(500),
	notes: z.string().optional(),
	emailId: z.string().optional(),
	observables: z.array(z.object({
		kind: z.string().min(1).max(32),
		value: z.string().min(1).max(500),
	})).optional(),
	// Per-case verdict score (issue #126). Optional on this generic
	// create path — `report-phish` derives it from the email's persisted
	// security_score automatically.
	score: z.number().int().min(0).max(100).nullable().optional(),
});

const UpdateCaseBody = z.object({
	status: z.enum(["open", "closed-tp", "closed-fp", "closed-dup"]).optional(),
	notes: z.string().optional(),
});

const SubmitCloudflareBody = z.object({
	domain: z.string().min(1).max(253),
	categoryId: z
		.number()
		.int()
		.refine((n) => (ALLOWED_CATEGORIES as readonly number[]).includes(n))
		.optional(),
});

const ReportPhishBody = z.object({ emailId: z.string().min(1) });

caseRoutes.get("/", async (c) => {
	const status = c.req.query("status") ?? undefined;
	const limit = Number(c.req.query("limit") ?? 50);
	const cases = await c.var.mailboxStub.listCases({ status, limit });
	return c.json({ cases });
});

caseRoutes.post("/", async (c) => {
	const parsed = CreateCaseBody.safeParse(await c.req.json().catch(() => null));
	if (!parsed.success) return c.json({ error: parsed.error.flatten() }, 400);
	const result = await c.var.mailboxStub.createCase(parsed.data);
	// Dispatch AI co-pilot summary generation in the background when the
	// case has a linked email (issue #127). createCase marks
	// summary_status='pending' on the row in the same transaction; this
	// `waitUntil` resolves it to 'ready' or 'failed'. Cases without a
	// linked email leave both summary columns NULL — the UI hides the card.
	if (parsed.data.emailId) {
		c.executionCtx.waitUntil(
			c.var.mailboxStub.generateCaseSummary(result.id),
		);
	}
	return c.json(result, 201);
});

caseRoutes.get("/:caseId", async (c) => {
	const caseData = await c.var.mailboxStub.getCase(c.req.param("caseId"));
	if (!caseData) return c.json({ error: "Not found" }, 404);

	// Expose aggregate confidence alongside score (issue #220). Confidence
	// is not a dedicated column — it lives in the persisted verdict JSON on
	// the originating email. Pull it from the first linked email's
	// security_verdict at read time so pre-#105 rows (no `confidence` field)
	// naturally fall back to null without any migration.
	let confidence: number | null = null;
	const firstEmailRef = caseData.emails?.[0];
	if (firstEmailRef) {
		const email = await c.var.mailboxStub.getEmail(firstEmailRef.email_id);
		if (email?.security_verdict) {
			try {
				const verdict = JSON.parse(email.security_verdict as string) as { confidence?: number };
				confidence = typeof verdict.confidence === "number" ? verdict.confidence : null;
			} catch {
				// malformed verdict JSON — confidence stays null
			}
		}
	}

	const cloudflare_submissions = await listCaseSubmissions(c.env.BLOOM_KV, c.req.param("caseId"));
	return c.json({
		case: {
			...caseData,
			confidence,
			cloudflare_submissions,
			cloudflare_submit_enabled: isCategorizeConfigured(c.env),
		},
	});
});

/**
 * Analyst-confirmed "Submit to Cloudflare" categorization (issue #755). Only
 * ever called from an explicit UI action; never from `report-phish`.
 */
caseRoutes.post("/:caseId/submit-cloudflare", async (c) => {
	if (!isCategorizeConfigured(c.env)) {
		return c.json({ error: "Cloudflare categorization is not configured" }, 501);
	}
	const kv = c.env.BLOOM_KV;
	if (!kv) return c.json({ error: "Cloudflare categorization is not configured" }, 501);

	const parsed = SubmitCloudflareBody.safeParse(await c.req.json().catch(() => null));
	if (!parsed.success) return c.json({ error: parsed.error.flatten() }, 400);
	const domain = registrableDomain(parsed.data.domain);
	if (!domain) return c.json({ error: "Not a valid domain" }, 400);

	const caseId = c.req.param("caseId");
	const caseData = await c.var.mailboxStub.getCase(caseId);
	if (!caseData) return c.json({ error: "Not found" }, 404);
	if (caseData.status !== "closed-tp") {
		return c.json({ error: "Only a confirmed-threat case can be submitted" }, 422);
	}
	const caseDomains = new Set(
		caseData.observables
			.filter((o: { kind: string }) => o.kind === "domain")
			.map((o: { value: string }) => registrableDomain(o.value)),
	);
	if (!caseDomains.has(domain)) {
		return c.json({ error: "Domain is not an observable of this case" }, 400);
	}

	if (isBlockedDomain(c.env, domain)) {
		return c.json({ error: "Shared-platform or high-value domains are never submitted" }, 422);
	}

	for (const ref of caseData.emails ?? []) {
		const email = (await c.var.mailboxStub.getEmail(ref.email_id)) as
			| { feedback?: { label?: string } | null }
			| null;
		if (email?.feedback?.label === "not_phish") {
			return c.json({ error: "A linked email is labeled Not phish" }, 422);
		}
	}

	if (await getDomainSubmission(kv, domain)) {
		return c.json({ error: "Domain already submitted" }, 409);
	}

	const now = new Date();
	if ((await monthlyCount(kv, now)) >= monthlyCap(c.env)) {
		return c.json({ error: "Monthly Cloudflare submission cap reached" }, 429);
	}

	const categoryId = parsed.data.categoryId ?? CATEGORY_PHISHING;
	if (!(await sendCategorization(c.env, domain, categoryId))) {
		return c.json({ error: "Cloudflare did not accept the request" }, 502);
	}

	const submission = {
		domain,
		case_id: caseId,
		analyst: callerEmailFromJwt(c.req.header("cf-access-jwt-assertion")) ?? "unknown",
		submitted_at: now.toISOString(),
		category_id: categoryId,
	};
	await recordSubmission(kv, submission, now);
	return c.json({ submission }, 201);
});

caseRoutes.patch("/:caseId", async (c) => {
	const parsed = UpdateCaseBody.safeParse(await c.req.json().catch(() => null));
	if (!parsed.success) return c.json({ error: parsed.error.flatten() }, 400);
	await c.var.mailboxStub.updateCase(c.req.param("caseId"), parsed.data);
	return c.json({ ok: true });
});

caseRoutes.delete("/:caseId", async (c) => {
	await c.var.mailboxStub.deleteCase(c.req.param("caseId"));
	return c.json({ ok: true });
});

/**
 * Shortcut: take an email id, auto-extract observables, create a case.
 * The UI's "Report phish" button hits this endpoint.
 */
caseRoutes.post("/report-phish", async (c) => {
	const parsed = ReportPhishBody.safeParse(await c.req.json().catch(() => null));
	if (!parsed.success) return c.json({ error: parsed.error.flatten() }, 400);
	const { emailId } = parsed.data;

	const email = (await c.var.mailboxStub.getEmail(emailId)) as EmailFull | null;
	if (!email) return c.json({ error: "Email not found" }, 404);

	const urls = extractUrls(email.body || "");
	const observables: Array<{ kind: string; value: string }> = [];
	if (email.sender) observables.push({ kind: "email", value: email.sender });
	for (const u of urls) {
		observables.push({ kind: "url", value: u.url });
		observables.push({ kind: "domain", value: u.hostname });
	}

	// Pull the verdict score off the originating email — the security
	// pipeline persists `FinalVerdict.score` to `emails.security_score`
	// during ingest, so by the time the user hits "Report phish" it's
	// already on the row. Cast: EmailFull's `security_score` is nullable
	// number; `createCase` accepts `number | null`.
	const verdictScore =
		typeof (email as { security_score?: number | null }).security_score === "number"
			? (email as { security_score?: number | null }).security_score!
			: null;
	// Same plumbing for the per-stage trace (issue #128). Stored on the
	// email row as opaque JSON during ingest; copied verbatim to the
	// case row here so the case-detail timeline doesn't have to join
	// back to the email at render time.
	const stageTrace =
		typeof (email as { stage_trace?: string | null }).stage_trace === "string"
			? (email as { stage_trace?: string | null }).stage_trace!
			: null;
	// Aggregate pipeline confidence (issue #224). Stored in the
	// security_verdict JSON as FinalVerdict.confidence; extract it here
	// so the case row carries the value without a join at render time.
	const verdictJson = (email as { security_verdict?: string | null }).security_verdict;
	let verdictConfidence: number | null = null;
	if (typeof verdictJson === "string") {
		try {
			const parsed = JSON.parse(verdictJson) as { confidence?: unknown };
			if (typeof parsed?.confidence === "number") {
				verdictConfidence = parsed.confidence;
			}
		} catch {
			// malformed JSON — leave confidence null
		}
	}
	const { id } = await c.var.mailboxStub.createCase({
		title: `Reported phish: ${email.subject || "(no subject)"}`,
		notes: `Reported from email ${emailId}. Sender: ${email.sender}.`,
		emailId,
		observables,
		score: verdictScore,
		stage_trace: stageTrace,
		confidence: verdictConfidence,
	});

	// Async AI co-pilot summary generation (issue #127). createCase
	// marked summary_status='pending'; this waitUntil-dispatched task
	// resolves it to 'ready' or 'failed' so the case-detail page can
	// poll while the analyst is reviewing the case.
	c.executionCtx.waitUntil(c.var.mailboxStub.generateCaseSummary(id));

	// Reputation penalty on the sender so the pipeline flags future mail.
	if (email.sender) {
		await c.var.mailboxStub.flagSender(email.sender, true).catch(() => {});
	}

	// Optional push to the community hub. Mailbox must opt in via
	// `intel.hub.auto_report = true` and configure hub credentials.
	let hubUuid: string | null = null;
	try {
		const mailboxId = c.req.param("mailboxId");
		if (mailboxId) {
			const hub = await loadHubConfig(c.env, mailboxId);
			if (hub?.auto_report) {
				const apiKey = (c.env as unknown as Record<string, string | undefined>)[hub.api_key_secret_name];
				if (apiKey) {
					const event = await buildMispEvent({
						orgUuid: hub.org_uuid,
						sharingGroupUuid: hub.default_sharing_group_uuid,
						info: email.subject || "Reported phish",
						observedAt: email.date,
						sender: email.sender,
						subject: email.subject || "",
						bodyText: stripHtmlToText(email.body || "").slice(0, 10_000),
						urls: urls.map((u) => ({ url: u.url, hostname: u.hostname })),
					});
					const client = new MispClient({ baseUrl: hub.url, apiKey });
					const posted = await client.postEvent(event);
					if (posted?.uuid) {
						hubUuid = posted.uuid;
						await c.var.mailboxStub.updateCase(id, {
							shared_to_hub: true,
							hub_event_uuid: posted.uuid,
						});
					}
				}
			}
		}
	} catch (e) {
		console.error("hub report failed:", (e as Error).message);
	}

	return c.json({ caseId: id, hubEventUuid: hubUuid }, 201);
});
