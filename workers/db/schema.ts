// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { sqliteTable, text, integer, real, primaryKey } from "drizzle-orm/sqlite-core";

export const folders = sqliteTable("folders", {
	id: text("id").primaryKey(),
	name: text("name").notNull().unique(),
	is_deletable: integer("is_deletable").notNull().default(1),
});

export const emails = sqliteTable("emails", {
	id: text("id").primaryKey(),
	folder_id: text("folder_id")
		.notNull()
		.references(() => folders.id, { onDelete: "cascade" }),
	subject: text("subject"),
	sender: text("sender"),
	recipient: text("recipient"),
	cc: text("cc"),
	bcc: text("bcc"),
	date: text("date"),
	read: integer("read").default(0),
	starred: integer("starred").default(0),
	body: text("body"),
	in_reply_to: text("in_reply_to"),
	email_references: text("email_references"),
	thread_id: text("thread_id"),
	message_id: text("message_id"),
	raw_headers: text("raw_headers"),
	security_verdict: text("security_verdict"),
	security_score: integer("security_score"),
	security_explanation: text("security_explanation"),
	// Per-stage pipeline trace (issue #128). JSON array of StageRecord
	// (see workers/security/stage-trace.ts) captured during
	// `runSecurityPipeline`, persisted alongside the verdict so the
	// originating email always carries the breakdown the case-detail
	// timeline renders. NULL when the pipeline didn't run for the
	// message (security disabled for the mailbox, ingest predates this
	// migration, or pipeline threw before persistence).
	stage_trace: text("stage_trace"),
	deep_scan_status: text("deep_scan_status").default("pending"),
	// Inline-gateway relay outcome (issue #32): "relayed" | "held" |
	// "failed"; NULL when the domain has no relay policy (or ingest
	// predates the gateway feature).
	relay_status: text("relay_status"),
	created_by: text("created_by").default("user"),
});

export const attachments = sqliteTable("attachments", {
	id: text("id").primaryKey(),
	email_id: text("email_id")
		.notNull()
		.references(() => emails.id, { onDelete: "cascade" }),
	filename: text("filename").notNull(),
	mimetype: text("mimetype").notNull(),
	size: integer("size").notNull(),
	content_id: text("content_id"),
	disposition: text("disposition"),
	scan_status: text("scan_status").default("pending"),
	scan_verdict: text("scan_verdict"),
});

// ── Security ─────────────────────────────────────────────────────

export const urls = sqliteTable("urls", {
	id: text("id").primaryKey(),
	email_id: text("email_id")
		.notNull()
		.references(() => emails.id, { onDelete: "cascade" }),
	url: text("url").notNull(),
	display_text: text("display_text"),
	is_homograph: integer("is_homograph").notNull().default(0),
	is_shortener: integer("is_shortener").notNull().default(0),
	resolved_url: text("resolved_url"),
	page_title: text("page_title"),
	fetch_status: text("fetch_status").default("pending"),
	verdict: text("verdict"),
	created_at: text("created_at").notNull().default("CURRENT_TIMESTAMP"),
});

// One row per `runSecurityPipeline` invocation that actually ran (skipped
// invocations — security disabled for the mailbox — are not recorded).
// Powers the dashboard's real p95-latency card. `stage_failed` is non-null
// only when `status = "failed"`. Per-stage timing breakdown is intentionally
// out of scope (see #71).
export const pipelineRuns = sqliteTable("pipeline_runs", {
	id: text("id").primaryKey(),
	email_id: text("email_id")
		.notNull()
		.references(() => emails.id, { onDelete: "cascade" }),
	started_at: text("started_at").notNull(),
	completed_at: text("completed_at"),
	status: text("status").notNull(),
	duration_ms: integer("duration_ms"),
	stage_failed: text("stage_failed"),
});

export const senderReputation = sqliteTable("sender_reputation", {
	sender: text("sender").primaryKey(),
	first_seen: text("first_seen").notNull(),
	last_seen: text("last_seen").notNull(),
	message_count: integer("message_count").notNull().default(1),
	avg_score: real("avg_score").notNull().default(50.0),
	flagged: integer("flagged").notNull().default(0),
});

// Per-mailbox sender graph for BEC / display-name impersonation detection
// (issue #26). Each row records how many times a given display name was
// seen arriving from a particular email address. The detector flags when a
// new address claims a display name that already has history from different
// addresses.
export const senderGraph = sqliteTable(
	"sender_graph",
	{
		sender_name: text("sender_name").notNull(),
		sender_address: text("sender_address").notNull(),
		message_count: integer("message_count").notNull().default(1),
		first_seen: text("first_seen").notNull(),
		last_seen: text("last_seen").notNull(),
	},
	(t) => ({
		pk: primaryKey({ columns: [t.sender_name, t.sender_address] }),
	}),
);

// ── Threat intel ─────────────────────────────────────────────────

export const intelFeedState = sqliteTable("intel_feed_state", {
	feed_id: text("feed_id").primaryKey(),
	url: text("url").notNull(),
	last_fetched_at: text("last_fetched_at"),
	etag: text("etag"),
	entry_count: integer("entry_count"),
	bloom_kv_key: text("bloom_kv_key"),
});

// ── DMARC ────────────────────────────────────────────────────────

export const dmarcReports = sqliteTable("dmarc_reports", {
	id: text("id").primaryKey(),
	received_at: text("received_at").notNull(),
	org_name: text("org_name"),
	report_id: text("report_id"),
	domain: text("domain").notNull(),
	date_range_begin: text("date_range_begin"),
	date_range_end: text("date_range_end"),
	policy_p: text("policy_p"),
	policy_adkim: text("policy_adkim"),
	policy_aspf: text("policy_aspf"),
	policy_sp: text("policy_sp"),
	policy_pct: text("policy_pct"),
	raw_r2_key: text("raw_r2_key"),
});

export const dmarcRecords = sqliteTable("dmarc_records", {
	id: text("id").primaryKey(),
	report_id: text("report_id")
		.notNull()
		.references(() => dmarcReports.id, { onDelete: "cascade" }),
	source_ip: text("source_ip").notNull(),
	count: integer("count").notNull(),
	disposition: text("disposition"),
	dkim_result: text("dkim_result"),
	spf_result: text("spf_result"),
	header_from: text("header_from"),
	auth_results_json: text("auth_results_json"),
});

export const dmarcSources = sqliteTable("dmarc_sources", {
	source_ip: text("source_ip").primaryKey(),
	label: text("label"),
	legitimate: integer("legitimate").notNull().default(0),
	notes: text("notes"),
	asn: text("asn"),
	country: text("country"),
});

// ── Cases (TheHive-lite) ─────────────────────────────────────────

export const cases = sqliteTable("cases", {
	id: text("id").primaryKey(),
	created_at: text("created_at").notNull().default("CURRENT_TIMESTAMP"),
	updated_at: text("updated_at").notNull().default("CURRENT_TIMESTAMP"),
	status: text("status").notNull().default("open"),
	title: text("title").notNull(),
	notes: text("notes"),
	shared_to_hub: integer("shared_to_hub").notNull().default(0),
	hub_event_uuid: text("hub_event_uuid"),
	// Per-case verdict score copied from the originating email's
	// FinalVerdict.score at case-creation time. Nullable: paths that
	// don't carry a scored verdict (manual API create without `score`,
	// or pre-#126 rows) leave it NULL.
	score: integer("score"),
	// AI-generated plain-language verdict-reasoning summary (issue #127).
	// `summary_status` tracks generation lifecycle: 'pending' while the
	// async waitUntil-dispatched task runs, 'ready' once persisted,
	// 'failed' on terminal error. NULL means no summary was ever
	// requested (manual API create with no linked email, or pre-#127
	// rows). The frontend hides the card when status is NULL.
	summary: text("summary"),
	summary_status: text("summary_status"),
	// Per-stage pipeline trace copied from the originating email at
	// case-creation time (issue #128). JSON array of StageRecord — see
	// workers/security/stage-trace.ts. NULL when the originating email
	// had no trace (pipeline disabled, manual API create with no linked
	// email, or pre-#128 rows). The frontend hides the timeline card
	// when this is NULL/empty.
	stage_trace: text("stage_trace"),
	// Aggregate pipeline confidence copied from FinalVerdict.confidence at
	// case-creation time (issue #224). NULL for old rows and manual API
	// creates; the frontend renders "—" in that case.
	confidence: real("confidence"),
});

export const caseEmails = sqliteTable(
	"case_emails",
	{
		case_id: text("case_id")
			.notNull()
			.references(() => cases.id, { onDelete: "cascade" }),
		email_id: text("email_id").notNull(),
	},
	(t) => ({
		pk: primaryKey({ columns: [t.case_id, t.email_id] }),
	}),
);

export const caseObservables = sqliteTable("case_observables", {
	id: text("id").primaryKey(),
	case_id: text("case_id")
		.notNull()
		.references(() => cases.id, { onDelete: "cascade" }),
	kind: text("kind").notNull(),
	value: text("value").notNull(),
});

// ── TLS-RPT (RFC 8460 inbound report ingestion) ──────────────────

export const tlsrptReports = sqliteTable("tlsrpt_reports", {
	id: text("id").primaryKey(),
	received_at: text("received_at").notNull(),
	org_name: text("org_name"),
	report_id: text("report_id"),
	domain: text("domain").notNull(),
	date_range_begin: text("date_range_begin"),
	date_range_end: text("date_range_end"),
	contact_info: text("contact_info"),
	raw_r2_key: text("raw_r2_key"),
});

// One row per (policy, optional failure-detail). The policy-summary row
// carries the per-policy success/failure totals from the report's
// `policies[].summary`; `sending_mta_ip`/`receiving_mx_hostname`/
// `result_type` are NULL on that row. Each entry under
// `policies[].failure-details` produces an additional row where those
// columns are populated and `failed_session_count` accounts for the
// failure breakdown. Sources rollups SUM across both row types.
export const tlsrptRecords = sqliteTable("tlsrpt_records", {
	id: text("id").primaryKey(),
	report_id: text("report_id")
		.notNull()
		.references(() => tlsrptReports.id, { onDelete: "cascade" }),
	policy_type: text("policy_type"),
	policy_domain: text("policy_domain"),
	sending_mta_ip: text("sending_mta_ip"),
	receiving_mx_hostname: text("receiving_mx_hostname"),
	result_type: text("result_type"),
	successful_session_count: integer("successful_session_count").notNull().default(0),
	failed_session_count: integer("failed_session_count").notNull().default(0),
});

// DMARC RUF forensic-report records (issue #171). One row per received
// forensic report. Ingested only when ruf_ingestion.enabled === true for
// the mailbox. `original_headers` is NULL when retain_raw === false (default).
export const dmarcRufRecords = sqliteTable("dmarc_ruf_records", {
	id: text("id").primaryKey(),
	received_at: text("received_at").notNull(),
	original_mail_from: text("original_mail_from"),
	source_ip: text("source_ip"),
	failure_type: text("failure_type"),
	reported_domain: text("reported_domain"),
	feedback_type: text("feedback_type"),
	auth_results: text("auth_results"),
	original_headers: text("original_headers"),
});
