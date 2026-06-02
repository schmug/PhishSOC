// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { type Context, Hono } from "hono";
import { cors } from "hono/cors";
import PostalMime from "postal-mime";
import { z } from "zod";
import { sendEmail } from "./email-sender";
import { attachmentObjectKey, storeAttachments, type StoredAttachment } from "./lib/attachments";
import {
	validateSender,
	SenderValidationError,
	generateMessageId,
	buildThreadingHeaders,
	listMailboxes,
} from "./lib/email-helpers";
import { handleReplyEmail, handleForwardEmail } from "./routes/reply-forward";
import { Folders } from "../shared/folders";
import type { Env } from "./types";
import { requireMailbox, type MailboxContext } from "./lib/mailbox";
import {
	resolveMailboxSettings,
	stripDefaultEqual,
} from "./lib/mailbox-settings";
import { getOrgSettings, putOrgSettings, clearOrgSettingsCache, orgSettingsKey } from "./lib/org-settings";
import { OrgSettings } from "../shared/org-settings";
import { getDomainSettings, putDomainSettings } from "./lib/domain-settings";
import { DomainSettings } from "../shared/domain-settings";
import { MailboxSettings } from "../shared/mailbox-settings";
import { runSecurityPipeline } from "./security";
import { runDeepScan } from "./intel/deep-scan";
import { isDmarcReport, ingestDmarcReport, isDmarcRuf, ingestDmarcRuf } from "./dmarc/ingest";
import { dmarcRoutes } from "./routes/dmarc";
import { isTlsRptReport, ingestTlsRptReport } from "./tlsrpt/ingest";
import { tlsrptRoutes } from "./routes/tlsrpt";
import { caseRoutes } from "./routes/cases";
import { sendEmailRoutes } from "./routes/send-email";
import { hubUiRoutes } from "./routes/hub-ui";
import {
	aggregateDomainStats,
	aggregateDomainsList,
	aggregateOrgOverview,
	bucketThreatPressure,
	computeP95,
	domainOf,
	pipelineSuccessRate,
	reduceDmarcAlignmentRate,
	type DmarcAlignmentTotals,
	type DmarcPosture,
	type DomainListEntry,
	type DomainMailboxRef,
	type DomainMailboxSummary,
	type DomainStats,
	type OrgMailboxSummary,
	type OrgOverview,
} from "./lib/dashboard-aggregation";
import { emptyDmarcTxtPosture, fetchDmarcTxtPosture } from "./dmarc/txt";
import { emptyMtaStsPosture, fetchMtaStsPosture } from "./mta-sts/posture";
import { emptyBimiPosture, fetchBimiPosture } from "./dmarc/bimi";
import { emptySpfPosture, fetchSpfPosture } from "./spf/posture";
import { emptyTlsRptPosture, fetchTlsRptPosture } from "./tlsrpt/posture";
import { emptyDkimPosture, fetchDkimPosture, mergeDkimPosture, probeDkimSelectors } from "./dkim/posture";
import { emptyDnssecPosture, fetchDnssecPosture } from "./dnssec/posture";
import { listTextModels } from "./lib/text-models";
import { fetchHubCorroborationCount } from "./intel/hub-corroboration";
import { loadHubCredentials } from "./lib/hub-config";
import {
	aggregateOrgSearch,
	mailboxesForOrgSearch,
	type PerMailboxSearchResult,
} from "./lib/org-search";
import { readMailboxAcl, writeMailboxAcl, deleteMailboxAcl, callerInAcl, callerGroupsFromJwt } from "./lib/mailbox-acl";
import { aclMemberRoutes } from "./routes/acl-members";
import { fireYaraScan } from "./security/yaramail-signal";
import { yaramailCallbackRoute } from "./routes/yaramail-callback";

type AppContext = Context<MailboxContext>;

// -- Request body schemas (kept for validation) ---------------------

const CreateMailboxBody = z.object({
	email: z.string().email(),
	name: z.string().min(1),
	settings: z.record(z.any()).optional(), // unvalidated — agentSystemPrompt goes straight to AI
});

const DraftBody = z.object({
	to: z.string().optional(),
	cc: z.string().optional(),
	bcc: z.string().optional(),
	subject: z.string().optional(),
	body: z.string(),
	in_reply_to: z.string().optional(),
	thread_id: z.string().optional(),
	draft_id: z.string().optional(),
});

// -- Helpers --------------------------------------------------------

function slugify(text: string) { // can return "" for non-alphanumeric input
	return text.toString().toLowerCase()
		.replace(/\s+/g, "-").replace(/[^\w-]+/g, "")
		.replace(/--+/g, "-").replace(/^-+/, "").replace(/-+$/, "");
}

function intQuery(c: AppContext, key: string): number | undefined {
	const v = c.req.query(key);
	if (!v) return undefined;
	const n = Number(v);
	return Number.isNaN(n) ? undefined : n;
}

function boolQuery(c: AppContext, key: string): boolean | undefined {
	const v = c.req.query(key);
	if (v === undefined || v === "") return undefined;
	return v === "true" || v === "1";
}

// -- App & middleware -----------------------------------------------

const app = new Hono<MailboxContext>();
app.use("/api/*", cors({
	origin: (origin) => {
		// Same-origin requests have no Origin header — allow them.
		if (!origin) return origin;
		// In development, allow localhost for Vite dev server.
		try {
			const url = new URL(origin);
			if (url.hostname === "localhost" || url.hostname === "127.0.0.1") return origin;
		} catch { /* invalid origin */ }
		// Block all other cross-origin requests. The app is served from the
		// same origin as the API, so legitimate browser requests never send
		// an Origin header. Returning undefined omits Access-Control-Allow-Origin.
		return undefined;
	},
}));
// -- Yaramail sidecar callback (HMAC-authenticated, no CF Access) ------
//
// Registered BEFORE the requireMailbox middleware so the sidecar's
// machine-to-machine calls — which carry an HMAC-SHA256 signature rather
// than a cf-access-authenticated-user-email header — can reach the handler
// without being rejected by the mailbox ACL check.
app.route("/api/v1/mailboxes/:mailboxId/yaramail-callback", yaramailCallbackRoute);

// Exact mailbox path (GET/PUT/DELETE settings) must be covered — Hono's `/*`
// wildcard does not match when there is no trailing segment after :mailboxId.
app.use("/api/v1/mailboxes/:mailboxId", requireMailbox);
app.use("/api/v1/mailboxes/:mailboxId/*", requireMailbox);

// -- Config ---------------------------------------------------------

app.route("/api/v1/mailboxes/:mailboxId/acl", aclMemberRoutes);
app.route("/api/v1/mailboxes/:mailboxId/dmarc", dmarcRoutes);
app.route("/api/v1/mailboxes/:mailboxId/tlsrpt", tlsrptRoutes);
app.route("/api/v1/mailboxes/:mailboxId/cases", caseRoutes);
app.route("/api/v1/mailboxes/:mailboxId/hub", hubUiRoutes);
app.route("/api/v1/mailboxes/:mailboxId", sendEmailRoutes);

// Rejects strings that aren't registrable domains (no protocol, path, @, single label).
function isValidRegistrableDomain(d: string): boolean {
	if (!d || d.length > 253) return false;
	if (d.includes("://") || d.includes("/") || d.includes("@") || d.includes(" ")) return false;
	const labels = d.split(".");
	if (labels.length < 2) return false;
	return labels.every((l) => l.length > 0 && /^[a-zA-Z0-9-]+$/.test(l));
}

app.get("/api/v1/config", async (c) => {
	const domainsRaw = c.env.DOMAINS || "";
	const seedList = domainsRaw.split(",").map((d) => d.trim()).filter(Boolean);
	const orgSettings = await getOrgSettings(c.env);
	const orgList = (orgSettings.domains as string[] | undefined) ?? [];
	const seen = new Set<string>();
	const domains: string[] = [];
	for (const d of [...seedList, ...orgList]) {
		const key = d.toLowerCase();
		if (!seen.has(key)) { seen.add(key); domains.push(d); }
	}
	const emailAddresses = c.env.EMAIL_ADDRESSES ?? [];
	return c.json({ domains, emailAddresses });
});

app.post("/api/v1/org/domains", async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as { domain?: unknown };
	const domain = typeof body.domain === "string" ? body.domain.trim().toLowerCase() : "";
	if (!isValidRegistrableDomain(domain)) {
		return c.json({ error: "Invalid domain" }, 400);
	}
	const current = await getOrgSettings(c.env);
	const existing = (current.domains as string[] | undefined) ?? [];
	if (existing.some((d) => d.toLowerCase() === domain)) {
		return c.json({ error: "Domain already exists" }, 409);
	}
	const updated = { ...current, domains: [...existing, domain] };
	const stripped = stripDefaultEqual(updated as Record<string, unknown>);
	await c.env.BUCKET.put(orgSettingsKey(), JSON.stringify(stripped));
	clearOrgSettingsCache();
	return c.json({ domain, domains: (stripped.domains as string[] | undefined) ?? [] }, 201);
});

app.delete("/api/v1/org/domains/:domain", async (c) => {
	const target = decodeURIComponent(c.req.param("domain")!).toLowerCase();
	const current = await getOrgSettings(c.env);
	const existing = (current.domains as string[] | undefined) ?? [];
	const next = existing.filter((d) => d.toLowerCase() !== target);
	if (next.length === existing.length) {
		return c.json({ error: "Domain not found" }, 404);
	}
	const updated = { ...current, domains: next };
	const stripped = stripDefaultEqual(updated as Record<string, unknown>);
	await c.env.BUCKET.put(orgSettingsKey(), JSON.stringify(stripped));
	clearOrgSettingsCache();
	return c.json({ domains: (stripped.domains as string[] | undefined) ?? [] });
});

// Authenticated-user identity (#204). The Cloudflare Access middleware in
// `workers/app.ts` has already verified the JWT and admitted the request;
// the `Cf-Access-Authenticated-User-Email` header is set by Access on the
// admitted request, so reading it here is safe — no second `jwtVerify`
// pass and no hand-rolled crypto. The Shell sidebar account menu consumes
// `{ email }` to render the signed-in identity and the sign-out link.
//
// Dev mode: the auth middleware short-circuits when `import.meta.env.DEV`
// is true (Vite dev server has no Access in front of it), so the header
// is absent. Mirror that branch with a stable stub identity rather than
// returning 401 — otherwise `npm run dev` shows a broken account menu.
app.get("/api/v1/me", (c) => {
	const headerEmail = c.req.header("cf-access-authenticated-user-email");
	if (headerEmail) {
		return c.json({ email: headerEmail });
	}
	if (import.meta.env.DEV) {
		return c.json({ email: "dev@local" });
	}
	// In production the Access middleware would have already 403'd a
	// request without a verified JWT; reaching this branch implies the
	// request was admitted but Access didn't populate the header — treat
	// as unauthenticated rather than guess.
	return c.json({ error: "not authenticated" }, 401);
});

// Workers AI text-generation model list (#64). KV-cached read-through to
// the Cloudflare API; falls back to the curated TEXT_MODELS constant when
// CLOUDFLARE_API_TOKEN/CLOUDFLARE_ACCOUNT_ID aren't configured or the
// upstream call fails.
app.get("/api/v1/ai/text-models", async (c) => {
	const env = c.env as typeof c.env & {
		CLOUDFLARE_API_TOKEN?: string;
		CLOUDFLARE_ACCOUNT_ID?: string;
	};
	const result = await listTextModels({
		BLOOM_KV: env.BLOOM_KV,
		CLOUDFLARE_API_TOKEN: env.CLOUDFLARE_API_TOKEN,
		CLOUDFLARE_ACCOUNT_ID: env.CLOUDFLARE_ACCOUNT_ID,
	});
	c.header("X-Text-Models-Source", result.source);
	return c.json({ models: result.models });
});

// -- Mailboxes ------------------------------------------------------

app.get("/api/v1/mailboxes", async (c) => {
	const callerEmail = c.req.header("cf-access-authenticated-user-email") ?? null;
	// Groups from the verified CF Access JWT — used for group-grant ACL checks (#295).
	const callerGroups = callerGroupsFromJwt(c.req.header("cf-access-jwt-assertion"));
	const allMailboxes = await listMailboxes(c.env.BUCKET);

	// Read ACLs for all mailboxes — needed for acl_status (#241) in both branches.
	const acls = await Promise.all(allMailboxes.map((m) => readMailboxAcl(c.env, m.id)));

	// In dev mode or on pre-#27 single-user deploys (no callerEmail) show all.
	if (!callerEmail) {
		return c.json(allMailboxes.map((m, i) => ({
			...m,
			name: m.id,
			acl_status: acls[i] ? "scoped" : "unscoped",
		})));
	}

	// Filter to mailboxes the caller is allowed to see (#27, #295).
	const visible = allMailboxes
		.map((m, i) => ({ mailbox: m, acl: acls[i] }))
		.filter(({ acl }) => callerInAcl(acl, callerEmail, callerGroups));
	return c.json(visible.map(({ mailbox, acl }) => ({
		...mailbox,
		name: mailbox.id,
		acl_status: acl ? "scoped" : "unscoped",
	})));
});

// Bulk lock-down: lock every unscoped mailbox the caller can see (#294).
app.post("/api/v1/mailboxes/bulk-lockdown", async (c) => {
	const callerEmail =
		c.req.header("cf-access-authenticated-user-email")?.toLowerCase() ?? null;

	if (!callerEmail) {
		return c.json({ error: "CF Access email required" }, 400);
	}

	const allMailboxes = await listMailboxes(c.env.BUCKET);
	const acls = await Promise.all(allMailboxes.map((m) => readMailboxAcl(c.env, m.id)));

	// Filter to unscoped mailboxes (no ACL = unscoped = visible to all).
	const unscoped = allMailboxes.filter((_m, i) => !acls[i]);

	let locked = 0;
	let skipped = 0;
	const errors: string[] = [];

	await Promise.all(
		unscoped.map(async (m) => {
			const existing = await readMailboxAcl(c.env, m.id);
			if (existing) {
				skipped++;
				return;
			}
			try {
				const acl = { owner: callerEmail, members: [callerEmail] };
				await writeMailboxAcl(c.env, m.id, acl);
				locked++;
			} catch (err) {
				errors.push(`${m.id}: ${(err as Error)?.message ?? "unknown error"}`);
			}
		}),
	);

	return c.json({ locked, skipped, errors });
});

// -- Org overview ---------------------------------------------------

/** Versioned KV key — bumping the prefix on schema change is a clean rename. */
const ORG_OVERVIEW_CACHE_KEY = "org-overview:v1";
const ORG_OVERVIEW_CACHE_TTL_S = 60;

app.get("/api/v1/org/overview", async (c) => {
	const cached = c.env.BLOOM_KV
		? await c.env.BLOOM_KV.get(ORG_OVERVIEW_CACHE_KEY, "json").catch(() => null)
		: null;
	if (cached) {
		return c.json(cached as OrgOverview);
	}

	const mailboxes = await listMailboxes(c.env.BUCKET);
	const settled = await Promise.allSettled(
		mailboxes.map((m) =>
			c.env.MAILBOX
				.get(c.env.MAILBOX.idFromName(m.id))
				.getDashboardSummary(),
		),
	);
	const summaries: Array<OrgMailboxSummary | null> = settled.map((r) => {
		if (r.status !== "fulfilled") {
			console.error("org-overview: mailbox summary failed:", (r.reason as Error)?.message);
			return null;
		}
		const v = r.value as OrgMailboxSummary;
		// `threatsBlocked7d` was added by this PR; tolerate older clients.
		// `verdictMix7d` (#103) is also optional — older DO replicas omit it
		// and the aggregator treats them as zeros.
		return { ...v, threatsBlocked7d: v.threatsBlocked7d ?? 0 };
	});

	const overview = aggregateOrgOverview({ mailboxes, summaries });

	if (c.env.BLOOM_KV) {
		c.executionCtx.waitUntil(
			c.env.BLOOM_KV.put(ORG_OVERVIEW_CACHE_KEY, JSON.stringify(overview), {
				expirationTtl: ORG_OVERVIEW_CACHE_TTL_S,
			}).catch((e) => console.error("org-overview cache write failed:", (e as Error).message)),
		);
	}

	return c.json(overview);
});

// -- Org ACL overview (#292) ----------------------------------------

/**
 * Org-level ACL audit surface (#292). Returns every mailbox with its
 * acl_status, owner, and member list so operators can audit who can access
 * what across the fleet without inspecting R2 blobs by hand.
 *
 * Authz: any CF-Access-admitted caller. No org-admin role exists today, so the
 * policy is identical to GET /api/v1/org/overview — all callers admitted past
 * the main CF Access policy may view the overview. In dev mode (no callerEmail)
 * the endpoint is also accessible. Owner and member emails of scoped mailboxes
 * are visible to all admitted callers — this is an operator audit surface.
 */
app.get("/api/v1/org/acl-overview", async (c) => {
	const allMailboxes = await listMailboxes(c.env.BUCKET);
	const acls = await Promise.all(allMailboxes.map((m) => readMailboxAcl(c.env, m.id)));

	return c.json(
		allMailboxes.map((m, i) => {
			const acl = acls[i];
			return {
				email: m.id,
				acl_status: acl ? "scoped" : "unscoped",
				owner: acl?.owner ?? null,
				members: acl?.members ?? [],
			};
		}),
	);
});

// -- Org-scope search (#197) ----------------------------------------

/** Per-mailbox cap for org-search fan-out. We pull at most this many rows
 * from each mailbox to bound the merged-page sort + response size. The org
 * page slices the merged ordering to the requested page; common operator
 * queries fit well below the cap. */
const ORG_SEARCH_PER_MAILBOX_CAP = 200;

app.get("/api/v1/org/search", async (c) => {
	const callerEmail =
		c.req.header("cf-access-authenticated-user-email")?.toLowerCase() ?? null;
	const callerGroups = callerGroupsFromJwt(c.req.header("cf-access-jwt-assertion"));

	const searchOpts = {
		query: c.req.query("query") || "",
		folder: c.req.query("folder"),
		from: c.req.query("from"),
		to: c.req.query("to"),
		subject: c.req.query("subject"),
		date_start: c.req.query("date_start"),
		date_end: c.req.query("date_end"),
		is_read: boolQuery(c, "is_read"),
		is_starred: boolQuery(c, "is_starred"),
		has_attachment: boolQuery(c, "has_attachment"),
	};
	const page = Math.max(1, intQuery(c, "page") ?? 1);
	const limit = Math.min(Math.max(intQuery(c, "limit") ?? 25, 1), 100);

	const allMailboxes = await listMailboxes(c.env.BUCKET);
	const acls = await Promise.all(allMailboxes.map((m) => readMailboxAcl(c.env, m.id)));
	const mailboxes = mailboxesForOrgSearch(allMailboxes, acls, callerEmail, callerGroups);

	const settled = await Promise.allSettled(
		mailboxes.map(async (m) => {
			const stub = c.env.MAILBOX.get(c.env.MAILBOX.idFromName(m.id)) as any;
			const [emails, count] = await Promise.all([
				stub.searchEmails({
					...searchOpts,
					page: 1,
					limit: ORG_SEARCH_PER_MAILBOX_CAP,
				}),
				stub.countSearchResults(searchOpts),
			]);
			return { mailboxId: m.id, mailboxEmail: m.email, emails, count };
		}),
	);
	const perMailbox: PerMailboxSearchResult[] = [];
	for (const r of settled) {
		if (r.status !== "fulfilled") {
			console.error("org-search: mailbox search failed:", (r.reason as Error)?.message);
			continue;
		}
		perMailbox.push(r.value);
	}
	return c.json(aggregateOrgSearch(perMailbox, page, limit));
});

// -- Per-domain stats + drill-down (#85) ----------------------------

/** Versioned KV keys — bumping the prefix on schema change is a clean rename. */
const DOMAINS_LIST_CACHE_KEY = "domains:v1";
const DOMAIN_STATS_CACHE_KEY_PREFIX = "domain-stats:v1:";
const DOMAIN_CACHE_TTL_S = 60;
/** Window for the apex-domain DMARC alignment-rate reducer (#138). 7 days
 * matches the rest of the dashboard's "recent" framing without going so far
 * back that a stale forwarder-fail spike from last month skews the rate. */
const DMARC_ALIGNMENT_WINDOW_DAYS = 7;

/**
 * Hostname-shape regex. Mirrors RFC 1035 / 5890 lite: at least two labels,
 * each label 1–63 chars, alphanumeric with internal hyphens, total length
 * ≤253. Lower-cased before matching. Rejects `acme..com`, `acme/foo`,
 * IDNs (out of scope for v1), and anything with whitespace.
 */
const DOMAIN_REGEX =
	/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

app.get("/api/v1/domains", async (c) => {
	const cached = c.env.BLOOM_KV
		? await c.env.BLOOM_KV.get(DOMAINS_LIST_CACHE_KEY, "json").catch(() => null)
		: null;
	if (cached) {
		return c.json(cached as DomainListEntry[]);
	}

	const mailboxes = await listMailboxes(c.env.BUCKET);
	const settled = await Promise.allSettled(
		mailboxes.map((m) =>
			c.env.MAILBOX
				.get(c.env.MAILBOX.idFromName(m.id))
				.getDashboardSummary(),
		),
	);
	const summaries: Array<OrgMailboxSummary | null> = settled.map((r) => {
		if (r.status !== "fulfilled") {
			console.error("domains-list: mailbox summary failed:", (r.reason as Error)?.message);
			return null;
		}
		const v = r.value as OrgMailboxSummary;
		return { ...v, threatsBlocked7d: v.threatsBlocked7d ?? 0 };
	});

	const list = aggregateDomainsList({ mailboxes, summaries });

	if (c.env.BLOOM_KV) {
		c.executionCtx.waitUntil(
			c.env.BLOOM_KV.put(DOMAINS_LIST_CACHE_KEY, JSON.stringify(list), {
				expirationTtl: DOMAIN_CACHE_TTL_S,
			}).catch((e) => console.error("domains-list cache write failed:", (e as Error).message)),
		);
	}

	return c.json(list);
});

app.get("/api/v1/domains/:domain/stats", async (c) => {
	const raw = c.req.param("domain") ?? "";
	const domain = decodeURIComponent(raw).toLowerCase();
	if (!DOMAIN_REGEX.test(domain)) {
		return c.json({ error: "Malformed domain" }, 400);
	}

	const cacheKey = `${DOMAIN_STATS_CACHE_KEY_PREFIX}${domain}`;
	const cached = c.env.BLOOM_KV
		? await c.env.BLOOM_KV.get(cacheKey, "json").catch(() => null)
		: null;
	if (cached) {
		return c.json(cached as DomainStats);
	}

	const allMailboxes = await listMailboxes(c.env.BUCKET);
	const scoped = allMailboxes.filter((m) => domainOf(m.email) === domain);
	if (scoped.length === 0) {
		return c.json({ error: "Domain not found" }, 404);
	}

	// Apex-domain DMARC posture (#138). The TXT lookup over DoH and the
	// per-mailbox alignment-rate fan-out run as siblings of the dashboard
	// summary fan-out — wrapping all three in the same Promise.allSettled
	// keeps a slow upstream off the critical path. Any sibling rejecting
	// degrades to null fields rather than failing the response.
	const nowMs = Date.now();
	const alignmentSinceIso = new Date(
		nowMs - DMARC_ALIGNMENT_WINDOW_DAYS * 24 * 60 * 60 * 1000,
	).toISOString();

	const summaryPromises = scoped.map((m) =>
		c.env.MAILBOX.get(c.env.MAILBOX.idFromName(m.id)).getDashboardSummary(),
	);
	const alignmentPromises = scoped.map((m) =>
		c.env.MAILBOX
			.get(c.env.MAILBOX.idFromName(m.id))
			.getDmarcAlignmentTotals(domain, alignmentSinceIso),
	);
	// Per-mailbox DKIM-selector fan-out (#170). Each mailbox observes its own
	// selector set; we union here so the per-domain DKIM tile reflects every
	// inbound DKIM signature seen for `domain` over the 30-day window. The
	// per-mailbox-DO scoping is preserved — selectors observed on a mailbox
	// of a different domain never enter this fan-out.
	const dkimSelectorPromises = scoped.map((m) =>
		c.env.MAILBOX
			.get(c.env.MAILBOX.idFromName(m.id))
			.getDkimSelectorsObserved(domain),
	);
	const txtPromise = fetchDmarcTxtPosture(domain, {
		kv: c.env.BLOOM_KV ?? null,
	});
	const mtaStsPromise = fetchMtaStsPosture(domain, {
		kv: c.env.BLOOM_KV ?? null,
	});
	const bimiPromise = fetchBimiPosture(domain, {
		kv: c.env.BLOOM_KV ?? null,
	});
	const spfPromise = fetchSpfPosture(domain, {
		kv: c.env.BLOOM_KV ?? null,
	});
	const tlsRptPromise = fetchTlsRptPosture(domain, {
		kv: c.env.BLOOM_KV ?? null,
	});
	const dnssecPromise = fetchDnssecPosture(domain, {
		kv: c.env.BLOOM_KV ?? null,
	});
	// Active DKIM probe (#358): probe well-known selectors concurrently with
	// the rest of the posture fan-out so it doesn't add sequential latency.
	const dkimProbePromise = probeDkimSelectors(domain, {
		kv: c.env.BLOOM_KV ?? null,
	});

	const [
		settledSummaries,
		settledAlignments,
		settledDkimSelectors,
		settledTxt,
		settledMtaSts,
		settledBimi,
		settledSpf,
		settledTlsRpt,
		settledDnssec,
		settledDkimProbe,
	] = await Promise.all([
		Promise.allSettled(summaryPromises),
		Promise.allSettled(alignmentPromises),
		Promise.allSettled(dkimSelectorPromises),
		Promise.allSettled([txtPromise]),
		Promise.allSettled([mtaStsPromise]),
		Promise.allSettled([bimiPromise]),
		Promise.allSettled([spfPromise]),
		Promise.allSettled([tlsRptPromise]),
		Promise.allSettled([dnssecPromise]),
		Promise.allSettled([dkimProbePromise]),
	]);

	const summaries: Array<DomainMailboxSummary | null> = settledSummaries.map((r) => {
		if (r.status !== "fulfilled") {
			console.error("domain-stats: mailbox summary failed:", (r.reason as Error)?.message);
			return null;
		}
		const v = r.value as DomainMailboxSummary;
		return { ...v, threatsBlocked7d: v.threatsBlocked7d ?? 0 };
	});

	const alignmentTotals: Array<DmarcAlignmentTotals | null> = settledAlignments.map(
		(r) => {
			if (r.status !== "fulfilled") {
				console.error(
					"domain-stats: alignment-totals failed:",
					(r.reason as Error)?.message,
				);
				return null;
			}
			return r.value as DmarcAlignmentTotals;
		},
	);

	const txtPosture =
		settledTxt[0].status === "fulfilled"
			? settledTxt[0].value
			: emptyDmarcTxtPosture();

	const dmarcPosture: DmarcPosture = {
		...txtPosture,
		alignmentRate: reduceDmarcAlignmentRate(alignmentTotals),
	};

	const mtaStsPosture =
		settledMtaSts[0].status === "fulfilled"
			? settledMtaSts[0].value
			: emptyMtaStsPosture();

	const bimiPosture =
		settledBimi[0].status === "fulfilled"
			? settledBimi[0].value
			: emptyBimiPosture();

	const spfPosture =
		settledSpf[0].status === "fulfilled"
			? settledSpf[0].value
			: emptySpfPosture();

	const tlsRptPosture =
		settledTlsRpt[0].status === "fulfilled"
			? settledTlsRpt[0].value
			: emptyTlsRptPosture();

	const dnssecPosture =
		settledDnssec[0].status === "fulfilled"
			? settledDnssec[0].value
			: emptyDnssecPosture();

	// Union the per-mailbox selector lists. A failed DO call contributes
	// nothing rather than blocking the whole DKIM tile — same degradation
	// model as `getDmarcAlignmentTotals`.
	const observedSelectors = new Set<string>();
	for (const r of settledDkimSelectors) {
		if (r.status !== "fulfilled") {
			console.error(
				"domain-stats: dkim-selectors failed:",
				(r.reason as Error)?.message,
			);
			continue;
		}
		for (const sel of r.value) {
			if (typeof sel === "string" && sel.length > 0) observedSelectors.add(sel);
		}
	}

	const observedDkimPosture = observedSelectors.size === 0
		? emptyDkimPosture()
		: await fetchDkimPosture(domain, [...observedSelectors], {
			kv: c.env.BLOOM_KV ?? null,
		}).catch((e) => {
			console.error(
				"domain-stats: dkim posture lookup failed:",
				(e as Error).message,
			);
			return emptyDkimPosture();
		});

	const probedDkimPosture =
		settledDkimProbe[0]?.status === "fulfilled"
			? settledDkimProbe[0].value
			: emptyDkimPosture();

	const dkimPosture = mergeDkimPosture(observedDkimPosture, probedDkimPosture);

	const mailboxRefs: DomainMailboxRef[] = scoped.map((m) => ({
		id: m.id,
		email: m.email,
		name: m.id,
	}));

	const stats = aggregateDomainStats({
		domain,
		mailboxes: mailboxRefs,
		summaries,
		dmarcPosture,
		mtaStsPosture,
		bimiPosture,
		spfPosture,
		tlsRptPosture,
		dkimPosture,
		dnssec: dnssecPosture,
	});
	// `aggregateDomainStats` only returns null when `mailboxes.length === 0`,
	// which we already guarded above with the 404 — but narrow the type
	// defensively in case the helper's contract changes later.
	if (!stats) {
		return c.json({ error: "Domain not found" }, 404);
	}

	if (c.env.BLOOM_KV) {
		c.executionCtx.waitUntil(
			c.env.BLOOM_KV.put(cacheKey, JSON.stringify(stats), {
				expirationTtl: DOMAIN_CACHE_TTL_S,
			}).catch((e) => console.error("domain-stats cache write failed:", (e as Error).message)),
		);
	}

	return c.json(stats);
});

// Org-wide settings (#106). The blob lives at R2 key `org/settings.json` and
// is read on the per-email hot path via a module-scope ETag cache, so the
// endpoints below intentionally bypass that cache: GET reads R2 directly
// (returning whatever's persisted, not the resolved view), PUT invalidates
// the cache as part of the write. The resolved view for a specific mailbox
// is exposed at /api/v1/mailboxes/:mailboxId/settings/effective below.
app.get("/api/v1/org/settings", async (c) => {
	const settings = await getOrgSettings(c.env);
	return c.json({ settings });
});

app.put("/api/v1/org/settings", async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as { settings?: unknown };
	const parsed = OrgSettings.safeParse(body?.settings ?? {});
	if (!parsed.success) {
		return c.json({ error: "Invalid org settings", issues: parsed.error.issues }, 400);
	}
	// Symmetry with the domain (below) and mailbox PUT/POST paths: drop fields
	// equal to the system default before persisting so a fresh form save with
	// rendered defaults doesn't pin them as explicit org-tier overrides that
	// shadow a future default change for every inheriting domain/mailbox.
	const stripped = stripDefaultEqual(parsed.data);
	const written = await putOrgSettings(c.env, stripped);
	return c.json({ settings: written });
});

// Domain-level settings (#142). Same pattern as the org endpoints —
// GET reads R2 directly through the resolver's per-domain cache, PUT
// invalidates the cache as part of the write. The resolved view for a
// specific mailbox under this domain is exposed at the existing
// /api/v1/mailboxes/:mailboxId/settings/effective endpoint, which now
// runs the full mailbox > domain > org > default chain via the same
// resolveMailboxSettings.
app.get("/api/v1/domains/:domain/settings", async (c) => {
	const domain = c.req.param("domain")!.toLowerCase();
	const settings = await getDomainSettings(c.env, domain);
	return c.json({ domain, settings });
});

app.put("/api/v1/domains/:domain/settings", async (c) => {
	const domain = c.req.param("domain")!.toLowerCase();
	const body = (await c.req.json().catch(() => ({}))) as { settings?: unknown };
	const parsed = DomainSettings.safeParse(body?.settings ?? {});
	if (!parsed.success) {
		return c.json({ error: "Invalid domain settings", issues: parsed.error.issues }, 400);
	}
	// Symmetry with #106's mailbox PUT/POST: drop fields equal to the
	// system default before persisting so a fresh form save with rendered
	// defaults doesn't silently shadow the org tier for every mailbox
	// under this domain. Caught by advisor before #142 merge.
	const stripped = stripDefaultEqual(parsed.data);
	const written = await putDomainSettings(c.env, domain, stripped);
	return c.json({ domain, settings: written });
});

// DMARC RUF records for a domain (issue #171). Fans out to all mailboxes on
// the domain that have ruf_ingestion.enabled === true and aggregates their
// forensic-report records. Returns { enabled: boolean, records: DmarcRufRecord[] }.
app.get("/api/v1/domains/:domain/ruf-records", async (c) => {
	const raw = c.req.param("domain") ?? "";
	const domain = decodeURIComponent(raw).toLowerCase();
	if (!DOMAIN_REGEX.test(domain)) return c.json({ error: "Malformed domain" }, 400);

	const allMailboxes = await listMailboxes(c.env.BUCKET);
	const scoped = allMailboxes.filter((m) => domainOf(m.email) === domain);
	if (scoped.length === 0) return c.json({ enabled: false, records: [] });

	const limit = Math.min(parseInt(c.req.query("limit") ?? "50", 10) || 50, 200);

	const perMailbox = await Promise.allSettled(
		scoped.map(async (m) => {
			const settings = (await resolveMailboxSettings(c.env, m.id)).security;
			if (!settings.ruf_ingestion.enabled) return { enabled: false, records: [] as unknown[] };
			const stub = c.env.MAILBOX.get(c.env.MAILBOX.idFromName(m.id));
			const records = await stub.listDmarcRufRecords({ domain, limit });
			return { enabled: true, records };
		}),
	);

	let anyEnabled = false;
	const allRecords: unknown[] = [];
	for (const result of perMailbox) {
		if (result.status !== "fulfilled") continue;
		if (result.value.enabled) anyEnabled = true;
		allRecords.push(...result.value.records);
	}

	// Sort merged records newest-first, cap at limit.
	const sorted = (allRecords as Array<{ received_at: string }>)
		.sort((a, b) => b.received_at.localeCompare(a.received_at))
		.slice(0, limit);

	return c.json({ enabled: anyEnabled, records: sorted });
});

app.post("/api/v1/mailboxes", async (c) => {
	const { name, settings, email: rawEmail } = CreateMailboxBody.parse(await c.req.json());
	const email = rawEmail.toLowerCase();
	const allowedAddresses = (c.env.EMAIL_ADDRESSES ?? []) as string[];
	if (allowedAddresses.length > 0 && !allowedAddresses.map((a) => a.toLowerCase()).includes(email)) {
		return c.json({ error: "Mailbox creation is restricted to configured EMAIL_ADDRESSES" }, 403);
	}
	const key = `mailboxes/${email}.json`;
	if (await c.env.BUCKET.head(key)) return c.json({ error: "Mailbox already exists" }, 409);
	const defaultSettings = { fromName: name, forwarding: { enabled: false, email: "" }, signature: { enabled: false, text: "" }, autoReply: { enabled: false, subject: "", message: "" } };
	// #106 acceptance criterion 6 applies on create too: a fresh mailbox
	// whose initial PUT-payload includes the rendered form defaults
	// (`agentModel: "@cf/moonshotai/kimi-k2.5"`, `autoDraft: { enabled: true }`)
	// must NOT silently shadow every org-level value on the very first
	// write. defaultSettings (per-mailbox identity fields) is layered AFTER
	// the strip so fromName/signature/forwarding/autoReply still get
	// materialised — those are strictly per-mailbox (audit Q8).
	const cleanedSettings = stripDefaultEqual((settings ?? {}) as MailboxSettings);
	const finalSettings = { ...defaultSettings, ...cleanedSettings };
	await c.env.BUCKET.put(key, JSON.stringify(finalSettings));

	// Bootstrap owner ACL (#27). Skipped when callerEmail is absent (dev
	// mode / no Access) — those deploys get the backwards-compat "anyone
	// past Access can see all mailboxes" behaviour.
	const creatorEmail = c.req.header("cf-access-authenticated-user-email");
	if (creatorEmail) {
		const owner = creatorEmail.toLowerCase();
		await writeMailboxAcl(c.env, email, { owner, members: [owner] });
	}

	const stub = c.env.MAILBOX.get(c.env.MAILBOX.idFromName(email));
	await stub.getFolders();
	return c.json({ id: email, email, name, settings: finalSettings }, 201);
});

app.get("/api/v1/mailboxes/:mailboxId", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const obj = await c.env.BUCKET.get(`mailboxes/${mailboxId}.json`);
	if (!obj) return c.json({ error: "Not found" }, 404);
	return c.json({ id: mailboxId, name: mailboxId, email: mailboxId, settings: await obj.json() });
});

app.get("/api/v1/mailboxes/:mailboxId/dashboard", async (c: AppContext) => {
	const raw = await c.var.mailboxStub.getDashboardSummary();
	const threatPressure = bucketThreatPressure(raw.verdictRows);
	const pipelineSuccess = pipelineSuccessRate(raw.pipelineScan);
	const p95Ms = computeP95(raw.pipelineDurationsMs);

	// Hub corroboration count (#72). Best-effort: the hub may be down, the
	// mailbox may have no hub config, or the call may time out. Any of those
	// → `corroboration: null` and the rest of the dashboard ships unaffected.
	let corroboration: number | null = null;
	const mailboxId = c.req.param("mailboxId");
	if (mailboxId) {
		try {
			const creds = await loadHubCredentials(
				c.env as unknown as Record<string, unknown> & { BUCKET: R2Bucket },
				mailboxId,
			);
			if (creds) {
				const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
				corroboration = await fetchHubCorroborationCount({
					baseUrl: creds.cfg.url,
					apiKey: creds.apiKey,
					orgUuid: creds.cfg.org_uuid,
					since,
				});
			}
		} catch (e) {
			console.error("dashboard corroboration fetch failed:", (e as Error)?.message);
			corroboration = null;
		}
	}

	return c.json({
		now: raw.now,
		threatsBlocked: raw.threatsBlocked,
		openCases: raw.openCases,
		hubContributions: raw.hubContributions,
		corroboration,
		pipelineSuccess,
		p95Ms: p95Ms === null ? null : Math.round(p95Ms),
		threatPressure,
		recentCases: raw.recentCases,
	});
});

// Realtime event stream. Browsers can't set custom headers on `new
// WebSocket()`, so auth piggybacks on the `cf-access-jwt-assertion` header
// the CF Access edge injects on all origin requests (including Upgrade)
// when the user's session is valid. The `*` middleware in workers/app.ts
// validates that header before this route is reached.
app.get("/api/v1/mailboxes/:mailboxId/events", async (c) => {
	if (c.req.header("Upgrade") !== "websocket") {
		return c.text("Expected WebSocket upgrade", 426);
	}
	return c.var.mailboxStub.fetch(c.req.raw);
});

app.put("/api/v1/mailboxes/:mailboxId", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const body = (await c.req.json()) as { settings?: unknown };
	// Validate the typed sub-shapes (autoDraft, agentModel, security.attachment_policy,
	// security.folder_policies). The schema is passthrough, so unknown fields
	// round-trip untouched — bad enum values (e.g. executable_action: "lol")
	// surface here as 400, not 500 from a downstream consumer.
	const parsed = MailboxSettings.safeParse(body?.settings ?? {});
	if (!parsed.success) {
		return c.json({ error: "Invalid settings", issues: parsed.error.issues }, 400);
	}
	// #106 acceptance criterion 6: drop fields equal to the system default
	// before persisting. A fresh mailbox PUT that just round-trips the UI's
	// rendered defaults must NOT silently shadow every org-level value.
	const settings = stripDefaultEqual(parsed.data);
	const key = `mailboxes/${mailboxId}.json`;
	if (!(await c.env.BUCKET.head(key))) return c.json({ error: "Not found" }, 404);
	await c.env.BUCKET.put(key, JSON.stringify(settings));
	return c.json({ id: mailboxId, name: mailboxId, email: mailboxId, settings });
});

// Resolved view of a mailbox's effective settings — runs the full
// inheritance hierarchy (mailbox > org > system default) and returns the
// post-normalised result. Used by the agent path internally and exposed
// here for the /settings UI's "Inherited from org" indicator (PR2) and
// for debugging.
app.get("/api/v1/mailboxes/:mailboxId/settings/effective", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const key = `mailboxes/${mailboxId}.json`;
	if (!(await c.env.BUCKET.head(key))) return c.json({ error: "Not found" }, 404);
	const resolved = await resolveMailboxSettings(c.env, mailboxId);
	return c.json({
		id: mailboxId,
		settings: resolved,
	});
});

app.delete("/api/v1/mailboxes/:mailboxId", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const key = `mailboxes/${mailboxId}.json`;
	if (!(await c.env.BUCKET.head(key))) return c.json({ error: "Not found" }, 404);

	// Settings-first delete. Removing the settings JSON makes the mailbox
	// invisible to every list/get endpoint immediately, and a DELETE retry
	// after partial failure is now idempotent: the next `head()` returns
	// null and we 404 cleanly. The heavier reap (R2 attachments + DO wipe)
	// runs in the background via waitUntil — orphaned rows/blobs are a
	// cleanup cost, never a correctness bug.
	await c.env.BUCKET.delete(key);
	c.executionCtx.waitUntil(reapMailbox(c.env, mailboxId));
	return c.body(null, 204);
});

/** Upper bound on R2 delete batch size. The Workers R2 binding accepts up
 *  to 1000 keys per call, but each call still consumes subrequest budget —
 *  100 keeps us well inside both the per-request subrequest cap and
 *  `reapMailbox`'s overall budget on mailboxes with long history. */
const R2_DELETE_BATCH = 100;

/**
 * Best-effort cleanup for a deleted mailbox. Every step is isolated in its
 * own try/catch so a partial failure (e.g. the DO being unreachable for a
 * few seconds) never cancels the remaining steps. None of these errors
 * propagate to the user — the settings JSON was already removed so the
 * mailbox is effectively gone from the product's point of view.
 */
async function reapMailbox(env: Env, mailboxId: string): Promise<void> {
	const mbStub = env.MAILBOX.get(env.MAILBOX.idFromName(mailboxId));
	const agentStub = env.EMAIL_AGENT.get(env.EMAIL_AGENT.idFromName(mailboxId));

	// 1. Enumerate attachment keys BEFORE the DO wipe. After deleteAll(),
	//    the attachments table is the only place these keys live, so we
	//    must list them first or accept orphans in R2 forever.
	let keys: string[] = [];
	try {
		keys = await (mbStub as any).listAllAttachmentKeys();
	} catch (e) {
		console.error(`reapMailbox(${mailboxId}): listAllAttachmentKeys failed:`, (e as Error).message);
	}

	// 2. Batched R2 deletes. Each batch is its own try/catch so one failed
	//    chunk doesn't abandon the rest — the alternative is leaving the
	//    bulk of the blobs stranded because the first batch tripped a
	//    transient error.
	for (let i = 0; i < keys.length; i += R2_DELETE_BATCH) {
		try {
			await env.BUCKET.delete(keys.slice(i, i + R2_DELETE_BATCH));
		} catch (e) {
			console.error(`reapMailbox(${mailboxId}): R2 batch delete failed at offset ${i}:`, (e as Error).message);
		}
	}

	// 3. Wipe both DOs. Safe to do after the R2 reap because neither
	//    bucket read nor bucket delete depended on DO state at this point.
	await (mbStub as any).reset().catch(
		(e: Error) => console.error(`reapMailbox(${mailboxId}): mailbox DO reset failed:`, e.message),
	);
	await (agentStub as any).reset().catch(
		(e: Error) => console.error(`reapMailbox(${mailboxId}): agent DO reset failed:`, e.message),
	);

	// 4. Delete ACL blob (#27). Best-effort — an orphaned ACL is harmless
	//    because the settings JSON is already gone, so the mailbox can never
	//    be found via list/get again.
	await deleteMailboxAcl(env, mailboxId).catch(
		(e: Error) => console.error(`reapMailbox(${mailboxId}): ACL delete failed:`, e.message),
	);
}

// -- Emails ---------------------------------------------------------

app.get("/api/v1/mailboxes/:mailboxId/emails", async (c: AppContext) => {
	const folder = c.req.query("folder");
	const thread_id = c.req.query("thread_id");
	const threaded = boolQuery(c, "threaded");
	const page = intQuery(c, "page");
	const limit = intQuery(c, "limit");
	const sortColumn = c.req.query("sortColumn") as any;
	const sortDirection = c.req.query("sortDirection") as "ASC" | "DESC" | undefined;
	const stub = c.var.mailboxStub;

	if (threaded && folder) {
		const emails = await (stub as any).getThreadedEmails({ folder, page, limit });
		const totalCount = await (stub as any).countThreadedEmails(folder);
		return c.json({ emails, totalCount });
	}
	const emails = await stub.getEmails({ folder, thread_id, page, limit, sortColumn, sortDirection });
	if (folder) {
		const totalCount = await stub.countEmails({ folder, thread_id });
		return c.json({ emails, totalCount });
	}
	return c.json(emails);
});


app.post("/api/v1/mailboxes/:mailboxId/drafts", async (c: AppContext) => {
	const mailboxId = c.req.param("mailboxId")!;
	const { to, cc, bcc, subject, body, in_reply_to, thread_id, draft_id } = DraftBody.parse(await c.req.json());
	const stub = c.var.mailboxStub;
	if (draft_id) await stub.deleteEmail(draft_id); // not atomic — create-then-delete would be safer
	const messageId = crypto.randomUUID();
	const now = new Date().toISOString();
	await stub.createEmail(Folders.DRAFT, {
		id: messageId, subject: subject || "", sender: mailboxId.toLowerCase(),
		recipient: (to || "").toLowerCase(), cc: cc?.toLowerCase() || null, bcc: bcc?.toLowerCase() || null,
		date: now, body, in_reply_to: in_reply_to || null, email_references: null,
		thread_id: thread_id || in_reply_to || messageId,
	}, []);
	return c.json({ id: messageId, status: "draft", subject: subject || "", recipient: to || "", date: now }, 201);
});

app.get("/api/v1/mailboxes/:mailboxId/emails/:id", async (c: AppContext) => {
	const email = await c.var.mailboxStub.getEmail(c.req.param("id")!);
	if (!email) return c.json({ error: "Email not found" }, 404);
	return new Response(JSON.stringify(email), {
		headers: { "Content-Type": "application/json" },
	});
});

app.put("/api/v1/mailboxes/:mailboxId/emails/:id", async (c: AppContext) => {
	const { read, starred } = (await c.req.json()) as { read?: boolean; starred?: boolean };
	const email = await c.var.mailboxStub.updateEmail(c.req.param("id")!, { read, starred });
	return email ? c.json(email) : c.json({ error: "Email not found" }, 404);
});

app.delete("/api/v1/mailboxes/:mailboxId/emails/:id", async (c: AppContext) => {
	const id = c.req.param("id")!;
	const attachments = await c.var.mailboxStub.deleteEmail(id);
	if (attachments === null) return c.json({ error: "Not found" }, 404);
	if (attachments.length > 0) await c.env.BUCKET.delete(attachments.map((att: any) => attachmentObjectKey(id, att.id, att.filename)));
	return c.body(null, 204);
});

app.post("/api/v1/mailboxes/:mailboxId/emails/:id/move", async (c: AppContext) => {
	const { folderId } = (await c.req.json()) as { folderId: string };
	const emailId = c.req.param("id")!;
	const mailboxId = c.req.param("mailboxId")!;

	// Snapshot the email's pre-move state so the "treat_as_verified" hook
	// below can decide based on the *folder transition*, not just the
	// destination. This keeps the sender-reputation bump idempotent: moving
	// out of and back into a verified folder does not double-count.
	const before = await c.var.mailboxStub.getEmail(emailId);

	const success = await c.var.mailboxStub.moveEmail(emailId, folderId);
	if (!success) return c.json({ error: "Folder not found" }, 400);

	// Per-folder `treat_as_verified` hook. When the user moves a message
	// INTO a verified folder from a non-verified folder, bump the sender's
	// reputation with a favourable score (0). Best-effort — never fail the
	// move because of a reputation write.
	if (before?.sender) {
		try {
			const settings = (await resolveMailboxSettings(c.env, mailboxId)).security;
			const destPolicy = settings.folder_policies?.[folderId];
			const srcPolicy = before.folder_id ? settings.folder_policies?.[before.folder_id] : undefined;
			if (destPolicy?.treat_as_verified && !srcPolicy?.treat_as_verified) {
				await c.var.mailboxStub.upsertSenderReputation(before.sender, 0);
			}
		} catch (e) {
			console.error("treat_as_verified reputation bump failed:", (e as Error).message);
		}
	}

	return c.json({ status: "moved" });
});

// -- Threads --------------------------------------------------------

app.get("/api/v1/mailboxes/:mailboxId/threads/:threadId", async (c: AppContext) => {
	return c.json(await (c.var.mailboxStub as any).getThreadEmails(c.req.param("threadId")!));
});

app.post("/api/v1/mailboxes/:mailboxId/threads/:threadId/read", async (c: AppContext) => {
	await c.var.mailboxStub.markThreadRead(c.req.param("threadId")!);
	return c.json({ status: "marked_read" });
});

// -- Reply / Forward ------------------------------------------------

app.post("/api/v1/mailboxes/:mailboxId/emails/:id/reply", handleReplyEmail);
app.post("/api/v1/mailboxes/:mailboxId/emails/:id/forward", handleForwardEmail);

// -- Folders --------------------------------------------------------

app.get("/api/v1/mailboxes/:mailboxId/folders", async (c: AppContext) => c.json(await c.var.mailboxStub.getFolders()));

app.post("/api/v1/mailboxes/:mailboxId/folders", async (c: AppContext) => {
	const { name } = (await c.req.json()) as { name: string };
	const slug = slugify(name);
	if (!slug) return c.json({ error: "Folder name must contain alphanumeric characters" }, 400);
	const f = await c.var.mailboxStub.createFolder(slug, name);
	return f ? c.json(f, 201) : c.json({ error: "Folder with this name already exists" }, 409);
});

app.put("/api/v1/mailboxes/:mailboxId/folders/:id", async (c: AppContext) => {
	const { name } = (await c.req.json()) as { name: string };
	const f = await c.var.mailboxStub.updateFolder(c.req.param("id")!, name);
	return f ? c.json(f) : c.json({ error: "Folder not found" }, 404);
});

app.delete("/api/v1/mailboxes/:mailboxId/folders/:id", async (c: AppContext) => {
	const ok = await c.var.mailboxStub.deleteFolder(c.req.param("id")!);
	return ok ? c.body(null, 204) : c.json({ error: "Folder not found or cannot be deleted" }, 400);
});

// -- Search ---------------------------------------------------------

app.get("/api/v1/mailboxes/:mailboxId/search", async (c: AppContext) => {
	const searchOpts: Record<string, unknown> = {
		query: c.req.query("query") || "", folder: c.req.query("folder"), from: c.req.query("from"),
		to: c.req.query("to"), subject: c.req.query("subject"), date_start: c.req.query("date_start"),
		date_end: c.req.query("date_end"), is_read: boolQuery(c, "is_read"),
		is_starred: boolQuery(c, "is_starred"), has_attachment: boolQuery(c, "has_attachment"),
	};
	const stub = c.var.mailboxStub as any;
	const emails = await stub.searchEmails({ ...searchOpts, page: intQuery(c, "page"), limit: intQuery(c, "limit") });
	const totalCount = await stub.countSearchResults(searchOpts);
	return c.json({ emails, totalCount });
});

// -- URL scan results -----------------------------------------------

app.get("/api/v1/mailboxes/:mailboxId/emails/:emailId/urls", async (c: AppContext) => {
	const emailId = c.req.param("emailId")!;
	const urls = await c.var.mailboxStub.getUrlsForEmail(emailId);
	return c.json({ urls });
});

// -- Attachments ----------------------------------------------------

app.get("/api/v1/mailboxes/:mailboxId/emails/:emailId/attachments/:attachmentId", async (c: AppContext) => {
	const emailId = c.req.param("emailId")!;
	const attachmentId = c.req.param("attachmentId")!;
	const attachment = await c.var.mailboxStub.getAttachment(attachmentId);
	if (!attachment) return c.json({ error: "Attachment not found" }, 404);
	const obj = await c.env.BUCKET.get(attachmentObjectKey(emailId, attachmentId, attachment.filename));
	if (!obj) return c.json({ error: "Attachment file not found" }, 404);
	const headers = new Headers();
	headers.set("Content-Type", attachment.mimetype);
	const sanitized = attachment.filename.replace(/[\x00-\x1f"\\]/g, "_");
	headers.set("Content-Disposition", `attachment; filename="${sanitized}"; filename*=UTF-8''${encodeURIComponent(attachment.filename)}`);
	return new Response(obj.body, { headers });
});

// -- Receive inbound email ------------------------------------------

const MAX_EMAIL_SIZE = 25 * 1024 * 1024;

async function streamToArrayBuffer(stream: ReadableStream, streamSize: number) {
	if (streamSize > MAX_EMAIL_SIZE) throw new Error(`Email too large: ${streamSize} bytes exceeds ${MAX_EMAIL_SIZE} byte limit`);
	if (streamSize <= 0) throw new Error(`Invalid stream size: ${streamSize}`);
	const result = new Uint8Array(streamSize);
	let bytesRead = 0;
	const reader = stream.getReader();
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		if (bytesRead + value.length > streamSize) { reader.cancel(); throw new Error(`Stream exceeds declared size`); }
		result.set(value, bytesRead);
		bytesRead += value.length;
	}
	return result;
}

async function receiveEmail(event: { raw: ReadableStream; rawSize: number }, env: Env, ctx: ExecutionContext) {
	const rawEmail = await streamToArrayBuffer(event.raw, event.rawSize);
	const parsedEmail = await new PostalMime().parse(rawEmail);

	if (!parsedEmail.to?.length || !parsedEmail.to[0].address) throw new Error("received email with empty to");

	const allowedAddresses = ((env.EMAIL_ADDRESSES ?? []) as string[]).map((a) => a.toLowerCase());
	const allRecipients = parsedEmail.to.map((t) => t.address?.toLowerCase()).filter(Boolean) as string[];
	const ccRecipients = (parsedEmail.cc || []).map((e) => e.address?.toLowerCase()).filter(Boolean) as string[];
	const bccRecipients = (parsedEmail.bcc || []).map((e) => e.address?.toLowerCase()).filter(Boolean) as string[];

	let mailboxId: string | undefined;
	if (allowedAddresses.length > 0) {
		mailboxId = allRecipients.find((addr) => allowedAddresses.includes(addr));
		if (!mailboxId) { console.log(`Ignoring email: no recipient matches EMAIL_ADDRESSES.`); return; }
	} else { mailboxId = allRecipients[0]; }
	if (!mailboxId) throw new Error("received email with no valid recipient address");

	const messageId = crypto.randomUUID();
	if (!(await env.BUCKET.head(`mailboxes/${mailboxId}.json`))) { console.log(`Ignoring email for ${mailboxId}: mailbox does not exist`); return; }

	const stub = env.MAILBOX.get(env.MAILBOX.idFromName(mailboxId));

	const attachmentData: StoredAttachment[] = [];
	if (parsedEmail.attachments) {
		for (const att of parsedEmail.attachments) {
			const attId = crypto.randomUUID();
			const filename = (att.filename || "untitled").replace(/[\/\\:*?"<>|\x00-\x1f]/g, "_");
			await env.BUCKET.put(attachmentObjectKey(messageId, attId, filename), att.content);
			attachmentData.push({ id: attId, email_id: messageId, filename, mimetype: att.mimeType,
				size: typeof att.content === "string" ? att.content.length : att.content.byteLength,
				content_id: att.contentId || null, disposition: att.disposition || "attachment" });
		}
	}

	const extractMsgId = (s: string) => { const m = s.match(/<([^>]+)>/); return m ? m[1] : s.trim().split(/\s+/)[0]; };
	const inReplyTo = parsedEmail.inReplyTo ? extractMsgId(parsedEmail.inReplyTo) : null;
	const emailReferences = parsedEmail.references ? parsedEmail.references.split(/\s+/).filter(Boolean).map(extractMsgId) : [];
	let threadId = emailReferences[0] || inReplyTo || messageId;

	if (!inReplyTo && emailReferences.length === 0) {
		const subjectThread = await (stub as any).findThreadBySubject(parsedEmail.subject || "", parsedEmail.from?.address || undefined);
		if (subjectThread) threadId = subjectThread;
	}

	const originalMessageId = parsedEmail.messageId ? extractMsgId(parsedEmail.messageId) : null;

	await stub.createEmail(Folders.INBOX, {
		id: messageId, subject: parsedEmail.subject || "",
		sender: (parsedEmail.from?.address || "").toLowerCase(), recipient: allRecipients.join(", "),
		cc: ccRecipients.join(", ") || null, bcc: bccRecipients.join(", ") || null,
		date: new Date().toISOString(), // uses receive time, not the email's Date header
		body: parsedEmail.html || parsedEmail.text || "",
		in_reply_to: inReplyTo, email_references: emailReferences.length > 0 ? JSON.stringify(emailReferences) : null,
		thread_id: threadId, message_id: originalMessageId, raw_headers: JSON.stringify(parsedEmail.headers),
	}, attachmentData);

	// DMARC aggregate reports arrive as email. Detect and divert to the
	// dashboard rather than running the content classifier against what is
	// obviously automated machine mail. See workers/dmarc/ingest.ts.
	if (isDmarcReport(parsedEmail)) {
		try {
			const result = await ingestDmarcReport(env, mailboxId, messageId, parsedEmail);
			if (result.ingested) {
				await stub.moveEmail(messageId, Folders.ARCHIVE);
				return;
			}
		} catch (e) {
			console.error("dmarc ingest failed:", (e as Error).message);
		}
	}

	// TLS-RPT (RFC 8460) reports arrive as email with `application/tlsrpt+gzip`
	// or `application/tlsrpt+json` payloads. Same divert pattern as DMARC RUA:
	// the security pipeline must never classify a machine report. See
	// workers/tlsrpt/ingest.ts. Issue #169.
	if (isTlsRptReport(parsedEmail)) {
		try {
			const result = await ingestTlsRptReport(env, mailboxId, messageId, parsedEmail);
			if (result.ingested) {
				await stub.moveEmail(messageId, Folders.ARCHIVE);
				return;
			}
		} catch (e) {
			console.error("tlsrpt ingest failed:", (e as Error).message);
		}
	}

	// DMARC RUF forensic reports (RFC 6591) — opt-in per mailbox (issue #171).
	// Same divert pattern as RUA/TLS-RPT: only short-circuit when ingest succeeds.
	// On heuristic miss, disabled ingest, or parse failure, fall through to the
	// security pipeline so subject-keyword false positives cannot bypass it.
	if (isDmarcRuf(parsedEmail)) {
		try {
			const rufSettings = (await resolveMailboxSettings(env, mailboxId)).security.ruf_ingestion;
			if (rufSettings.enabled) {
				const result = await ingestDmarcRuf(env, mailboxId, messageId, parsedEmail, rufSettings);
				if (result.ingested) {
					await stub.moveEmail(messageId, Folders.ARCHIVE);
					return;
				}
				console.log("dmarc ruf drop:", result.reason);
			}
		} catch (e) {
			console.error("dmarc ruf ingest failed:", (e as Error).message);
		}
	}

	// Security pipeline (opt-in per mailbox via settings.security.enabled).
	// Runs synchronously so quarantine decisions are made before the agent
	// auto-draft fires. See workers/security/index.ts.
	//
	// Per-run timing is logged to `pipeline_runs` for the dashboard's real
	// p95 card. The start row is written before the call so a throw partway
	// through still gets patched to `failed` in the catch — otherwise a hung
	// `running` row would silently drop out of the p95 sample.
	let securityVerdict: Awaited<ReturnType<typeof runSecurityPipeline>>["verdict"] = null;
	const runId = crypto.randomUUID();
	const startedAtIso = new Date().toISOString();
	const startedAtMs = Date.now();
	let runRecorded = false;
	try {
		await stub.recordPipelineRunStart({
			runId,
			emailId: messageId,
			startedAt: startedAtIso,
		});
		runRecorded = true;
	} catch (e) {
		// Don't let a logging failure block the actual scan. The downstream
		// completion patch will be a no-op if the start row never landed.
		console.error("recordPipelineRunStart failed:", (e as Error).message);
	}
	try {
		const result = await runSecurityPipeline({
			env,
			mailboxId,
			messageId,
			// `receiveEmail` always lands inbound mail in INBOX today. If a
			// future filter-rule engine routes mail into other folders on
			// receive, this destination folder must be passed through so the
			// folder-bypass triage tier can honour per-folder policy.
			targetFolder: Folders.INBOX,
			parsedEmail: {
				subject: parsedEmail.subject,
				from: parsedEmail.from,
				html: parsedEmail.html,
				text: parsedEmail.text,
				headers: parsedEmail.headers,
				attachments: parsedEmail.attachments?.map((a) => ({
					filename: a.filename ?? null,
					mimeType: a.mimeType ?? null,
				})),
			},
		});
		securityVerdict = result.verdict;
		if (securityVerdict?.action === "quarantine" || securityVerdict?.action === "block") {
			await stub.moveEmail(messageId, Folders.QUARANTINE);
		}
		if (runRecorded) {
			// Skipped runs (mailbox security disabled) are marked with a
			// distinct status so p95 / success-rate aggregation naturally
			// excludes them — the run finished in microseconds and isn't
			// representative of the actual scan latency we're tracking.
			await stub
				.recordPipelineRunComplete({
					runId,
					completedAt: new Date().toISOString(),
					durationMs: Date.now() - startedAtMs,
					status: result.skipped ? "skipped" : "completed",
					stageFailed: null,
				})
				.catch((err) => {
					console.error(
						"recordPipelineRunComplete failed:",
						(err as Error).message,
					);
				});
		}
	} catch (e) {
		console.error("Security pipeline failed:", (e as Error).message);
		if (runRecorded) {
			await stub
				.recordPipelineRunComplete({
					runId,
					completedAt: new Date().toISOString(),
					durationMs: Date.now() - startedAtMs,
					status: "failed",
					stageFailed: "pipeline",
				})
				.catch((err) => {
					console.error(
						"recordPipelineRunComplete (failure) failed:",
						(err as Error).message,
					);
				});
		}
	}

	// Foreground notification fanout. Pass the *final* folder so connected
	// clients can suppress desktop notifications for mail that was
	// quarantined/blocked by the sync verdict — surfacing a notification for
	// a phishing email that just vanished into Quarantine is worse than
	// silence. Deep-scan can still tighten the verdict later, but that
	// happens out-of-band and does not retract the notification.
	const finalFolder =
		securityVerdict?.action === "quarantine" || securityVerdict?.action === "block"
			? Folders.QUARANTINE
			: Folders.INBOX;
	try {
		await stub.notifyNewEmail(messageId, finalFolder);
	} catch (e) {
		console.error("notifyNewEmail failed:", (e as Error).message);
	}

	// Async deep-scan. Runs AFTER the sync pipeline decision and only ever
	// tightens the verdict (never downgrades). Enqueued via ctx.waitUntil
	// so it doesn't block email receipt; failures are logged but don't
	// propagate. Gated on the same `security.enabled` flag as the sync path.
	if (securityVerdict) {
		try {
			const settings = (await resolveMailboxSettings(env, mailboxId)).security;
			ctx.waitUntil(
				runDeepScan({ env, mailboxId, emailId: messageId, thresholds: settings.thresholds })
					.then(
						(r) => {
							if (r.added_score > 0) {
								console.log(
									`deep-scan ${messageId}: +${r.added_score} → ${r.final_action} (${r.reasons.slice(0, 3).join("; ")})`,
								);
							}
						},
						(e) => console.error("deep-scan failed:", (e as Error).message),
					),
			);
		} catch (e) {
			console.error("deep-scan enqueue failed:", (e as Error).message);
		}
	}

	// Async yaramail sidecar scan (issue #257). Fire-and-forget via
	// ctx.waitUntil — one request per attachment. Only runs when the mailbox
	// has `yaramail_scanner.enabled === true`. Skipped if the email has no
	// attachments. presignedUrl is "" until R2 S3-API presigned URL support
	// is wired; the sidecar must fall back to PhishSOC's download endpoint.
	if (attachmentData.length > 0) {
		try {
			const yaraScanSettings = (await resolveMailboxSettings(env, mailboxId)).raw?.yaramail_scanner;
			if (yaraScanSettings?.enabled) {
				for (const att of attachmentData) {
					const r2Key = attachmentObjectKey(att.email_id, att.id, att.filename);
					// fireYaraScan internally calls resolveMailboxSettings again and
					// checks enabled + endpoint_url — the outer check is an optimisation
					// to skip the per-attachment loop entirely when the scanner is off.
					ctx.waitUntil(
						fireYaraScan(env, ctx, mailboxId, messageId, r2Key).catch(
							(e) => console.error("yaramail fire failed:", (e as Error).message),
						),
					);
				}
			}
		} catch (e) {
			console.error("yaramail scan enqueue failed:", (e as Error).message);
		}
	}

	// Auto-draft dispatch is gated on resolved settings (mailbox > org >
	// default). The security pipeline above always runs; only the agent's
	// onNewEmail fetch is skipped when the operator has disabled auto-draft
	// for this mailbox (or for the org as a whole).
	const mailboxSettings = await resolveMailboxSettings(env, mailboxId);
	if (!mailboxSettings.autoDraft.enabled) {
		return;
	}

	const agentStub = env.EMAIL_AGENT.get(env.EMAIL_AGENT.idFromName(mailboxId));
	ctx.waitUntil(agentStub.fetch(new Request("https://agents/onNewEmail", {
		method: "POST", headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			mailboxId,
			emailId: messageId,
			sender: (parsedEmail.from?.address || "").toLowerCase(),
			subject: parsedEmail.subject || "",
			threadId,
			securityVerdict: securityVerdict
				? { action: securityVerdict.action, score: securityVerdict.score, explanation: securityVerdict.explanation }
				: null,
		}),
	})).catch((e) => console.error("Auto-draft trigger failed:", (e as Error).message)));
}

export { app, receiveEmail };
