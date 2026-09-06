// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * AIS community hub — MISP-compatible reporting & feed distribution.
 *
 * This is an open-source reference implementation, not a full MISP server.
 * Supported surface:
 *   POST   /events
 *   GET    /events/{uuid}
 *   POST   /events/restSearch
 *   GET    /feeds/destroylist.txt
 *   GET    /sharing_groups
 *   POST   /sharing_groups
 *   POST   /orgs/invite    (authenticated — existing org invites another)
 *   POST   /orgs/accept    (public — consumes an invite token, creates org + key)
 *   GET    /orgs/me
 *   *      /admin/*        (operator-only — gated by HUB_ADMIN_KEY)
 */

import { Hono } from "hono";
import { secureHeaders } from "hono/secure-headers";
import { eventRoutes } from "./routes/events";
import { feedRoutes, publicFeedRoutes } from "./routes/feeds";
import { orgRoutes, orgAcceptApp } from "./routes/orgs";
import { sharingGroupRoutes } from "./routes/sharing-groups";
import { adminRoutes } from "./routes/admin";
import { adminStatsRoutes } from "./routes/admin/stats";
import { corroborationRoutes } from "./routes/corroboration";
import { peerRoutes } from "./routes/peers";
import { consumeTriageBatch } from "./agent/triage";
import { runInboundSync } from "./lib/sync";
import type { Env, TriageMessage } from "./types";

const app = new Hono<{ Bindings: Env }>();

// Global security headers
app.use(
	"*",
	secureHeaders({
		referrerPolicy: "strict-origin-when-cross-origin",
		strictTransportSecurity: "max-age=31536000; includeSubDomains",
		xFrameOptions: "DENY",
		xContentTypeOptions: "nosniff",
	}),
);

app.get("/", (c) =>
	c.text(
		"AIS Hub — MISP-compatible threat-intel sharing. See /events, /feeds/destroylist.txt, /orgs.",
	),
);

app.route("/events", eventRoutes);
// Public (unauthenticated) feeds must be mounted before the authenticated
// /feeds sub-app so that /feeds/public/* is handled here before the
// requireOrg middleware on feedRoutes fires.
app.route("/feeds/public", publicFeedRoutes);
app.route("/feeds", feedRoutes);
app.route("/orgs", orgAcceptApp); // public /orgs/accept
app.route("/orgs", orgRoutes); // authed /orgs/me, /orgs/invite
app.route("/sharing_groups", sharingGroupRoutes);
app.route("/peers", peerRoutes);
app.route("/admin", adminRoutes);
app.route("/admin", adminStatsRoutes);
app.route("/api/v1/corroboration", corroborationRoutes);

export default {
	fetch: app.fetch,
	async queue(batch: MessageBatch<TriageMessage>, env: Env) {
		await consumeTriageBatch(batch, env);
	},
	async scheduled(
		_event: ScheduledController,
		env: Env,
		ctx: ExecutionContext,
	) {
		ctx.waitUntil(runInboundSync(env));
	},
};
