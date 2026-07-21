// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { routeAgentRequest } from "agents";
import { Hono } from "hono";
import { secureHeaders } from "hono/secure-headers";
import { jwtVerify, createRemoteJWKSet } from "jose";
import { createRequestHandler } from "react-router";
import {
	app as apiApp,
	receiveEmail,
	receiveCatchall,
	reapExpiredHoneypots,
} from "./index";
import { normalizeInbound } from "./providers/cf-routing";
import { receiveGatewayPassthrough } from "./lib/gateway-receive";
import { EmailMCP } from "./mcp";
import { refreshAllFeeds } from "./intel/feeds";
import { pollSidecarMailboxes, reapSidecarBodies } from "./providers/workspace";
import { deleteExpiredChallenges } from "./lib/webauthn-store";
import { webauthnRoute } from "./routes/webauthn";
import {
	callerAllowedForMailbox,
	emailAgentMailboxIdFromPath,
} from "./lib/mailbox-acl";
import {
	identityFromAccessPayload,
	type AccessVariables,
} from "./lib/access-identity";
import type { Env } from "./types";

export { MailboxDO } from "./durableObject";
export { CatchallIntelDO } from "./durableObject/catchall-intel";
export { EmailAgent } from "./agent";
export { OrgAgent } from "./agent/org";
export { EmailMCP } from "./mcp";

declare module "react-router" {
	export interface AppLoadContext {
		cloudflare: {
			env: Env;
			ctx: ExecutionContext;
		};
	}
}

const requestHandler = createRequestHandler(
	() => import("virtual:react-router/server-build"),
	import.meta.env.MODE,
);

function getAccessUrls(teamDomain: string) {
	const certsPath = "/cdn-cgi/access/certs";
	const teamUrl = new URL(teamDomain);
	const issuer = teamUrl.origin;
	const certsUrl = teamUrl.pathname.endsWith(certsPath)
		? teamUrl
		: new URL(certsPath, issuer);

	return { issuer, certsUrl };
}

// Main app that wraps the API and adds React Router fallback
const app = new Hono<{ Bindings: Env; Variables: AccessVariables }>();

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

// Cloudflare Access JWT validation middleware (production only)
app.use("*", async (c, next) => {
	// Skip validation in development, but seed a synthetic interactive identity
	// so the WebAuthn step-up routes (#376) are exercisable under `wrangler dev`.
	if (import.meta.env.DEV) {
		c.set("accessIdentity", { sub: "dev-user", email: "dev@localhost" });
		return next();
	}

	const { POLICY_AUD, TEAM_DOMAIN } = c.env;

	// Fail closed in production if Access is not configured.
	if (!POLICY_AUD || !TEAM_DOMAIN) {
		return c.text(
			"Cloudflare Access must be configured in production. Set POLICY_AUD and TEAM_DOMAIN.",
			500,
		);
	}

	const token = c.req.header("cf-access-jwt-assertion");
	if (!token) {
		return c.text("Missing required CF Access JWT", 403);
	}

	try {
		const { issuer, certsUrl } = getAccessUrls(TEAM_DOMAIN);
		const JWKS = createRemoteJWKSet(certsUrl);
		const { payload } = await jwtVerify(token, JWKS, {
			issuer,
			audience: POLICY_AUD,
		});
		// Carry the verified identity (sub + optional email) downstream for the
		// WebAuthn step-up routes (#376). email is present only for interactive
		// SSO sessions, so its absence marks a service-token / MCP caller.
		const identity = identityFromAccessPayload(payload);
		if (identity) c.set("accessIdentity", identity);
	} catch {
		return c.text("Invalid or expired Access token", 403);
	}

	// Authorization model note: once a teammate passes the shared Cloudflare
	// Access policy, they can access all mailboxes in this app by design.
	return next();
});

// MCP server endpoint — used by AI coding tools (ProtoAgent, Claude Code, Cursor, etc.)
// Must be before API routes and React Router catch-all
const mcpHandler = EmailMCP.serve("/mcp", { binding: "EMAIL_MCP" });
app.all("/mcp", async (c) => {
	return mcpHandler.fetch(c.req.raw, c.env, c.executionCtx as ExecutionContext);
});
app.all("/mcp/*", async (c) => {
	return mcpHandler.fetch(c.req.raw, c.env, c.executionCtx as ExecutionContext);
});

// WebAuthn step-up (issue #376). Mounted AFTER the main Access middleware so
// c.var.accessIdentity (verified POLICY_AUD sub/email) is available for the
// identity binding and interactive-only enrollment gates. Unlike the legacy
// /api/v1/confirm relay, this needs no second Access app.
app.route("/api/v1/webauthn", webauthnRoute);

// Mount the API routes
app.route("/", apiApp);

// Agent WebSocket routing - must be before React Router catch-all
app.all("/agents/*", async (c) => {
	// Per-mailbox ACL enforcement for the EmailAgent path — parity with the
	// HTTP `requireMailbox` and MCP `verifyMailbox` gates (#27/#295). The agent
	// instance name IS the mailboxId (attacker-chosen via the connection URL),
	// and the full email toolset is built for it, so without this check any
	// teammate admitted by the shared CF Access policy could read and mutate
	// any other mailbox over the agent WebSocket. Runs after the global CF
	// Access JWT middleware (token verified-present) and before
	// `routeAgentRequest`, covering both the WebSocket upgrade and HTTP.
	const mailboxId = emailAgentMailboxIdFromPath(new URL(c.req.url).pathname);
	if (mailboxId) {
		const allowed = await callerAllowedForMailbox(
			c.env,
			mailboxId,
			c.req.header("cf-access-jwt-assertion"),
			import.meta.env.DEV,
		);
		if (!allowed) return c.json({ error: "Forbidden" }, 403);
	}
	const response = await routeAgentRequest(c.req.raw, c.env);
	if (response) return response;
	return c.text("Agent not found", 404);
});

// React Router catch-all: serves the SPA for all non-API routes
app.all("*", (c) => {
	return requestHandler(c.req.raw, {
		cloudflare: { env: c.env, ctx: c.executionCtx as ExecutionContext },
	});
});

// Export the Hono app as the default export with an email handler
export default {
	fetch: app.fetch,
	async email(
		// `to` is the SMTP envelope recipient (RCPT TO) Cloudflare Email
		// Routing matched its rule on; normalizeInbound resolves the target
		// mailbox from it rather than trusting the parsed `To:` header.
		// `from` is the envelope MAIL FROM — the runtime `ForwardableEmailMessage`
		// carries it even though the previous signature omitted it; the gateway
		// relay path (issue #32) needs it to preserve the original sender.
		event: { raw: ReadableStream; rawSize: number; to?: string; from?: string },
		env: Env,
		ctx: ExecutionContext,
	) {
		try {
			const normalized = await normalizeInbound(event, env);
			if (!normalized) return;
			if (normalized.kind === "catchall") {
				await receiveCatchall(normalized, env, ctx);
			} else if (normalized.kind === "gateway") {
				await receiveGatewayPassthrough(normalized, env, ctx);
			} else {
				await receiveEmail(normalized, env, ctx);
			}
		} catch (e) {
			console.error(
				"Failed to process incoming email:",
				(e as Error).message,
				(e as Error).stack,
			);
			// Re-throw so Cloudflare's email routing can retry delivery or bounce the message.
			// Swallowing the error would silently drop the email.
			throw e;
		}
	},
	async scheduled(event: ScheduledController, env: Env, ctx: ExecutionContext) {
		// Minutely tick (issue #31): sidecar mailbox polling ONLY. Everything
		// else stays on the hourly tick. An unknown cron string falls through
		// to the hourly branch so `wrangler dev --test-scheduled` and future
		// triggers keep today's behavior.
		if (event.cron === "* * * * *") {
			ctx.waitUntil(
				pollSidecarMailboxes(env, ctx).then(
					(r) => {
						if (r.polled > 0)
							console.log(
								`sidecar: polled ${r.polled} mailboxes, ${r.processed} messages, ${r.failures} failures`,
							);
					},
					(e) => console.error("sidecar poll failed:", (e as Error).message),
				),
			);
			return;
		}

		ctx.waitUntil(
			refreshAllFeeds(env).then(
				(r) =>
					console.log(
						`intel: refreshed ${r.feeds} feeds, ${r.entries} entries`,
					),
				(e) =>
					console.error("intel feed refresh failed:", (e as Error).message),
			),
		);

		// Reap expired WebAuthn step-up challenges (#376). consumeChallenge only
		// deletes on a successful consume, so abandoned step-ups leave rows that
		// never expire out of the table; sweep them hourly. Runs as a separate
		// waitUntil and swallows its own error so a reap failure (or an unbound
		// WEBAUTHN_DB in deploys without step-up configured) never breaks the
		// feed refresh above.
		if (env.WEBAUTHN_DB) {
			ctx.waitUntil(
				deleteExpiredChallenges(env.WEBAUTHN_DB, Date.now()).then(
					(n) => {
						if (n > 0) console.log(`webauthn: reaped ${n} expired challenges`);
					},
					(e) =>
						console.error(
							"webauthn challenge reap failed:",
							(e as Error).message,
						),
				),
			);
		}

		// Reap expired honeypot mailboxes (#24): delete their settings blob and
		// wipe the DO + R2 attachment blobs once their TTL passes. Separate
		// waitUntil so a reap failure never breaks the other cron jobs.
		ctx.waitUntil(
			reapExpiredHoneypots(env).then(
				(r) => {
					if (r.reaped > 0)
						console.log(`honeypots: reaped ${r.reaped} expired`);
				},
				(e) => console.error("honeypot reap failed:", (e as Error).message),
			),
		);

		// Strip sidecar message bodies past their retention window (issue #31).
		// Separate waitUntil so a reap failure never breaks the other cron jobs.
		ctx.waitUntil(
			reapSidecarBodies(env).then(
				(r) => {
					if (r.reaped > 0)
						console.log(
							`sidecar: reaped ${r.reaped} bodies across ${r.mailboxes} mailboxes`,
						);
				},
				(e) => console.error("sidecar body reap failed:", (e as Error).message),
			),
		);
	},
};
