// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Hono } from "hono";
import { jwtVerify, createRemoteJWKSet } from "jose";
import { z } from "zod";
import { signConfirmationToken, computePayloadHash } from "../lib/confirm-token";
import type { Env } from "../types";

// Mirrors getAccessUrls in workers/app.ts — needed here for step-up JWKS resolution.
function getAccessUrls(teamDomain: string) {
	const certsPath = "/cdn-cgi/access/certs";
	const teamUrl = new URL(teamDomain);
	const issuer = teamUrl.origin;
	const certsUrl = teamUrl.pathname.endsWith(certsPath)
		? teamUrl
		: new URL(certsPath, issuer);
	return { issuer, certsUrl };
}


const ConfirmBodySchema = z.object({
	tier: z.number().int().min(0).max(2),
	mailboxId: z.string().min(1),
	to: z.union([z.string(), z.array(z.string())]),
	cc: z.union([z.string(), z.array(z.string())]).optional(),
	bcc: z.union([z.string(), z.array(z.string())]).optional(),
	subject: z.string().optional().default(""),
	body: z.string().optional().default(""),
	attachmentIds: z.array(z.string()).optional().default([]),
});

export const confirmRoute = new Hono<{ Bindings: Env }>();

// ── Step-up relay page (issue #285) ───────────────────────────────────────────
//
// Cloudflare Access step-up requires a top-level navigation to a
// step-up-protected path. `/api/v1/confirm` is the only such path, so the
// composer opens THIS GET in a popup. Access intercepts the navigation,
// runs the step-up login, and (post-auth) lets the request through to this
// handler with the step-up cookie now set for the popup's origin. The tiny
// relay page below then POSTs the preflighted payload back to the same path
// (Access injects `cf-access-jwt-assertion` on that fetch), and relays the
// one-shot confirmation token to the opener via `postMessage`.
//
// This is an ADDITIVE sibling to the POST handler — it does not alter the
// slice-2 token contract (payloadHash binding, one-shot jti, signing) in
// any way. The page has no interpolated/untrusted content; the payload
// arrives at runtime via a same-origin, opener-checked postMessage.
const RELAY_HTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>PhishSOC step-up confirmation</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font:14px system-ui,sans-serif;margin:0;display:flex;align-items:center;justify-content:center;height:100vh;color:#374151;background:#f9fafb}</style>
</head>
<body>
<p id="s">Completing step-up confirmation…</p>
<script>
(function(){
  var SRC="phishsoc-confirm";
  var opener=window.opener;
  var status=document.getElementById("s");
  if(!opener){status.textContent="This window must be opened by PhishSOC.";return;}
  var openerOrigin=window.location.origin;
  var handled=false;
  function send(m){try{opener.postMessage(m,openerOrigin);}catch(e){}}
  window.addEventListener("message",function(e){
    if(e.origin!==openerOrigin)return;
    if(e.source!==opener)return;
    var d=e.data;
    if(!d||d.source!==SRC||d.type!=="payload")return;
    if(handled)return;handled=true;
    var nonce=d.nonce;
    fetch("/api/v1/confirm",{method:"POST",credentials:"same-origin",
      headers:{"content-type":"application/json"},body:JSON.stringify(d.payload)})
    .then(function(r){return r.json().catch(function(){return {};}).then(function(j){
      if(r.ok&&j&&typeof j.token==="string"){
        send({source:SRC,type:"token",nonce:nonce,token:j.token});
      }else{
        send({source:SRC,type:"error",nonce:nonce,error:(j&&j.error)||("confirm failed ("+r.status+")")});
      }
    });})
    .catch(function(err){send({source:SRC,type:"error",nonce:nonce,error:String((err&&err.message)||err)});})
    .then(function(){try{window.close();}catch(e){}});
  });
  send({source:SRC,type:"ready"});
})();
</script>
</body>
</html>`;

confirmRoute.get("/", (c) =>
	c.html(RELAY_HTML, 200, {
		"cache-control": "no-store",
		"x-frame-options": "DENY",
	}),
);

confirmRoute.post("/", async (c) => {
	const { STEP_UP_AUD, TEAM_DOMAIN, CONFIRMATION_TOKEN_SECRET, BLOOM_KV } = c.env;

	if (!STEP_UP_AUD || !CONFIRMATION_TOKEN_SECRET || !TEAM_DOMAIN || !BLOOM_KV) {
		return c.json({ error: "step-up auth not configured" }, 503);
	}

	const token = c.req.header("cf-access-jwt-assertion");
	if (!token) {
		return c.json({ error: "missing step-up JWT" }, 401);
	}

	try {
		const { issuer, certsUrl } = getAccessUrls(TEAM_DOMAIN);
		const JWKS = createRemoteJWKSet(certsUrl);
		const { payload } = await jwtVerify(token, JWKS, { issuer, audience: STEP_UP_AUD });

		// TEMPORARY — issue #364 acceptance criterion 1 (empirical gate).
		// The freshness enforcement #364 proposes is only viable if some
		// Access-JWT claim distinguishes a real MFA event from a silent
		// warm-session reissue. This diagnostic logs ONLY the numeric time
		// claims (never `email`/identity claims) so a `wrangler tail` can
		// compare a fresh-MFA send against a warm-session second send within
		// the Access session window. Off unless STEP_UP_CLAIM_DEBUG === "1";
		// REMOVE by redeploying from clean main once the finding is recorded.
		if (c.env.STEP_UP_CLAIM_DEBUG === "1") {
			const claims = payload as Record<string, unknown>;
			console.log(
				"[#364 step-up claims] " +
					JSON.stringify({
						iat: claims.iat ?? null,
						auth_time: claims.auth_time ?? null,
						exp: claims.exp ?? null,
						nbf: claims.nbf ?? null,
						now: Math.floor(Date.now() / 1000),
					}),
			);
		}
	} catch {
		return c.json({ error: "invalid step-up JWT" }, 401);
	}

	const parseResult = ConfirmBodySchema.safeParse(
		await c.req.json().catch(() => ({})),
	);
	if (!parseResult.success) {
		return c.json({ error: "invalid request body" }, 400);
	}

	const { tier, mailboxId, to, cc, bcc, subject, body, attachmentIds } = parseResult.data;
	const payloadHash = await computePayloadHash(to, subject, body, attachmentIds, cc, bcc);
	const jti = crypto.randomUUID();

	const confirmToken = await signConfirmationToken(
		{ tier: tier as 0 | 1 | 2, mailboxId, payloadHash, jti },
		CONFIRMATION_TOKEN_SECRET,
	);

	await BLOOM_KV.put(`confirm-jti:${jti}`, "1", { expirationTtl: 120 });

	return c.json({ token: confirmToken });
});
