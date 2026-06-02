// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Org-level peer discovery and subscription routes (closes #29).
 *
 * GET  /peers                     — list discoverable peers + subscription status
 * POST /peers/:peer_uuid/subscribe   — subscribe (upsert) with optional trust_multiplier
 * DELETE /peers/:peer_uuid/subscribe — unsubscribe
 */

import { Hono } from "hono";
import { z } from "zod";
import { requireOrg, type HubContext } from "../lib/auth";

export const peerRoutes = new Hono<HubContext>();

peerRoutes.use("*", requireOrg);

peerRoutes.get("/", async (c) => {
	const orgUuid = c.var.org.uuid;
	const rows = await c.env.DB
		.prepare(
			`SELECT p.uuid, p.name, p.contact, p.created_at,
			        ops.trust_multiplier
			 FROM peers p
			 LEFT JOIN org_peer_subscriptions ops
			   ON ops.peer_uuid = p.uuid AND ops.org_uuid = ?1
			 WHERE p.discoverable = 1
			 ORDER BY p.name`,
		)
		.bind(orgUuid)
		.all<{
			uuid: string;
			name: string;
			contact: string | null;
			created_at: string;
			trust_multiplier: number | null;
		}>();
	return c.json({
		peers: (rows.results ?? []).map((p) => ({
			uuid: p.uuid,
			name: p.name,
			contact: p.contact,
			created_at: p.created_at,
			subscribed: p.trust_multiplier !== null,
			trust_multiplier: p.trust_multiplier,
		})),
	});
});

const SubscribeSchema = z.object({
	trust_multiplier: z.number().min(0).max(10).default(1.0),
});

peerRoutes.post("/:peer_uuid/subscribe", async (c) => {
	const peerUuid = c.req.param("peer_uuid");
	const orgUuid = c.var.org.uuid;

	const parsed = SubscribeSchema.safeParse(await c.req.json().catch(() => ({})));
	if (!parsed.success) return c.json({ error: parsed.error.flatten() }, 400);

	const peer = await c.env.DB
		.prepare(`SELECT uuid FROM peers WHERE uuid = ?1`)
		.bind(peerUuid)
		.first<{ uuid: string }>();
	if (!peer) return c.json({ error: "not found" }, 404);

	const now = new Date().toISOString();
	await c.env.DB
		.prepare(
			`INSERT INTO org_peer_subscriptions
			   (org_uuid, peer_uuid, trust_multiplier, subscribed_at)
			 VALUES (?1, ?2, ?3, ?4)
			 ON CONFLICT (org_uuid, peer_uuid)
			 DO UPDATE SET trust_multiplier = ?3`,
		)
		.bind(orgUuid, peerUuid, parsed.data.trust_multiplier, now)
		.run();

	return c.json({ ok: true, peer_uuid: peerUuid, trust_multiplier: parsed.data.trust_multiplier }, 201);
});

peerRoutes.delete("/:peer_uuid/subscribe", async (c) => {
	const peerUuid = c.req.param("peer_uuid");
	const orgUuid = c.var.org.uuid;

	const result = await c.env.DB
		.prepare(
			`DELETE FROM org_peer_subscriptions WHERE org_uuid = ?1 AND peer_uuid = ?2`,
		)
		.bind(orgUuid, peerUuid)
		.run();

	if ((result.meta.changes ?? 0) === 0) {
		return c.json({ error: "not subscribed" }, 404);
	}

	return new Response(null, { status: 204 });
});
