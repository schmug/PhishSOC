// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * MISP-compatible event endpoints.
 *
 * Supports the subset needed for the report/pull loop: POST /events,
 * GET /events/{uuid}, POST /events/restSearch. Full MISP has dozens more
 * endpoints; consumers needing those can run a real MISP instance.
 */

import { Hono } from "hono";
import { z } from "zod";
import { applyCorroboration } from "../lib/aggregate";
import { type HubContext, requireOrg } from "../lib/auth";

export const eventRoutes = new Hono<HubContext>();

eventRoutes.use("*", requireOrg);

const AttributeSchema = z.object({
	uuid: z.string().uuid().optional(),
	type: z.string().min(1).max(64),
	category: z.string().min(1).max(64),
	value: z.string().min(1).max(2000),
	to_ids: z.union([z.boolean(), z.literal(0), z.literal(1)]).optional(),
	comment: z.string().max(500).optional(),
});

const EventSchema = z.object({
	Event: z.object({
		uuid: z.string().uuid().optional(),
		info: z.string().min(1).max(500),
		date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
		timestamp: z.string(),
		analysis: z.string().optional(),
		threat_level_id: z.string().optional(),
		distribution: z.string().optional(),
		orgc_uuid: z.string().uuid().optional(),
		sharing_group_uuid: z.string().uuid().optional(),
		Tag: z.array(z.object({ name: z.string().min(1).max(128) })).optional(),
		Attribute: z.array(AttributeSchema).default([]),
	}),
});

eventRoutes.post("/", async (c) => {
	const body = await c.req.json().catch(() => null);
	const parsed = EventSchema.safeParse(body);
	if (!parsed.success) return c.json({ error: parsed.error.flatten() }, 400);
	const incoming = parsed.data.Event;

	const org = c.var.org;
	// Orgc_uuid must match the authenticated org — prevents impersonation.
	if (incoming.orgc_uuid && incoming.orgc_uuid !== org.uuid) {
		return c.json({ error: "orgc_uuid does not match authenticated org" }, 403);
	}
	// If a sharing group is specified, the org must belong to it.
	if (incoming.sharing_group_uuid) {
		const mem = await c.env.DB.prepare(
			`SELECT 1 FROM sharing_group_orgs WHERE sharing_group_uuid = ?1 AND org_uuid = ?2`,
		)
			.bind(incoming.sharing_group_uuid, org.uuid)
			.first();
		if (!mem) return c.json({ error: "org not in sharing_group" }, 403);
	}

	const eventUuid = incoming.uuid ?? crypto.randomUUID();
	await c.env.DB.prepare(
		`INSERT INTO events
			 (uuid, orgc_uuid, sharing_group_uuid, info, date, timestamp,
			  distribution, analysis, threat_level_id, event_json)
			 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
	)
		.bind(
			eventUuid,
			org.uuid,
			incoming.sharing_group_uuid ?? null,
			incoming.info,
			incoming.date,
			incoming.timestamp,
			incoming.distribution ?? "1",
			incoming.analysis ?? "0",
			incoming.threat_level_id ?? "2",
			JSON.stringify(parsed.data),
		)
		.run();

	// Insert attributes and tags in batches where possible.
	const attrStatements = incoming.Attribute.map((a) =>
		c.env.DB.prepare(
			`INSERT INTO attributes (uuid, event_uuid, type, category, value, to_ids, comment)
				 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
		).bind(
			a.uuid ?? crypto.randomUUID(),
			eventUuid,
			a.type,
			a.category,
			a.value,
			a.to_ids === true || a.to_ids === 1 ? 1 : 0,
			a.comment ?? null,
		),
	);
	if (attrStatements.length > 0) await c.env.DB.batch(attrStatements);

	const tags = incoming.Tag ?? [];
	if (tags.length > 0) {
		// ⚡ Bolt: Batch D1 queries for tag insertions to eliminate N+1 latency
		// when an event carries multiple tags.
		const tagStatements: D1PreparedStatement[] = [];
		for (const t of tags) {
			tagStatements.push(
				c.env.DB.prepare(`INSERT OR IGNORE INTO tags (name) VALUES (?1)`).bind(
					t.name,
				),
			);
			tagStatements.push(
				c.env.DB.prepare(
					`INSERT OR IGNORE INTO event_tags (event_uuid, tag_name) VALUES (?1, ?2)`,
				).bind(eventUuid, t.name),
			);
		}
		await c.env.DB.batch(tagStatements);
	}

	// Corroboration update (sync — keeps feed generation consistent; a Queue
	// push is also sent so the triage agent can dedupe/tag asynchronously).
	await applyCorroboration(c.env.DB, {
		event_uuid: eventUuid,
		orgc_uuid: org.uuid,
		sharing_group_uuid: incoming.sharing_group_uuid ?? null,
		attributes: incoming.Attribute.map((a) => ({
			type: a.type,
			value: a.value,
		})),
	});

	await c.env.TRIAGE_QUEUE.send({ kind: "event", event_uuid: eventUuid }).catch(
		(e) => console.error("triage enqueue failed:", (e as Error).message),
	);

	return c.json({ Event: { uuid: eventUuid } }, 201);
});

eventRoutes.get("/:uuid", async (c) => {
	const uuid = c.req.param("uuid");
	const event = await c.env.DB.prepare(
		`SELECT event_json, orgc_uuid, sharing_group_uuid FROM events WHERE uuid = ?1`,
	)
		.bind(uuid)
		.first<{
			event_json: string;
			orgc_uuid: string;
			sharing_group_uuid: string | null;
		}>();
	if (!event) return c.json({ error: "not found" }, 404);
	// Visibility: own org, or member of the event's sharing group.
	if (event.orgc_uuid !== c.var.org.uuid) {
		if (!event.sharing_group_uuid) return c.json({ error: "forbidden" }, 403);
		const mem = await c.env.DB.prepare(
			`SELECT 1 FROM sharing_group_orgs WHERE sharing_group_uuid = ?1 AND org_uuid = ?2`,
		)
			.bind(event.sharing_group_uuid, c.var.org.uuid)
			.first();
		if (!mem) return c.json({ error: "forbidden" }, 403);
	}
	return c.json(JSON.parse(event.event_json));
});

/** MISP `/events/restSearch`. Minimal filter set. */
const RestSearchSchema = z.object({
	returnFormat: z.literal("json").optional(),
	type: z.string().optional(),
	value: z.string().optional(),
	limit: z.number().int().min(1).max(1000).optional(),
	page: z.number().int().min(1).optional(),
});

eventRoutes.post("/restSearch", async (c) => {
	const parsed = RestSearchSchema.safeParse(
		await c.req.json().catch(() => ({})),
	);
	if (!parsed.success) return c.json({ error: parsed.error.flatten() }, 400);
	const { type, value, limit = 100, page = 1 } = parsed.data;
	const offset = (page - 1) * limit;

	// Visibility-aware — include own events plus events in any sharing group
	// the org belongs to.
	const membershipRows = await c.env.DB.prepare(
		`SELECT sharing_group_uuid FROM sharing_group_orgs WHERE org_uuid = ?1`,
	)
		.bind(c.var.org.uuid)
		.all<{ sharing_group_uuid: string }>();
	const visibleGroups = (membershipRows.results ?? []).map(
		(r) => r.sharing_group_uuid,
	);

	// Build WHERE via parameters.
	const whereParts: string[] = [
		`(e.orgc_uuid = ?1${visibleGroups.length > 0 ? ` OR e.sharing_group_uuid IN (${visibleGroups.map((_, i) => `?${i + 2}`).join(",")})` : ""})`,
	];
	const params: (string | number)[] = [c.var.org.uuid, ...visibleGroups];

	if (type) {
		whereParts.push(`a.type = ?${params.length + 1}`);
		params.push(type);
	}
	if (value) {
		whereParts.push(`a.value = ?${params.length + 1}`);
		params.push(value);
	}

	const join =
		type || value ? `JOIN attributes a ON a.event_uuid = e.uuid` : ``;
	params.push(limit, offset);

	const sql = `SELECT DISTINCT e.event_json FROM events e ${join}
		WHERE ${whereParts.join(" AND ")}
		ORDER BY e.timestamp DESC
		LIMIT ?${params.length - 1} OFFSET ?${params.length}`;

	const rows = await c.env.DB.prepare(sql)
		.bind(...params)
		.all<{ event_json: string }>();
	const events = (rows.results ?? []).map((r) => JSON.parse(r.event_json));
	return c.json({ response: events });
});
