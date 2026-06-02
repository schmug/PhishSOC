// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Trust-weighted aggregation.
 *
 * When a new event lands, we update a per-(type, value, sharing_group) row in
 * `corroboration`. Each distinct contributor org contributes `org.trust`
 * points (first-time contribution only — de-duped via corroboration_contributors).
 *
 * An attribute promotes to a sharing group's public feed when BOTH:
 *   - score ≥ PROMOTION_SCORE
 *   - contributor_count ≥ PROMOTION_CONTRIBUTORS
 */

export const PROMOTION_SCORE = 2.0;
export const PROMOTION_CONTRIBUTORS = 2;

/** Attribute types that belong on the published destroylist feed. */
const PROMOTABLE_TYPES = new Set(["url", "domain", "hostname", "ip-src", "ip-dst", "sha256"]);

interface AggregateInput {
	event_uuid: string;
	orgc_uuid: string;
	sharing_group_uuid: string | null;
	attributes: Array<{ type: string; value: string }>;
	// When provided, skip the orgs table lookup and use this value directly.
	// Used by inbound sync to apply per-subscription trust multipliers without
	// an extra DB round-trip per event.
	trustOverride?: number;
}

export async function applyCorroboration(db: D1Database, input: AggregateInput) {
	let trust: number;
	if (input.trustOverride !== undefined) {
		trust = input.trustOverride;
	} else {
		const orgRow = await db
			.prepare(`SELECT trust FROM orgs WHERE uuid = ?1`)
			.bind(input.orgc_uuid)
			.first<{ trust: number }>();
		trust = orgRow?.trust ?? 1.0;
	}
	const now = new Date().toISOString();

	for (const attr of input.attributes) {
		if (!PROMOTABLE_TYPES.has(attr.type)) continue;

		// Upsert corroboration row
		await db
			.prepare(
				`INSERT INTO corroboration
				   (sharing_group_uuid, attribute_type, value, first_seen, last_seen, contributor_count, score)
				 VALUES (?1, ?2, ?3, ?4, ?4, 0, 0.0)
				 ON CONFLICT (sharing_group_uuid, attribute_type, value)
				 DO UPDATE SET last_seen = ?4`,
			)
			.bind(input.sharing_group_uuid, attr.type, attr.value, now)
			.run();

		const row = await db
			.prepare(
				`SELECT id FROM corroboration
				 WHERE (sharing_group_uuid IS ?1 OR (sharing_group_uuid IS NULL AND ?1 IS NULL))
				   AND attribute_type = ?2 AND value = ?3`,
			)
			.bind(input.sharing_group_uuid, attr.type, attr.value)
			.first<{ id: number }>();
		if (!row) continue;

		// Attempt contributor insert; if it's already there, INSERT OR IGNORE
		// is a no-op and we do not re-add their trust.
		const res = await db
			.prepare(
				`INSERT OR IGNORE INTO corroboration_contributors (corroboration_id, orgc_uuid)
				 VALUES (?1, ?2)`,
			)
			.bind(row.id, input.orgc_uuid)
			.run();

		const newlyAdded = (res.meta.changes ?? 0) > 0;
		if (newlyAdded) {
			await db
				.prepare(
					`UPDATE corroboration
					 SET contributor_count = contributor_count + 1,
					     score = score + ?1
					 WHERE id = ?2`,
				)
				.bind(trust, row.id)
				.run();
		}
	}
}

export interface PromotedEntry {
	attribute_type: string;
	value: string;
	score: number;
	contributor_count: number;
}

/**
 * Promoted entries visible to a caller for a given sharing group.
 *
 * The result is the union of:
 *   (a) cross-org-corroborated entries that meet the standard threshold
 *       (`score ≥ PROMOTION_SCORE AND contributor_count ≥ PROMOTION_CONTRIBUTORS`),
 *       visible to every caller — preserves sybil resistance for other orgs.
 *   (b) entries the caller's own org contributed itself, regardless of
 *       contributor_count. This lets sibling mailboxes inside the same org
 *       round-trip pre-block coverage from each other and lets fresh single-org
 *       deployments verify the report → publish loop without waiting for
 *       independent corroboration.
 *
 * The asymmetry only fires for the caller. Other orgs' single-contributor
 * entries remain hidden until they also cross the standard threshold.
 *
 * `callerOrgUuid` is optional for backward compat with callers that don't
 * scope to a calling org (e.g. internal stats); when omitted, only branch (a)
 * applies.
 */
export async function getPromotedForSharingGroup(
	db: D1Database,
	sharingGroupUuid: string | null,
	callerOrgUuid?: string | null,
): Promise<PromotedEntry[]> {
	const res = await db
		.prepare(
			`SELECT attribute_type, value, score, contributor_count
			 FROM corroboration c
			 WHERE (sharing_group_uuid IS ?1 OR (sharing_group_uuid IS NULL AND ?1 IS NULL))
			   AND (
			     (score >= ?2 AND contributor_count >= ?3)
			     OR (?4 IS NOT NULL AND EXISTS (
			       SELECT 1 FROM corroboration_contributors cc
			       WHERE cc.corroboration_id = c.id AND cc.orgc_uuid = ?4
			     ))
			   )
			 ORDER BY score DESC
			 LIMIT 50000`,
		)
		.bind(sharingGroupUuid, PROMOTION_SCORE, PROMOTION_CONTRIBUTORS, callerOrgUuid ?? null)
		.all<PromotedEntry>();
	return res.results ?? [];
}
