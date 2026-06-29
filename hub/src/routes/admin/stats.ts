// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * GET /admin/stats — at-a-glance hub operational health.
 *
 * Single JSON snapshot for an operator. Covers:
 *   - org & event counts (with 24h / 7d slices)
 *   - corroboration row count + promoted-to-destroylist count
 *   - destroylist sizes per sharing group
 *   - inbound peers: last pull time, last error, events pulled in last 24h
 *   - triage health: % of last-24h events that got LLM tags + count of
 *     events still untagged 15m after ingest (queue-backup smoke signal)
 *   - cron last-run proxy
 *
 * Index discipline. All counts come off D1 indexes from 0001_schema.sql
 * / 0002_inbound_sync.sql / 0004_idx_events_created_at.sql, plus a
 * single-row PK lookup against `cron_runs` (added in 0003_cron_runs.sql,
 * no index needed):
 *
 *   - `idx_events_created_at`     drives `events.last_24h` and the 7d
 *     org-activity window. Uses local ingest time so that backfilled
 *     events with stale upstream `date` still land in the day they
 *     were actually ingested — the right semantic for an at-a-glance
 *     operational dashboard.
 *   - `idx_events_date`           drives per-peer events_pulled_24h
 *     (upstream-date semantics) and the triage 24h slice (used as a
 *     bounded pre-filter for the non-indexed `created_at < -15m` and
 *     `EXISTS event_tags` predicates). Other `date`-based queries in
 *     the hub stay on this index.
 *   - `idx_events_source_peer`    drives per-peer events_pulled_24h.
 *   - `idx_corroboration_sharing_group` drives the destroylist groupby.
 *
 * Where a query needs a non-indexed predicate (e.g. the 15-minute
 * `created_at` filter for stuck-in-triage events), it is gated behind an
 * indexed pre-filter (`date >= today-1`) so the scan is bounded to a
 * single day's slice rather than the full table.
 *
 * `cron.last_run_at` is read directly from `cron_runs` (epoch-ms INTEGER),
 * which the cron handler stamps at the START of every iteration — so a
 * hung run that never reaches a peer is still observable. Returns null
 * when the table is empty (cron has not yet fired since deploy).
 */

import { Hono } from "hono";
import { requireAdmin, type AdminContext } from "../../lib/admin-auth";
import { PROMOTION_SCORE, PROMOTION_CONTRIBUTORS } from "../../lib/aggregate";
import { INBOUND_SYNC_CRON_NAME } from "../../lib/sync";

export const adminStatsRoutes = new Hono<AdminContext>();

adminStatsRoutes.use("*", requireAdmin);

interface CountRow {
	n: number;
}

adminStatsRoutes.get("/stats", async (c) => {
	const db = c.env.DB;

	// --- orgs -----------------------------------------------------------
	const orgsTotal =
		(await db.prepare(`SELECT COUNT(*) AS n FROM orgs`).first<CountRow>())?.n ??
		0;

	// "active" = has ingested at least one event in the last 7d. Uses
	// idx_events_created_at so a peer backfilling stale-dated events
	// counts the contributing org as active.
	const activeOrgs =
		(
			await db
				.prepare(
					`SELECT COUNT(DISTINCT orgc_uuid) AS n
			 FROM events
			 WHERE created_at >= datetime('now', '-7 days')`,
				)
				.first<CountRow>()
		)?.n ?? 0;

	// --- events ---------------------------------------------------------
	const eventsTotal =
		(await db.prepare(`SELECT COUNT(*) AS n FROM events`).first<CountRow>())
			?.n ?? 0;
	// 24h window keyed off local ingest time (idx_events_created_at) so
	// that an event imported today with a stale upstream `date` still
	// lands in today's bucket. Other event-time queries below stay on
	// `events.date` — see file-level note.
	const eventsLast24h =
		(
			await db
				.prepare(
					`SELECT COUNT(*) AS n FROM events WHERE created_at >= datetime('now', '-1 day')`,
				)
				.first<CountRow>()
		)?.n ?? 0;

	// --- corroboration --------------------------------------------------
	const corroborationRows =
		(
			await db
				.prepare(`SELECT COUNT(*) AS n FROM corroboration`)
				.first<CountRow>()
		)?.n ?? 0;
	// Use the same predicate `aggregate.ts` uses for promotion. Imported
	// rather than re-declared so a threshold change in one place can never
	// drift from the other.
	const corroborationPromoted =
		(
			await db
				.prepare(
					`SELECT COUNT(*) AS n FROM corroboration
			 WHERE score >= ?1 AND contributor_count >= ?2`,
				)
				.bind(PROMOTION_SCORE, PROMOTION_CONTRIBUTORS)
				.first<CountRow>()
		)?.n ?? 0;

	// --- destroylist size per sharing group -----------------------------
	const destroyRows = await db
		.prepare(
			`SELECT sg.uuid AS uuid, sg.name AS name, COUNT(c.id) AS size
			 FROM sharing_groups sg
			 LEFT JOIN corroboration c
			   ON c.sharing_group_uuid = sg.uuid
			   AND c.score >= ?1
			   AND c.contributor_count >= ?2
			 GROUP BY sg.uuid, sg.name
			 ORDER BY sg.name`,
		)
		.bind(PROMOTION_SCORE, PROMOTION_CONTRIBUTORS)
		.all<{ uuid: string; name: string; size: number }>();
	const destroylistBySharingGroup = (destroyRows.results ?? []).map((r) => ({
		uuid: r.uuid,
		name: r.name,
		size: r.size,
	}));

	// --- peers ----------------------------------------------------------
	// Two-step: (1) list peers, (2) for each peer count events_pulled_24h
	// off idx_events_source_peer + date predicate. Fan-out is bounded by
	// the peer count (small — operator config), so this is fine.
	const peerRows = await db
		.prepare(
			`SELECT ib.uuid AS inbound_uuid, p.name AS name,
			        ib.last_pulled_ts AS last_pulled_at,
			        ib.last_error AS last_error
			 FROM inbound_peers ib JOIN peers p ON p.uuid = ib.peer_uuid
			 ORDER BY p.name`,
		)
		.all<{
			inbound_uuid: string;
			name: string;
			last_pulled_at: string | null;
			last_error: string | null;
		}>();
	// ⚡ Bolt: Batch D1 queries for per-peer events_pulled_24h into a single
	// network request to eliminate N+1 query latency on the dashboard.
	const peersResult = peerRows.results ?? [];
	const peerQueries = peersResult.map((peer) =>
		db
			.prepare(
				`SELECT COUNT(*) AS n FROM events
				 WHERE source_peer_uuid = ?1
				   AND date >= date('now', '-1 day')`,
			)
			.bind(peer.inbound_uuid),
	);

	const batchResults =
		peerQueries.length > 0 ? await db.batch<CountRow>(peerQueries) : [];

	const peers = peersResult.map((peer, i) => {
		const resultGroup = batchResults[i];
		const pulledResult = resultGroup?.results?.[0];

		let pulled = 0;
		if (pulledResult && typeof pulledResult.n === "number") {
			pulled = pulledResult.n;
		} else if (
			Array.isArray(resultGroup) &&
			resultGroup[0] &&
			typeof resultGroup[0].n === "number"
		) {
			pulled = resultGroup[0].n;
		} else if (resultGroup && typeof resultGroup.n === "number") {
			pulled = resultGroup.n;
		}

		return {
			name: peer.name,
			last_pulled_at: peer.last_pulled_at,
			last_error: peer.last_error,
			events_pulled_24h: pulled,
		};
	});

	// --- triage health --------------------------------------------------
	// pct of last-24h events with at least one tag attached. The 24h slice
	// is selected via idx_events_date so this stays bounded.
	const taggedSummary = await db
		.prepare(
			`SELECT
			   COUNT(*) AS total,
			   SUM(CASE WHEN EXISTS (
			       SELECT 1 FROM event_tags et WHERE et.event_uuid = e.uuid
			   ) THEN 1 ELSE 0 END) AS tagged
			 FROM events e
			 WHERE date >= date('now', '-1 day')`,
		)
		.first<{ total: number; tagged: number | null }>();
	const total24 = taggedSummary?.total ?? 0;
	const tagged24 = taggedSummary?.tagged ?? 0;
	const eventsWithTagsPct24h = total24 > 0 ? tagged24 / total24 : 0;

	// "Untagged > 15 minutes after ingest" — symptom of a backed-up triage
	// queue (queue depth itself isn't queryable from a Worker). We narrow
	// to the last-24h slice via the indexed `date` column FIRST so the
	// non-indexed `created_at < now-15m` predicate only scans a day's
	// worth of rows in the worst case.
	const untaggedOlderThan15m =
		(
			await db
				.prepare(
					`SELECT COUNT(*) AS n FROM events e
			 WHERE date >= date('now', '-1 day')
			   AND created_at < datetime('now', '-15 minutes')
			   AND NOT EXISTS (
			     SELECT 1 FROM event_tags et WHERE et.event_uuid = e.uuid
			   )`,
				)
				.first<CountRow>()
		)?.n ?? 0;

	// --- cron -----------------------------------------------------------
	// Direct read from cron_runs (stamped at the START of each iteration by
	// the scheduled handler). Null when the table is empty — i.e. the cron
	// has not yet fired since deploy.
	const cronLast = await db
		.prepare(`SELECT last_run_at AS last FROM cron_runs WHERE name = ?1`)
		.bind(INBOUND_SYNC_CRON_NAME)
		.first<{ last: number | null }>();

	return c.json({
		orgs: { total: orgsTotal, active_last_7d: activeOrgs },
		events: { total: eventsTotal, last_24h: eventsLast24h },
		corroboration: { rows: corroborationRows, promoted: corroborationPromoted },
		destroylist: { by_sharing_group: destroylistBySharingGroup },
		peers,
		triage: {
			events_with_tags_pct_24h: Number(eventsWithTagsPct24h.toFixed(4)),
			untagged_older_than_15m: untaggedOlderThan15m,
		},
		cron: { last_run_at: cronLast?.last ?? null },
	});
});
