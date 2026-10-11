-- Track when each org FIRST contributed to a corroboration row, so the
-- "corroborated since X" query can window on contributor-join time rather
-- than conflating it with `corroboration.last_seen` (issue #131).
--
-- first_seen is epoch MILLISECONDS (INTEGER), matching the `sinceMs` the
-- /corroboration route binds.
--
-- D1 CONSTRAINT: `ADD COLUMN` must use a CONSTANT default. A parenthesised
-- expression such as `DEFAULT (unixepoch() * 1000)` is rejected with
--   Cannot add a column with non-constant default: SQLITE_ERROR [code: 7500]
-- even though stock SQLite (better-sqlite3, which backs tests/helpers/d1.ts)
-- accepts it. Hence: constant default, then backfill. `tests/migrations-d1-
-- compat.test.ts` lints for this, because no better-sqlite3-backed test can.
--
-- Because the default is 0 rather than "now", every INSERT must supply
-- first_seen explicitly — see `recordContribution` in src/lib/aggregate.ts.
ALTER TABLE corroboration_contributors
    ADD COLUMN first_seen INTEGER NOT NULL DEFAULT 0;

-- Backfill existing rows from their corroboration's last_seen, the closest
-- available approximation of join time for rows that predate this column.
-- COALESCE guards an unparseable last_seen, which would otherwise violate
-- the NOT NULL constraint.
UPDATE corroboration_contributors
SET first_seen = COALESCE(
    (
        SELECT unixepoch(c.last_seen) * 1000
        FROM corroboration c
        WHERE c.id = corroboration_contributors.corroboration_id
    ),
    unixepoch() * 1000
)
WHERE EXISTS (
    SELECT 1 FROM corroboration c WHERE c.id = corroboration_contributors.corroboration_id
);

-- Orphan rows (no matching corroboration) get "now", preserving the original
-- intent of the non-constant default this migration used to carry.
UPDATE corroboration_contributors
SET first_seen = unixepoch() * 1000
WHERE first_seen = 0;

CREATE INDEX idx_corroboration_contributors_orgc_first_seen
    ON corroboration_contributors(orgc_uuid, first_seen);
