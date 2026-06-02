-- Copyright (c) 2026 Cloudflare, Inc.
-- Licensed under the Apache 2.0 license found in the LICENSE file or at:
--     https://opensource.org/licenses/Apache-2.0

-- Operators can mark a peer discoverable so orgs can self-subscribe to its
-- feed without operator intervention (closes #29).
ALTER TABLE peers ADD COLUMN discoverable INTEGER NOT NULL DEFAULT 0;

-- Per-org peer subscriptions.  When an org subscribes to a peer, the inbound
-- sync writes corroboration rows to ALL sharing groups that org belongs to,
-- using trust_multiplier * synthetic_org.trust as the contribution weight.
-- This lets two orgs subscribed to different peers see different corroboration
-- scores for the same attribute.
CREATE TABLE org_peer_subscriptions (
    org_uuid TEXT NOT NULL,
    peer_uuid TEXT NOT NULL,
    trust_multiplier REAL NOT NULL DEFAULT 1.0,
    subscribed_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (org_uuid, peer_uuid),
    FOREIGN KEY (org_uuid) REFERENCES orgs(uuid) ON DELETE CASCADE,
    FOREIGN KEY (peer_uuid) REFERENCES peers(uuid) ON DELETE CASCADE
);
-- Fast lookup of all orgs subscribed to a given peer (used during inbound sync).
CREATE INDEX idx_org_peer_subs_peer ON org_peer_subscriptions(peer_uuid);
