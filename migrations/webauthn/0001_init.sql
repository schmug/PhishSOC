-- WebAuthn step-up credential + challenge store (issue #376).
-- First D1 database in the project. Credentials are per-user (keyed by Access
-- `sub`), not per-mailbox, so a relational table is a better fit than the
-- per-mailbox MailboxDO SQLite or BLOOM_KV.

CREATE TABLE webauthn_credentials (
  credential_id TEXT PRIMARY KEY,
  user_sub      TEXT NOT NULL,
  public_key    BLOB NOT NULL,
  counter       INTEGER NOT NULL,
  transports    TEXT,
  aaguid        TEXT,
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER
);

CREATE INDEX idx_webauthn_cred_user ON webauthn_credentials(user_sub);

-- Server-issued, single-use challenges. Consumed atomically with
-- `DELETE ... RETURNING` (NOT get-then-delete, which is racy and replayable —
-- the exact bug #461 fixed for the confirm-token jti). Authentication
-- challenges are bound to the send `payload_hash`; registration challenges
-- carry a NULL payload_hash.
CREATE TABLE webauthn_challenges (
  challenge    TEXT PRIMARY KEY,
  user_sub     TEXT NOT NULL,
  type         TEXT NOT NULL,
  payload_hash TEXT,
  expires_at   INTEGER NOT NULL
);
