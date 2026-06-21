// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// D1-backed store for WebAuthn step-up (issue #376). Credentials are per-user
// (keyed by Access `sub`), not per-mailbox, so a relational table fits better
// than the per-mailbox MailboxDO SQLite or BLOOM_KV. Challenges are server-
// issued and single-use, consumed atomically with `DELETE … RETURNING` — never
// get-then-delete, which is racy and replayable (the bug #461 fixed for the
// confirm-token jti). Schema: migrations/webauthn/0001_init.sql.

export type ChallengeType = "registration" | "authentication";

export type StoredCredential = {
	credentialId: string;
	userSub: string;
	publicKey: Uint8Array;
	counter: number;
	transports: string[] | null;
	aaguid: string | null;
	createdAt: number;
	lastUsedAt: number | null;
};

export type NewCredential = {
	credentialId: string;
	userSub: string;
	publicKey: Uint8Array;
	counter: number;
	transports?: string[] | null;
	aaguid?: string | null;
	createdAt: number;
	lastUsedAt?: number | null;
};

export type StoredChallenge = {
	challenge: string;
	userSub: string;
	type: ChallengeType;
	payloadHash: string | null;
	expiresAt: number;
};

/** Copy a Uint8Array into a standalone ArrayBuffer for a D1 BLOB bind. */
function toBlob(u8: Uint8Array): ArrayBuffer {
	return u8.slice().buffer;
}

/** D1 may return a BLOB as ArrayBuffer or as number[]; normalize to bytes. */
function toBytes(value: unknown): Uint8Array {
	if (value instanceof ArrayBuffer) return new Uint8Array(value);
	if (value instanceof Uint8Array) return value;
	if (Array.isArray(value)) return Uint8Array.from(value as number[]);
	if (ArrayBuffer.isView(value)) {
		const v = value as ArrayBufferView;
		return new Uint8Array(v.buffer, v.byteOffset, v.byteLength).slice();
	}
	throw new Error("webauthn-store: unexpected public_key column type");
}

type CredentialRow = {
	credential_id: string;
	user_sub: string;
	public_key: unknown;
	counter: number;
	transports: string | null;
	aaguid: string | null;
	created_at: number;
	last_used_at: number | null;
};

function rowToCredential(row: CredentialRow): StoredCredential {
	return {
		credentialId: row.credential_id,
		userSub: row.user_sub,
		publicKey: toBytes(row.public_key),
		counter: Number(row.counter),
		transports: row.transports ? (JSON.parse(row.transports) as string[]) : null,
		aaguid: row.aaguid,
		createdAt: Number(row.created_at),
		lastUsedAt: row.last_used_at == null ? null : Number(row.last_used_at),
	};
}

export async function createCredential(db: D1Database, cred: NewCredential): Promise<void> {
	await db
		.prepare(
			`INSERT INTO webauthn_credentials
			   (credential_id, user_sub, public_key, counter, transports, aaguid, created_at, last_used_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		)
		.bind(
			cred.credentialId,
			cred.userSub,
			toBlob(cred.publicKey),
			cred.counter,
			cred.transports && cred.transports.length ? JSON.stringify(cred.transports) : null,
			cred.aaguid ?? null,
			cred.createdAt,
			cred.lastUsedAt ?? null,
		)
		.run();
}

export async function getByCredentialId(
	db: D1Database,
	credentialId: string,
): Promise<StoredCredential | null> {
	const row = await db
		.prepare("SELECT * FROM webauthn_credentials WHERE credential_id = ?")
		.bind(credentialId)
		.first<CredentialRow>();
	return row ? rowToCredential(row) : null;
}

export async function listBySub(db: D1Database, userSub: string): Promise<StoredCredential[]> {
	const { results } = await db
		.prepare("SELECT * FROM webauthn_credentials WHERE user_sub = ? ORDER BY created_at")
		.bind(userSub)
		.all<CredentialRow>();
	return results.map(rowToCredential);
}

export async function updateCounter(
	db: D1Database,
	credentialId: string,
	counter: number,
	lastUsedAt: number,
): Promise<void> {
	await db
		.prepare("UPDATE webauthn_credentials SET counter = ?, last_used_at = ? WHERE credential_id = ?")
		.bind(counter, lastUsedAt, credentialId)
		.run();
}

export async function putChallenge(db: D1Database, ch: StoredChallenge): Promise<void> {
	await db
		.prepare(
			`INSERT INTO webauthn_challenges (challenge, user_sub, type, payload_hash, expires_at)
			 VALUES (?, ?, ?, ?, ?)`,
		)
		.bind(ch.challenge, ch.userSub, ch.type, ch.payloadHash ?? null, ch.expiresAt)
		.run();
}

/**
 * Atomically consume a non-expired challenge. Returns the row on the single
 * successful consume and null thereafter (or if expired/unknown). The
 * `DELETE … RETURNING` is one statement, so two concurrent consumers cannot
 * both succeed — this is the replay defense, not a convenience.
 */
export async function consumeChallenge(
	db: D1Database,
	challenge: string,
	now: number,
): Promise<StoredChallenge | null> {
	const row = await db
		.prepare("DELETE FROM webauthn_challenges WHERE challenge = ? AND expires_at > ? RETURNING *")
		.bind(challenge, now)
		.first<{
			challenge: string;
			user_sub: string;
			type: string;
			payload_hash: string | null;
			expires_at: number;
		}>();
	if (!row) return null;
	return {
		challenge: row.challenge,
		userSub: row.user_sub,
		type: row.type as ChallengeType,
		payloadHash: row.payload_hash,
		expiresAt: Number(row.expires_at),
	};
}
