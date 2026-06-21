// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// M1 (#376): D1-backed WebAuthn credential + challenge store. Runs in real
// workerd so `DELETE … RETURNING` atomicity and BLOB round-tripping match prod.
import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import {
	consumeChallenge,
	createCredential,
	deleteExpiredChallenges,
	getByCredentialId,
	listBySub,
	putChallenge,
	updateCounter,
} from "../../workers/lib/webauthn-store";

const db = () => env.WEBAUTHN_DB;

function sampleCredential(over: Partial<Parameters<typeof createCredential>[1]> = {}) {
	return {
		credentialId: "cred-abc",
		userSub: "user-1",
		publicKey: new Uint8Array([1, 2, 3, 250, 128, 0, 255]),
		counter: 0,
		transports: ["internal", "hybrid"],
		aaguid: "00000000-0000-0000-0000-000000000000",
		createdAt: 1_700_000_000_000,
		lastUsedAt: null,
		...over,
	};
}

describe("webauthn-store: credentials", () => {
	it("round-trips a credential through createCredential + getByCredentialId", async () => {
		const cred = sampleCredential();
		await createCredential(db(), cred);

		const got = await getByCredentialId(db(), "cred-abc");
		expect(got).not.toBeNull();
		expect(got!.credentialId).toBe("cred-abc");
		expect(got!.userSub).toBe("user-1");
		expect(Array.from(got!.publicKey)).toEqual([1, 2, 3, 250, 128, 0, 255]);
		expect(got!.counter).toBe(0);
		expect(got!.transports).toEqual(["internal", "hybrid"]);
		expect(got!.aaguid).toBe("00000000-0000-0000-0000-000000000000");
		expect(got!.createdAt).toBe(1_700_000_000_000);
		expect(got!.lastUsedAt).toBeNull();
	});

	it("getByCredentialId returns null for an unknown id", async () => {
		expect(await getByCredentialId(db(), "nope")).toBeNull();
	});

	it("listBySub returns all of a user's credentials and none for others", async () => {
		await createCredential(db(), sampleCredential({ credentialId: "c1", userSub: "u-list", createdAt: 1 }));
		await createCredential(db(), sampleCredential({ credentialId: "c2", userSub: "u-list", createdAt: 2 }));
		await createCredential(db(), sampleCredential({ credentialId: "c3", userSub: "other", createdAt: 3 }));

		const mine = await listBySub(db(), "u-list");
		expect(mine.map((c) => c.credentialId).sort()).toEqual(["c1", "c2"]);
		expect(await listBySub(db(), "nobody")).toEqual([]);
	});

	it("updateCounter advances the sign counter and stamps last_used_at", async () => {
		await createCredential(db(), sampleCredential({ credentialId: "c-upd", counter: 5 }));
		await updateCounter(db(), "c-upd", 6, 1_700_000_111_000);

		const got = await getByCredentialId(db(), "c-upd");
		expect(got!.counter).toBe(6);
		expect(got!.lastUsedAt).toBe(1_700_000_111_000);
	});
});

describe("webauthn-store: challenges (atomic single-use consume)", () => {
	it("consumeChallenge returns the row exactly once, then null", async () => {
		await putChallenge(db(), {
			challenge: "chal-1",
			userSub: "user-1",
			type: "authentication",
			payloadHash: "abc123",
			expiresAt: 9_999_999_999_999,
		});

		const first = await consumeChallenge(db(), "chal-1", 1_700_000_000_000);
		expect(first).not.toBeNull();
		expect(first!.userSub).toBe("user-1");
		expect(first!.type).toBe("authentication");
		expect(first!.payloadHash).toBe("abc123");

		// Second consume — already deleted by RETURNING; replay is rejected.
		const second = await consumeChallenge(db(), "chal-1", 1_700_000_000_000);
		expect(second).toBeNull();
	});

	it("consumeChallenge returns null for an expired challenge (and leaves it unconsumed)", async () => {
		await putChallenge(db(), {
			challenge: "chal-expired",
			userSub: "user-1",
			type: "authentication",
			payloadHash: "h",
			expiresAt: 1_000, // far in the past relative to `now`
		});
		const got = await consumeChallenge(db(), "chal-expired", 1_700_000_000_000);
		expect(got).toBeNull();
	});

	it("consumeChallenge returns null for an unknown challenge", async () => {
		expect(await consumeChallenge(db(), "ghost", 1_700_000_000_000)).toBeNull();
	});

	it("preserves a null payloadHash for registration challenges", async () => {
		await putChallenge(db(), {
			challenge: "chal-reg",
			userSub: "user-1",
			type: "registration",
			payloadHash: null,
			expiresAt: 9_999_999_999_999,
		});
		const got = await consumeChallenge(db(), "chal-reg", 1_700_000_000_000);
		expect(got!.type).toBe("registration");
		expect(got!.payloadHash).toBeNull();
	});
});

describe("webauthn-store: deleteExpiredChallenges (cron reap)", () => {
	// D1 storage persists across tests in this workers-pool suite (the other
	// suites lean on unique keys for the same reason), and the reap is a
	// table-wide DELETE — so to assert exact counts/snapshots we start each
	// test from a known-empty challenges table.
	beforeEach(async () => {
		await db().prepare("DELETE FROM webauthn_challenges").run();
	});

	// List the challenge keys still present, so we can assert exactly which rows
	// survived the reap rather than relying on consumeChallenge's own expiry gate.
	async function remainingChallenges(): Promise<string[]> {
		const { results } = await db()
			.prepare("SELECT challenge FROM webauthn_challenges ORDER BY challenge")
			.all<{ challenge: string }>();
		return results.map((r) => r.challenge);
	}

	it("removes only rows with expires_at <= now, leaves live rows, returns the count", async () => {
		const now = 1_700_000_000_000;
		// Two already-expired (one strictly past, one exactly at `now` — the
		// boundary consumeChallenge treats as non-consumable, so it must reap)
		// and two still-live challenges.
		await putChallenge(db(), { challenge: "exp-past", userSub: "u", type: "authentication", payloadHash: "h", expiresAt: now - 1 });
		await putChallenge(db(), { challenge: "exp-boundary", userSub: "u", type: "authentication", payloadHash: "h", expiresAt: now });
		await putChallenge(db(), { challenge: "live-1", userSub: "u", type: "authentication", payloadHash: "h", expiresAt: now + 1 });
		await putChallenge(db(), { challenge: "live-2", userSub: "u", type: "registration", payloadHash: null, expiresAt: now + 60_000 });

		const removed = await deleteExpiredChallenges(db(), now);
		expect(removed).toBe(2);
		expect(await remainingChallenges()).toEqual(["live-1", "live-2"]);

		// Surviving live rows are still consumable.
		expect(await consumeChallenge(db(), "live-1", now)).not.toBeNull();
	});

	it("is idempotent — a second reap with no expired rows returns 0", async () => {
		const now = 1_700_000_000_000;
		await putChallenge(db(), { challenge: "idem-expired", userSub: "u", type: "authentication", payloadHash: "h", expiresAt: now - 5 });
		await putChallenge(db(), { challenge: "idem-live", userSub: "u", type: "authentication", payloadHash: "h", expiresAt: now + 5 });

		expect(await deleteExpiredChallenges(db(), now)).toBe(1);
		expect(await deleteExpiredChallenges(db(), now)).toBe(0);
		expect(await remainingChallenges()).toEqual(["idem-live"]);
	});

	it("returns 0 against an empty table", async () => {
		expect(await deleteExpiredChallenges(db(), 1_700_000_000_000)).toBe(0);
	});
});
