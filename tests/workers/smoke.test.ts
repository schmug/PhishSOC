// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// M0 gate (#376): prove the workers-pool runs in workerd and the test D1 has
// the migrations/webauthn schema applied.
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("workers-pool D1 smoke (#376 M0)", () => {
	it("WEBAUTHN_DB is bound and the migrated schema exists", async () => {
		const { results } = await env.WEBAUTHN_DB.prepare(
			"SELECT name FROM sqlite_master WHERE type='table' AND name IN ('webauthn_credentials','webauthn_challenges') ORDER BY name",
		).all<{ name: string }>();
		expect(results.map((r) => r.name)).toEqual([
			"webauthn_challenges",
			"webauthn_credentials",
		]);
	});

	it("round-trips a row through the test D1", async () => {
		await env.WEBAUTHN_DB.prepare(
			"INSERT INTO webauthn_challenges (challenge, user_sub, type, payload_hash, expires_at) VALUES (?,?,?,?,?)",
		)
			.bind("c1", "sub1", "authentication", "hash1", 9999999999999)
			.run();
		const row = await env.WEBAUTHN_DB.prepare(
			"SELECT user_sub FROM webauthn_challenges WHERE challenge=?",
		)
			.bind("c1")
			.first<{ user_sub: string }>();
		expect(row?.user_sub).toBe("sub1");
	});
});
