// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { webcrypto } from "node:crypto";
if (!(globalThis as unknown as { crypto?: unknown }).crypto) {
	(globalThis as unknown as { crypto: unknown }).crypto = webcrypto;
}

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Hono } from "hono";
import { peerRoutes } from "../../src/routes/peers";
import { sha256 } from "../../src/lib/hash";
import { makeTestDb, type TestDb } from "../helpers/d1";
import type { Env } from "../../src/types";

let db: TestDb;
let env: Env;

const ORG_UUID = "aaaaaaaa-0000-0000-0000-000000000001";
const ORG_KEY = "org-api-key-test";
const PEER_UUID_1 = "bbbbbbbb-0000-0000-0000-000000000001";
const PEER_UUID_2 = "bbbbbbbb-0000-0000-0000-000000000002";
const PEER_UUID_HIDDEN = "bbbbbbbb-0000-0000-0000-000000000003";

beforeEach(async () => {
	db = makeTestDb();
	env = {
		DB: db.d1,
		AI: {} as Ai,
		TRIAGE_QUEUE: { send: async () => {} } as never,
		HUB_ADMIN_KEY: "admin-secret",
	};

	const keyHash = await sha256(ORG_KEY);

	// Seed one org with an API key.
	db.raw
		.prepare(`INSERT INTO orgs (uuid, name, trust) VALUES (?, ?, ?)`)
		.run(ORG_UUID, "test-org", 1.0);
	db.raw
		.prepare(`INSERT INTO api_keys (key_hash, org_uuid, label, created_at) VALUES (?, ?, 'k', ?)`)
		.run(keyHash, ORG_UUID, new Date().toISOString());

	// Seed two discoverable peers and one hidden peer.
	db.raw
		.prepare(`INSERT INTO peers (uuid, name, discoverable) VALUES (?, ?, ?)`)
		.run(PEER_UUID_1, "Peer Alpha", 1);
	db.raw
		.prepare(`INSERT INTO peers (uuid, name, discoverable) VALUES (?, ?, ?)`)
		.run(PEER_UUID_2, "Peer Beta", 1);
	db.raw
		.prepare(`INSERT INTO peers (uuid, name, discoverable) VALUES (?, ?, ?)`)
		.run(PEER_UUID_HIDDEN, "Peer Hidden", 0);
});

afterEach(() => db.close());

function appReq(path: string, init?: RequestInit) {
	const app = new Hono<{ Bindings: typeof env }>();
	app.route("/peers", peerRoutes);
	return app.request(`/peers${path || ""}`, init, env as never);
}

const orgAuth = { Authorization: `Bearer ${ORG_KEY}` };

describe("GET /peers", () => {
	it("requires authentication", async () => {
		const res = await appReq("");
		expect(res.status).toBe(401);
	});

	it("returns only discoverable peers", async () => {
		const res = await appReq("", { headers: orgAuth });
		expect(res.status).toBe(200);
		const body = await res.json() as { peers: Array<{ uuid: string; subscribed: boolean }> };
		const uuids = body.peers.map((p) => p.uuid);
		expect(uuids).toContain(PEER_UUID_1);
		expect(uuids).toContain(PEER_UUID_2);
		expect(uuids).not.toContain(PEER_UUID_HIDDEN);
	});

	it("marks subscribed peers and includes trust_multiplier", async () => {
		// Subscribe to one peer.
		db.raw
			.prepare(
				`INSERT INTO org_peer_subscriptions (org_uuid, peer_uuid, trust_multiplier)
				 VALUES (?, ?, ?)`,
			)
			.run(ORG_UUID, PEER_UUID_1, 0.8);

		const res = await appReq("", { headers: orgAuth });
		const body = await res.json() as { peers: Array<{ uuid: string; subscribed: boolean; trust_multiplier: number | null }> };
		const alpha = body.peers.find((p) => p.uuid === PEER_UUID_1)!;
		const beta = body.peers.find((p) => p.uuid === PEER_UUID_2)!;
		expect(alpha.subscribed).toBe(true);
		expect(alpha.trust_multiplier).toBeCloseTo(0.8);
		expect(beta.subscribed).toBe(false);
		expect(beta.trust_multiplier).toBeNull();
	});

	it("returns empty list when no discoverable peers exist", async () => {
		db.raw.prepare(`UPDATE peers SET discoverable = 0`).run();
		const res = await appReq("", { headers: orgAuth });
		const body = await res.json() as { peers: unknown[] };
		expect(body.peers).toHaveLength(0);
	});
});

describe("POST /peers/:peer_uuid/subscribe", () => {
	it("requires authentication", async () => {
		const res = await appReq(`/${PEER_UUID_1}/subscribe`, { method: "POST" });
		expect(res.status).toBe(401);
	});

	it("subscribes with default trust_multiplier of 1.0", async () => {
		const res = await appReq(`/${PEER_UUID_1}/subscribe`, {
			method: "POST",
			headers: { ...orgAuth, "Content-Type": "application/json" },
			body: JSON.stringify({}),
		});
		expect(res.status).toBe(201);
		const body = await res.json() as { ok: boolean; trust_multiplier: number };
		expect(body.ok).toBe(true);
		expect(body.trust_multiplier).toBeCloseTo(1.0);

		const row = db.raw
			.prepare(`SELECT trust_multiplier FROM org_peer_subscriptions WHERE org_uuid = ? AND peer_uuid = ?`)
			.get(ORG_UUID, PEER_UUID_1) as { trust_multiplier: number } | undefined;
		expect(row?.trust_multiplier).toBeCloseTo(1.0);
	});

	it("subscribes with custom trust_multiplier", async () => {
		const res = await appReq(`/${PEER_UUID_2}/subscribe`, {
			method: "POST",
			headers: { ...orgAuth, "Content-Type": "application/json" },
			body: JSON.stringify({ trust_multiplier: 0.5 }),
		});
		expect(res.status).toBe(201);
		const row = db.raw
			.prepare(`SELECT trust_multiplier FROM org_peer_subscriptions WHERE org_uuid = ? AND peer_uuid = ?`)
			.get(ORG_UUID, PEER_UUID_2) as { trust_multiplier: number };
		expect(row.trust_multiplier).toBeCloseTo(0.5);
	});

	it("upserts trust_multiplier on re-subscribe", async () => {
		await appReq(`/${PEER_UUID_1}/subscribe`, {
			method: "POST",
			headers: { ...orgAuth, "Content-Type": "application/json" },
			body: JSON.stringify({ trust_multiplier: 0.5 }),
		});
		await appReq(`/${PEER_UUID_1}/subscribe`, {
			method: "POST",
			headers: { ...orgAuth, "Content-Type": "application/json" },
			body: JSON.stringify({ trust_multiplier: 0.9 }),
		});
		const row = db.raw
			.prepare(`SELECT trust_multiplier FROM org_peer_subscriptions WHERE org_uuid = ? AND peer_uuid = ?`)
			.get(ORG_UUID, PEER_UUID_1) as { trust_multiplier: number };
		expect(row.trust_multiplier).toBeCloseTo(0.9);
		// Only one row in the table.
		const count = db.raw
			.prepare(`SELECT COUNT(*) AS n FROM org_peer_subscriptions WHERE org_uuid = ?`)
			.get(ORG_UUID) as { n: number };
		expect(count.n).toBe(1);
	});

	it("returns 404 for unknown peer", async () => {
		const res = await appReq("/00000000-0000-0000-0000-000000000099/subscribe", {
			method: "POST",
			headers: { ...orgAuth, "Content-Type": "application/json" },
			body: JSON.stringify({}),
		});
		expect(res.status).toBe(404);
	});

	it("allows subscribing to a non-discoverable peer (by UUID)", async () => {
		const res = await appReq(`/${PEER_UUID_HIDDEN}/subscribe`, {
			method: "POST",
			headers: { ...orgAuth, "Content-Type": "application/json" },
			body: JSON.stringify({}),
		});
		expect(res.status).toBe(201);
	});

	it("rejects trust_multiplier outside [0, 10]", async () => {
		const res = await appReq(`/${PEER_UUID_1}/subscribe`, {
			method: "POST",
			headers: { ...orgAuth, "Content-Type": "application/json" },
			body: JSON.stringify({ trust_multiplier: 99 }),
		});
		expect(res.status).toBe(400);
	});
});

describe("DELETE /peers/:peer_uuid/subscribe", () => {
	it("requires authentication", async () => {
		const res = await appReq(`/${PEER_UUID_1}/subscribe`, { method: "DELETE" });
		expect(res.status).toBe(401);
	});

	it("removes an existing subscription and returns 204", async () => {
		db.raw
			.prepare(`INSERT INTO org_peer_subscriptions (org_uuid, peer_uuid) VALUES (?, ?)`)
			.run(ORG_UUID, PEER_UUID_1);

		const res = await appReq(`/${PEER_UUID_1}/subscribe`, { method: "DELETE", headers: orgAuth });
		expect(res.status).toBe(204);
		const row = db.raw
			.prepare(`SELECT 1 FROM org_peer_subscriptions WHERE org_uuid = ? AND peer_uuid = ?`)
			.get(ORG_UUID, PEER_UUID_1);
		expect(row).toBeUndefined();
	});

	it("returns 404 when not subscribed", async () => {
		const res = await appReq(`/${PEER_UUID_1}/subscribe`, { method: "DELETE", headers: orgAuth });
		expect(res.status).toBe(404);
	});

	it("does not affect subscriptions for other orgs", async () => {
		const otherOrgUuid = "cccccccc-0000-0000-0000-000000000001";
		db.raw.prepare(`INSERT INTO orgs (uuid, name, trust) VALUES (?, ?, ?)`)
			.run(otherOrgUuid, "other-org", 1.0);
		db.raw
			.prepare(`INSERT INTO org_peer_subscriptions (org_uuid, peer_uuid) VALUES (?, ?)`)
			.run(ORG_UUID, PEER_UUID_1);
		db.raw
			.prepare(`INSERT INTO org_peer_subscriptions (org_uuid, peer_uuid) VALUES (?, ?)`)
			.run(otherOrgUuid, PEER_UUID_1);

		await appReq(`/${PEER_UUID_1}/subscribe`, { method: "DELETE", headers: orgAuth });

		const otherRow = db.raw
			.prepare(`SELECT 1 FROM org_peer_subscriptions WHERE org_uuid = ? AND peer_uuid = ?`)
			.get(otherOrgUuid, PEER_UUID_1);
		expect(otherRow).toBeDefined();
	});
});
