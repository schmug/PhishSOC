// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for the domain-onboarding endpoints (#181):
 *   GET /api/v1/config  — union of env.DOMAINS seed + org-stored domains
 *   POST /api/v1/org/domains — add a domain (rejects duplicate / invalid)
 *   DELETE /api/v1/org/domains/:domain — remove a domain
 *
 * Also covers the `stripDefaultEqual` "domains" case so an empty array is not
 * persisted as `"domains": []` on the written blob.
 *
 * The test rebuilds minimal Hono handlers (same pattern as me.test.ts) rather
 * than importing the full workers/index.ts graph.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { stripDefaultEqual } from "../../workers/lib/mailbox-settings";

// ---------------------------------------------------------------------------
// Shared in-memory "R2 bucket" stub
// ---------------------------------------------------------------------------

function makeR2Stub(initial: Record<string, string> = {}) {
	const store = { ...initial };
	return {
		async get(key: string) {
			const val = store[key];
			if (!val) return null;
			return {
				json: async <T>() => JSON.parse(val) as T,
				etag: "stub-etag",
			};
		},
		async put(key: string, value: string) {
			store[key] = value;
		},
		_read: (key: string) => store[key],
	};
}

// ---------------------------------------------------------------------------
// Inline copies of the helpers under test (mirrors production code in
// workers/index.ts) so the test doesn't import the full worker graph.
// ---------------------------------------------------------------------------

function isValidRegistrableDomain(d: string): boolean {
	if (!d || d.length > 253) return false;
	if (d.includes("://") || d.includes("/") || d.includes("@") || d.includes(" ")) return false;
	const labels = d.split(".");
	if (labels.length < 2) return false;
	return labels.every((l) => l.length > 0 && /^[a-zA-Z0-9-]+$/.test(l));
}

type OrgSettings = { domains?: string[]; [k: string]: unknown };

function makeApp(seedDomains: string, orgStore: ReturnType<typeof makeR2Stub>) {
	const app = new Hono<{ Bindings: { DOMAINS: string; BUCKET: typeof orgStore } }>();

	// Mirror of GET /api/v1/config
	app.get("/api/v1/config", async (c) => {
		const seedRaw = (c.env.DOMAINS as string) || "";
		const seedList = seedRaw.split(",").map((d) => d.trim()).filter(Boolean);
		const settingsObj = await (c.env.BUCKET as typeof orgStore).get("org/settings.json");
		const orgSettings: OrgSettings = settingsObj ? await settingsObj.json() : {};
		const orgList = (orgSettings.domains as string[] | undefined) ?? [];
		const seen = new Set<string>();
		const domains: string[] = [];
		for (const d of [...seedList, ...orgList]) {
			const key = d.toLowerCase();
			if (!seen.has(key)) { seen.add(key); domains.push(d); }
		}
		return c.json({ domains, emailAddresses: [] });
	});

	// Mirror of POST /api/v1/org/domains
	app.post("/api/v1/org/domains", async (c) => {
		const body = (await c.req.json().catch(() => ({}))) as { domain?: unknown };
		const domain = typeof body.domain === "string" ? body.domain.trim().toLowerCase() : "";
		if (!isValidRegistrableDomain(domain)) {
			return c.json({ error: "Invalid domain" }, 400);
		}
		const settingsObj = await (c.env.BUCKET as typeof orgStore).get("org/settings.json");
		const current: OrgSettings = settingsObj ? await settingsObj.json() : {};
		const existing = (current.domains as string[] | undefined) ?? [];
		if (existing.some((d) => d.toLowerCase() === domain)) {
			return c.json({ error: "Domain already exists" }, 409);
		}
		const updated = { ...current, domains: [...existing, domain] };
		const stripped = stripDefaultEqual(updated as Record<string, unknown>);
		await (c.env.BUCKET as typeof orgStore).put("org/settings.json", JSON.stringify(stripped));
		return c.json(
			{ domain, domains: (stripped.domains as string[] | undefined) ?? [] },
			201,
		);
	});

	// Mirror of DELETE /api/v1/org/domains/:domain
	app.delete("/api/v1/org/domains/:domain", async (c) => {
		const target = decodeURIComponent(c.req.param("domain")!).toLowerCase();
		const settingsObj = await (c.env.BUCKET as typeof orgStore).get("org/settings.json");
		const current: OrgSettings = settingsObj ? await settingsObj.json() : {};
		const existing = (current.domains as string[] | undefined) ?? [];
		const next = existing.filter((d) => d.toLowerCase() !== target);
		if (next.length === existing.length) {
			return c.json({ error: "Domain not found" }, 404);
		}
		const updated = { ...current, domains: next };
		const stripped = stripDefaultEqual(updated as Record<string, unknown>);
		await (c.env.BUCKET as typeof orgStore).put("org/settings.json", JSON.stringify(stripped));
		return c.json({ domains: (stripped.domains as string[] | undefined) ?? [] });
	});

	// Mirror of PUT /api/v1/org/settings — must strip default-equal fields
	// before persisting (F-001), the same as the domain and mailbox PUT paths.
	app.put("/api/v1/org/settings", async (c) => {
		const body = (await c.req.json().catch(() => ({}))) as { settings?: unknown };
		const incoming = (body.settings ?? {}) as Record<string, unknown>;
		const stripped = stripDefaultEqual(incoming);
		await (c.env.BUCKET as typeof orgStore).put("org/settings.json", JSON.stringify(stripped));
		return c.json({ settings: stripped });
	});

	return app;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("GET /api/v1/config — domain union (#181)", () => {
	it("returns seed domains when no org domains stored", async () => {
		const bucket = makeR2Stub();
		const app = makeApp("seed.example,other.example", bucket);
		const res = await app.request("/api/v1/config", {}, { DOMAINS: "seed.example,other.example", BUCKET: bucket });
		expect(res.status).toBe(200);
		const body = (await res.json()) as { domains: string[] };
		expect(body.domains).toEqual(["seed.example", "other.example"]);
	});

	it("unions seed + org-stored domains, deduplicates", async () => {
		const bucket = makeR2Stub({ "org/settings.json": JSON.stringify({ domains: ["added.example", "seed.example"] }) });
		const app = makeApp("seed.example,base.example", bucket);
		const res = await app.request("/api/v1/config", {}, { DOMAINS: "seed.example,base.example", BUCKET: bucket });
		expect(res.status).toBe(200);
		const body = (await res.json()) as { domains: string[] };
		// seed first, no duplicates (seed.example appears once)
		expect(body.domains).toContain("seed.example");
		expect(body.domains).toContain("base.example");
		expect(body.domains).toContain("added.example");
		expect(body.domains.filter((d) => d === "seed.example")).toHaveLength(1);
	});
});

describe("POST /api/v1/org/domains — add domain (#181)", () => {
	it("adds a valid domain and returns 201", async () => {
		const bucket = makeR2Stub();
		const app = makeApp("", bucket);
		const res = await app.request(
			"/api/v1/org/domains",
			{ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: "acme.example" }) },
			{ DOMAINS: "", BUCKET: bucket },
		);
		expect(res.status).toBe(201);
		const body = (await res.json()) as { domain: string; domains: string[] };
		expect(body.domain).toBe("acme.example");
		expect(body.domains).toContain("acme.example");
	});

	it("rejects a duplicate domain with 409", async () => {
		const bucket = makeR2Stub({ "org/settings.json": JSON.stringify({ domains: ["acme.example"] }) });
		const app = makeApp("", bucket);
		const res = await app.request(
			"/api/v1/org/domains",
			{ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: "acme.example" }) },
			{ DOMAINS: "", BUCKET: bucket },
		);
		expect(res.status).toBe(409);
	});

	it("rejects an invalid domain with 400", async () => {
		const bucket = makeR2Stub();
		const app = makeApp("", bucket);
		for (const bad of ["", "no-tld", "has@at.com", "has/path.com", "https://example.com"]) {
			const res = await app.request(
				"/api/v1/org/domains",
				{ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: bad }) },
				{ DOMAINS: "", BUCKET: bucket },
			);
			expect(res.status, `expected 400 for "${bad}"`).toBe(400);
		}
	});
});

describe("DELETE /api/v1/org/domains/:domain — remove domain (#181)", () => {
	it("removes an existing domain", async () => {
		const bucket = makeR2Stub({ "org/settings.json": JSON.stringify({ domains: ["acme.example", "beta.example"] }) });
		const app = makeApp("", bucket);
		const res = await app.request(
			"/api/v1/org/domains/acme.example",
			{ method: "DELETE" },
			{ DOMAINS: "", BUCKET: bucket },
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { domains: string[] };
		expect(body.domains).not.toContain("acme.example");
		expect(body.domains).toContain("beta.example");
	});

	it("returns 404 for a domain not in the list", async () => {
		const bucket = makeR2Stub({ "org/settings.json": JSON.stringify({ domains: ["acme.example"] }) });
		const app = makeApp("", bucket);
		const res = await app.request(
			"/api/v1/org/domains/nothere.example",
			{ method: "DELETE" },
			{ DOMAINS: "", BUCKET: bucket },
		);
		expect(res.status).toBe(404);
	});
});

describe("stripDefaultEqual — domains field (#181)", () => {
	it("strips domains when the array is empty", () => {
		const result = stripDefaultEqual({ domains: [] as string[], agentModel: "gpt-4o" });
		expect(result).not.toHaveProperty("domains");
	});

	it("keeps domains when the array is non-empty", () => {
		const result = stripDefaultEqual({ domains: ["acme.example"] });
		expect(result.domains).toEqual(["acme.example"]);
	});

	it("does not persist 'domains: []' after removing the last domain", async () => {
		const bucket = makeR2Stub({ "org/settings.json": JSON.stringify({ domains: ["only.example"] }) });
		const app = makeApp("", bucket);
		await app.request(
			"/api/v1/org/domains/only.example",
			{ method: "DELETE" },
			{ DOMAINS: "", BUCKET: bucket },
		);
		const stored = bucket._read("org/settings.json");
		const parsed = JSON.parse(stored) as Record<string, unknown>;
		expect(parsed).not.toHaveProperty("domains");
	});
});

describe("PUT /api/v1/org/settings — strips rendered defaults before persist (F-001)", () => {
	it("does not persist a default-equal field as an explicit org-tier override", async () => {
		const bucket = makeR2Stub();
		const app = makeApp("", bucket);
		const res = await app.request(
			"/api/v1/org/settings",
			{
				method: "PUT",
				headers: { "content-type": "application/json" },
				// `domains: []` equals the system default; a real save with rendered
				// defaults must not pin it as an explicit override that shadows
				// inheritance. A genuine non-default value is preserved.
				body: JSON.stringify({ settings: { domains: [], agentModel: "custom-model" } }),
			},
			{ DOMAINS: "", BUCKET: bucket },
		);
		expect(res.status).toBe(200);
		const stored = JSON.parse(bucket._read("org/settings.json")) as Record<string, unknown>;
		expect(stored).not.toHaveProperty("domains");
		expect(stored.agentModel).toBe("custom-model");
	});
});
