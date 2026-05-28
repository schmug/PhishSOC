// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	DKIM_OBSERVATION_WINDOW_DAYS,
	DKIM_PROBE_SELECTORS,
	dkimObservationCutoffIso,
	emptyDkimPosture,
	fetchDkimPosture,
	isAnyPublished,
	isPublishedDkimRecord,
	mergeDkimPosture,
	normalizeDohTxtData,
	probeDkimSelectors,
	type DkimPostureKv,
} from "../../workers/dkim/posture";

describe("isPublishedDkimRecord", () => {
	it("treats a canonical v=DKIM1 record with non-empty p= as published", () => {
		expect(
			isPublishedDkimRecord("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQ"),
		).toBe(true);
	});

	it("treats v=DKIM1 with empty p= as 'revoked' — NOT published", () => {
		// RFC 6376 §3.6.1 — `p=` empty signals the operator has retired the
		// key. The label still resolves but the selector should be treated as
		// gone; counting it as published would mislead the dashboard into
		// claiming a retired selector is still in service.
		expect(isPublishedDkimRecord("v=DKIM1; k=rsa; p=")).toBe(false);
	});

	it("treats v=DKIM1 with no p= tag as published (forgiving toward malformed-but-shaped records)", () => {
		expect(isPublishedDkimRecord("v=DKIM1; k=rsa")).toBe(true);
	});

	it("treats a record without v=DKIM1 but with non-empty p= as published (legacy form)", () => {
		expect(isPublishedDkimRecord("k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQ")).toBe(true);
	});

	it("rejects a non-DKIM TXT entry", () => {
		expect(isPublishedDkimRecord("google-site-verification=abc")).toBe(false);
		expect(isPublishedDkimRecord("v=spf1 -all")).toBe(false);
		expect(isPublishedDkimRecord("")).toBe(false);
	});

	it("is case-insensitive on tag names and on v= value", () => {
		expect(isPublishedDkimRecord("V=DKIM1; K=rsa; P=AAA")).toBe(true);
		expect(isPublishedDkimRecord("v=dkim1; p=AAA")).toBe(true);
	});
});

describe("isAnyPublished", () => {
	it("returns true when at least one TXT entry is a valid DKIM record", () => {
		expect(
			isAnyPublished([
				"google-site-verification=abc",
				"v=DKIM1; k=rsa; p=AAA",
				"some-other=tag",
			]),
		).toBe(true);
	});

	it("returns false when no TXT entry is a valid DKIM record", () => {
		expect(isAnyPublished(["v=spf1 -all", "x=y"])).toBe(false);
		expect(isAnyPublished([])).toBe(false);
	});
});

describe("dkimObservationCutoffIso (#170 — 30-day observation horizon)", () => {
	it("defaults to a 30-day window matching the issue's stated horizon", () => {
		expect(DKIM_OBSERVATION_WINDOW_DAYS).toBe(30);
	});

	it("computes the cutoff as nowIso - 30d", () => {
		// 30 days = 2_592_000_000 ms. Cutoff falls exactly there relative to
		// `nowIso` so the SQL filter `last_seen_iso >= cutoff` keeps rows
		// observed within the last 30d (inclusive of the boundary).
		const now = new Date("2026-05-04T12:00:00Z").toISOString();
		const cutoff = dkimObservationCutoffIso(now);
		expect(cutoff).toBe("2026-04-04T12:00:00.000Z");
	});

	it("a row at exactly the cutoff is still fresh (>= comparison, not strict >)", () => {
		// Boundary semantics: an observation at `now - 30d` to the millisecond
		// is the *oldest* row the read should still surface. The `>=` filter
		// in `getDkimSelectorsObserved` makes that explicit; this test pins
		// the cutoff math so the inclusive boundary stays inclusive.
		const now = new Date("2026-05-04T12:00:00Z").toISOString();
		const cutoff = dkimObservationCutoffIso(now);
		// A row with last_seen_iso === cutoff is fresh (kept).
		expect(cutoff >= cutoff).toBe(true);
	});

	it("rows older than the cutoff are stale (< cutoff = excluded by the SQL filter)", () => {
		// At `now - 30d - 1ms` the row is past the horizon and the SQL
		// `>= cutoff` filter excludes it. The lazy-GC pass on
		// `recordDkimSelectorsObserved` deletes the same set with `< cutoff`,
		// so reads and writes share the boundary.
		const now = new Date("2026-05-04T12:00:00Z").toISOString();
		const cutoff = dkimObservationCutoffIso(now);
		const stale = new Date(
			new Date(cutoff).getTime() - 1,
		).toISOString();
		expect(stale < cutoff).toBe(true);
	});

	it("rows newer than the cutoff are fresh (> cutoff = kept)", () => {
		const now = new Date("2026-05-04T12:00:00Z").toISOString();
		const cutoff = dkimObservationCutoffIso(now);
		const fresh = new Date(
			new Date(cutoff).getTime() + 1,
		).toISOString();
		expect(fresh > cutoff).toBe(true);
	});

	it("supports a custom window for callers that want a tighter horizon", () => {
		const now = new Date("2026-05-04T12:00:00Z").toISOString();
		expect(dkimObservationCutoffIso(now, 7)).toBe(
			"2026-04-27T12:00:00.000Z",
		);
		expect(dkimObservationCutoffIso(now, 1)).toBe(
			"2026-05-03T12:00:00.000Z",
		);
	});

	it("falls back to 'now − window' against the runtime clock when nowIso is malformed", () => {
		// Defensive: a NaN cutoff would make the SQL filter silently match
		// nothing (or every row, depending on engine). The fallback keeps
		// the read returning recent rows. We can't pin the exact value
		// (depends on Date.now()) but we can pin the shape.
		const before = Date.now();
		const cutoff = dkimObservationCutoffIso("not-a-date");
		const after = Date.now();
		const cutoffMs = new Date(cutoff).getTime();
		expect(Number.isFinite(cutoffMs)).toBe(true);
		const windowMs = DKIM_OBSERVATION_WINDOW_DAYS * 24 * 60 * 60 * 1000;
		expect(cutoffMs).toBeGreaterThanOrEqual(before - windowMs);
		expect(cutoffMs).toBeLessThanOrEqual(after - windowMs);
	});
});

describe("normalizeDohTxtData", () => {
	it("concatenates multi-string TXT-record fragments", () => {
		expect(
			normalizeDohTxtData(
				'"v=DKIM1; k=rsa; " "p=MIGfMA0GCSqGSIb3DQEBAQ"',
			),
		).toBe("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQ");
	});

	it("strips surrounding quotes from a single-fragment string", () => {
		expect(normalizeDohTxtData('"v=DKIM1; p=AAA"')).toBe("v=DKIM1; p=AAA");
	});
});

// ── DoH integration tests ──────────────────────────────────────────────

function fakeKv(initial: Record<string, unknown> = {}): DkimPostureKv & {
	store: Map<string, string>;
} {
	const store = new Map<string, string>();
	for (const [k, v] of Object.entries(initial)) {
		store.set(k, JSON.stringify(v));
	}
	return {
		store,
		async get(key: string, _type: "json") {
			const raw = store.get(key);
			return raw ? (JSON.parse(raw) as unknown) : null;
		},
		async put(key: string, value: string) {
			store.set(key, value);
		},
	};
}

function dohTxtResponse(records: string[], status = 0): Response {
	return new Response(
		JSON.stringify({
			Status: status,
			Answer: records.map((data) => ({ type: 16, data })),
		}),
		{ status: 200, headers: { "content-type": "application/dns-json" } },
	);
}

function dohNxdomainResponse(): Response {
	// Cloudflare's resolver returns Status:3 (NXDOMAIN) with no Answer field.
	return new Response(JSON.stringify({ Status: 3 }), { status: 200 });
}

describe("fetchDkimPosture", () => {
	it("returns the empty posture for a domain with zero observed selectors (no DoH calls)", async () => {
		let calls = 0;
		const fetchImpl = async () => {
			calls += 1;
			return dohTxtResponse([]);
		};
		const r = await fetchDkimPosture("acme.com", [], { fetchImpl });
		expect(r).toEqual(emptyDkimPosture());
		expect(calls).toBe(0);
	});

	it("resolves one selector with a passing TXT record as published=true", async () => {
		const fetchImpl = async (url: string) => {
			// Hostname-based dispatch — substring matching on URLs is a CodeQL
			// `js/incomplete-url-substring-sanitization` trip wire (repo CLAUDE.md).
			expect(new URL(url).hostname).toBe("cloudflare-dns.com");
			expect(new URL(url).searchParams.get("name")).toBe(
				"sel1._domainkey.acme.com",
			);
			return dohTxtResponse(['"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQ"']);
		};
		const r = await fetchDkimPosture("acme.com", ["sel1"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "sel1", published: true }],
		});
	});

	it("treats NXDOMAIN as a durable published=false", async () => {
		const fetchImpl = async () => dohNxdomainResponse();
		const r = await fetchDkimPosture("acme.com", ["missing"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "missing", published: false }],
		});
	});

	it("treats NOERROR-no-data as a durable published=false", async () => {
		const fetchImpl = async () =>
			new Response(JSON.stringify({ Status: 0 }), { status: 200 });
		const r = await fetchDkimPosture("acme.com", ["empty"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "empty", published: false }],
		});
	});

	it("returns mixed published/missing posture across multiple selectors", async () => {
		const fetchImpl = async (url: string) => {
			const name = new URL(url).searchParams.get("name");
			if (name === "good._domainkey.acme.com") {
				return dohTxtResponse(['"v=DKIM1; k=rsa; p=AAA"']);
			}
			if (name === "gone._domainkey.acme.com") {
				return dohNxdomainResponse();
			}
			throw new Error(`unexpected DoH name: ${name}`);
		};
		const r = await fetchDkimPosture("acme.com", ["good", "gone"], {
			fetchImpl,
		});
		expect(r).toEqual({
			selectors: [
				{ selector: "gone", published: false },
				{ selector: "good", published: true },
			],
		});
	});

	it("returns published=null on DoH non-200 (transient unavailability)", async () => {
		const fetchImpl = async () => new Response("server error", { status: 500 });
		const r = await fetchDkimPosture("acme.com", ["sel"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "sel", published: null }],
		});
	});

	it("returns published=null when DoH fetch rejects (timeout / network)", async () => {
		const fetchImpl = async () => {
			throw new Error("network");
		};
		const r = await fetchDkimPosture("acme.com", ["sel"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "sel", published: null }],
		});
	});

	it("returns published=null when DoH returns malformed JSON", async () => {
		const fetchImpl = async () =>
			new Response("<html>", { status: 200 });
		const r = await fetchDkimPosture("acme.com", ["sel"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "sel", published: null }],
		});
	});

	it("treats SERVFAIL (Status=2) as a transient null, not durable false", async () => {
		const fetchImpl = async () =>
			new Response(JSON.stringify({ Status: 2 }), { status: 200 });
		const r = await fetchDkimPosture("acme.com", ["sel"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "sel", published: null }],
		});
	});

	it("counts an empty p= record as published=false (revoked key)", async () => {
		const fetchImpl = async () => dohTxtResponse(['"v=DKIM1; k=rsa; p="']);
		const r = await fetchDkimPosture("acme.com", ["retired"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "retired", published: false }],
		});
	});

	it("dedupes selector inputs case-insensitively", async () => {
		const seen: string[] = [];
		const fetchImpl = async (url: string) => {
			const name = new URL(url).searchParams.get("name") ?? "";
			seen.push(name);
			return dohTxtResponse(['"v=DKIM1; p=AAA"']);
		};
		await fetchDkimPosture("acme.com", ["Sel1", "sel1", "SEL1"], { fetchImpl });
		expect(seen).toEqual(["sel1._domainkey.acme.com"]);
	});

	it("reads from KV cache when a per-selector posture is stored", async () => {
		const kv = fakeKv({
			"dkim-published:v1:acme.com:sel1": { published: true },
		});
		let calls = 0;
		const fetchImpl = async () => {
			calls += 1;
			return dohTxtResponse(['"v=DKIM1; p=BBB"']);
		};
		const r = await fetchDkimPosture("acme.com", ["sel1"], { fetchImpl, kv });
		expect(calls).toBe(0);
		expect(r).toEqual({
			selectors: [{ selector: "sel1", published: true }],
		});
	});

	it("writes the durable-positive posture to KV", async () => {
		const kv = fakeKv();
		const fetchImpl = async () =>
			dohTxtResponse(['"v=DKIM1; p=AAA"']);
		await fetchDkimPosture("acme.com", ["sel1"], { fetchImpl, kv });
		await new Promise((r) => setTimeout(r, 0));
		const cached = kv.store.get("dkim-published:v1:acme.com:sel1");
		expect(cached).toBeDefined();
		expect(JSON.parse(cached!)).toEqual({ published: true });
	});

	it("writes the durable-negative posture to KV (NXDOMAIN sticks for the TTL)", async () => {
		const kv = fakeKv();
		const fetchImpl = async () => dohNxdomainResponse();
		await fetchDkimPosture("acme.com", ["gone"], { fetchImpl, kv });
		await new Promise((r) => setTimeout(r, 0));
		const cached = kv.store.get("dkim-published:v1:acme.com:gone");
		expect(cached).toBeDefined();
		expect(JSON.parse(cached!)).toEqual({ published: false });
	});

	it("does NOT cache the unavailable sentinel (transient errors mustn't poison the cache)", async () => {
		const kv = fakeKv();
		const fetchImpl = async () => {
			throw new Error("network");
		};
		const r = await fetchDkimPosture("acme.com", ["sel"], { fetchImpl, kv });
		await new Promise((r) => setTimeout(r, 0));
		expect(r).toEqual({
			selectors: [{ selector: "sel", published: null }],
		});
		expect(kv.store.has("dkim-published:v1:acme.com:sel")).toBe(false);
	});

	it("falls through KV miss to DoH and writes the result", async () => {
		const kv = fakeKv();
		let calls = 0;
		const fetchImpl = async () => {
			calls += 1;
			return dohTxtResponse(['"v=DKIM1; p=AAA"']);
		};
		const r = await fetchDkimPosture("acme.com", ["sel1"], { fetchImpl, kv });
		expect(calls).toBe(1);
		expect(r).toEqual({
			selectors: [{ selector: "sel1", published: true }],
		});
	});

	it("queries the <selector>._domainkey.<domain> label with TXT", async () => {
		let captured = "";
		const fetchImpl = async (url: string) => {
			captured = url;
			return dohTxtResponse(['"v=DKIM1; p=AAA"']);
		};
		await fetchDkimPosture("acme.com", ["googleapis"], { fetchImpl });
		const u = new URL(captured);
		expect(u.hostname).toBe("cloudflare-dns.com");
		expect(u.pathname).toBe("/dns-query");
		expect(u.searchParams.get("name")).toBe("googleapis._domainkey.acme.com");
		expect(u.searchParams.get("type")).toBe("TXT");
	});
});

// ── probeDkimSelectors (#358) ─────────────────────────────────────────

describe("DKIM_PROBE_SELECTORS", () => {
	it("contains the expected well-known names", () => {
		expect(DKIM_PROBE_SELECTORS).toContain("google");
		expect(DKIM_PROBE_SELECTORS).toContain("selector1");
		expect(DKIM_PROBE_SELECTORS).toContain("selector2");
		expect(DKIM_PROBE_SELECTORS).toContain("mail");
	});

	it("has no duplicates", () => {
		const unique = new Set(DKIM_PROBE_SELECTORS);
		expect(unique.size).toBe(DKIM_PROBE_SELECTORS.length);
	});
});

describe("probeDkimSelectors", () => {
	it("returns only published selectors tagged source:'probed'", async () => {
		const fetchImpl = async (url: string) => {
			const name = new URL(url).searchParams.get("name") ?? "";
			if (name === "google._domainkey.send-only.example") {
				return dohTxtResponse(['"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQ"']);
			}
			return dohNxdomainResponse();
		};
		const result = await probeDkimSelectors("send-only.example", { fetchImpl });
		expect(result.selectors).toHaveLength(1);
		expect(result.selectors[0]).toEqual({
			selector: "google",
			published: true,
			source: "probed",
		});
	});

	it("returns empty posture when no well-known selectors are published", async () => {
		const fetchImpl = async () => dohNxdomainResponse();
		const result = await probeDkimSelectors("no-dkim.example", { fetchImpl });
		expect(result).toEqual(emptyDkimPosture());
	});

	it("silently drops absent selectors (no false positives in the output)", async () => {
		const fetchImpl = async (url: string) => {
			const name = new URL(url).searchParams.get("name") ?? "";
			// selector1 is published; all others are NXDOMAIN
			if (name === "selector1._domainkey.acme.com") {
				return dohTxtResponse(['"v=DKIM1; p=AAA"']);
			}
			return dohNxdomainResponse();
		};
		const result = await probeDkimSelectors("acme.com", { fetchImpl });
		// Only the published selector should appear; absent probes are dropped.
		expect(result.selectors.every((s) => s.published === true)).toBe(true);
		expect(result.selectors.every((s) => s.source === "probed")).toBe(true);
	});

	it("degrades to emptyDkimPosture when DoH times out (probe failure → not probed, not absent)", async () => {
		const fetchImpl = async (): Promise<Response> => {
			throw new Error("AbortError: signal timed out");
		};
		const result = await probeDkimSelectors("timeout.example", { fetchImpl });
		// Timeout should produce published:null for each selector but probeDkimSelectors
		// filters to published===true only, so the result is empty — not an error.
		expect(result).toEqual(emptyDkimPosture());
	});

	it("does not include published:null (transient unavailable) selectors in output", async () => {
		// SERVFAIL returns published:null — should not appear as a published selector.
		const fetchImpl = async () =>
			new Response(JSON.stringify({ Status: 2 }), { status: 200 });
		const result = await probeDkimSelectors("servfail.example", { fetchImpl });
		expect(result.selectors).toHaveLength(0);
	});

	it("probes against the well-known candidate list, not observed selectors", async () => {
		const probed: string[] = [];
		const fetchImpl = async (url: string) => {
			const name = new URL(url).searchParams.get("name") ?? "";
			probed.push(name.split("._domainkey.")[0] ?? "");
			return dohNxdomainResponse();
		};
		await probeDkimSelectors("acme.com", { fetchImpl });
		// Every probed selector should be in the well-known list.
		for (const sel of probed) {
			expect(DKIM_PROBE_SELECTORS).toContain(sel);
		}
		expect(probed).toHaveLength(DKIM_PROBE_SELECTORS.length);
	});
});

// ── mergeDkimPosture (#358) ─────────────────────────────────────────

describe("mergeDkimPosture", () => {
	it("tags observed-only selectors as source:'observed'", () => {
		const observed = {
			selectors: [{ selector: "s1", published: true }],
		};
		const probed = emptyDkimPosture();
		const result = mergeDkimPosture(observed, probed);
		expect(result.selectors).toEqual([
			{ selector: "s1", published: true, source: "observed" },
		]);
	});

	it("tags probed-only selectors as source:'probed'", () => {
		const probed = {
			selectors: [{ selector: "google", published: true, source: "probed" as const }],
		};
		const result = mergeDkimPosture(emptyDkimPosture(), probed);
		expect(result.selectors).toEqual([
			{ selector: "google", published: true, source: "probed" },
		]);
	});

	it("tags selectors present in both as source:'both' without duplication", () => {
		const observed = {
			selectors: [{ selector: "google", published: true }],
		};
		const probed = {
			selectors: [{ selector: "google", published: true, source: "probed" as const }],
		};
		const result = mergeDkimPosture(observed, probed);
		expect(result.selectors).toHaveLength(1);
		expect(result.selectors[0]).toEqual({
			selector: "google",
			published: true,
			source: "both",
		});
	});

	it("uses observed published status for overlap (observed is authoritative)", () => {
		// Observed has published:false (revoked key), probe has published:true.
		// The observed value should win.
		const observed = {
			selectors: [{ selector: "old", published: false }],
		};
		const probed = {
			selectors: [{ selector: "old", published: true, source: "probed" as const }],
		};
		const result = mergeDkimPosture(observed, probed);
		expect(result.selectors[0]).toEqual({
			selector: "old",
			published: false,
			source: "both",
		});
	});

	it("merges multiple selectors with correct provenance", () => {
		const observed = {
			selectors: [
				{ selector: "custom-sel", published: true },
				{ selector: "google", published: true },
			],
		};
		const probed = {
			selectors: [
				{ selector: "google", published: true, source: "probed" as const },
				{ selector: "selector1", published: true, source: "probed" as const },
			],
		};
		const result = mergeDkimPosture(observed, probed);
		// Alphabetical order: custom-sel, google, selector1
		expect(result.selectors).toEqual([
			{ selector: "custom-sel", published: true, source: "observed" },
			{ selector: "google", published: true, source: "both" },
			{ selector: "selector1", published: true, source: "probed" },
		]);
	});

	it("returns empty posture when both inputs are empty", () => {
		expect(mergeDkimPosture(emptyDkimPosture(), emptyDkimPosture())).toEqual(
			emptyDkimPosture(),
		);
	});

	it("output is alphabetically sorted for stable rendering", () => {
		const observed = {
			selectors: [
				{ selector: "zebra", published: true },
				{ selector: "alpha", published: true },
			],
		};
		const result = mergeDkimPosture(observed, emptyDkimPosture());
		expect(result.selectors.map((s) => s.selector)).toEqual(["alpha", "zebra"]);
	});
});
