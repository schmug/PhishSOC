// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	emptyMtaStsPosture,
	fetchMtaStsPosture,
	normalizeDohTxtData,
	parseMtaStsPolicy,
	parseMtaStsTxt,
	selectMtaStsTxtRecord,
	type MtaStsKv,
} from "../../workers/mta-sts/posture";

describe("parseMtaStsTxt", () => {
	it("parses a v=STSv1 record with an id tag", () => {
		expect(parseMtaStsTxt("v=STSv1; id=20251102T0000")).toEqual({
			id: "20251102T0000",
		});
	});

	it("returns null for non-STSv1 records", () => {
		expect(parseMtaStsTxt("v=spf1 -all")).toBeNull();
		expect(parseMtaStsTxt("not even a tag list")).toBeNull();
		expect(parseMtaStsTxt("")).toBeNull();
	});

	it("returns null when the id tag is missing", () => {
		expect(parseMtaStsTxt("v=STSv1")).toBeNull();
	});

	it("returns null when the id is over 32 chars or non-alphanumeric", () => {
		expect(parseMtaStsTxt(`v=STSv1; id=${"x".repeat(33)}`)).toBeNull();
		expect(parseMtaStsTxt("v=STSv1; id=has-dash")).toBeNull();
		expect(parseMtaStsTxt("v=STSv1; id=has space")).toBeNull();
	});

	it("is case-insensitive on tag names but not on id values", () => {
		const r = parseMtaStsTxt("V=STSv1; ID=ABC123");
		expect(r).toEqual({ id: "ABC123" });
	});

	it("ignores duplicate tags after the first occurrence", () => {
		const r = parseMtaStsTxt("v=STSv1; id=first; id=second");
		expect(r?.id).toBe("first");
	});
});

describe("selectMtaStsTxtRecord", () => {
	it("picks the v=STSv1-prefixed record", () => {
		const r = selectMtaStsTxtRecord([
			"google-site-verification=abc",
			"v=STSv1; id=20251102",
			"v=spf1 -all",
		]);
		expect(r).toBe("v=STSv1; id=20251102");
	});

	it("returns null when no STSv1 record present", () => {
		expect(selectMtaStsTxtRecord(["v=spf1 -all"])).toBeNull();
	});

	it("matches case-insensitively and tolerates whitespace around v=", () => {
		expect(selectMtaStsTxtRecord(["V = STSv1; id=abc"])).toMatch(/STSv1/);
	});
});

describe("parseMtaStsPolicy", () => {
	it("parses a complete enforce-mode policy", () => {
		const body = [
			"version: STSv1",
			"mode: enforce",
			"mx: mail.example.com",
			"mx: *.example.net",
			"max_age: 604800",
		].join("\n");
		expect(parseMtaStsPolicy(body)).toEqual({
			mode: "enforce",
			mx: ["mail.example.com", "*.example.net"],
			maxAge: 604800,
		});
	});

	it("parses testing and none modes", () => {
		const t = parseMtaStsPolicy(
			"version: STSv1\nmode: testing\nmax_age: 86400",
		);
		expect(t?.mode).toBe("testing");
		const n = parseMtaStsPolicy(
			"version: STSv1\nmode: none\nmax_age: 86400",
		);
		expect(n?.mode).toBe("none");
	});

	it("tolerates CRLF line endings", () => {
		const body = "version: STSv1\r\nmode: enforce\r\nmax_age: 86400";
		expect(parseMtaStsPolicy(body)?.mode).toBe("enforce");
	});

	it("returns null when version is missing or wrong", () => {
		expect(parseMtaStsPolicy("mode: enforce\nmax_age: 86400")).toBeNull();
		expect(
			parseMtaStsPolicy("version: STSv2\nmode: enforce\nmax_age: 86400"),
		).toBeNull();
	});

	it("returns null when mode is invalid", () => {
		expect(
			parseMtaStsPolicy("version: STSv1\nmode: bogus\nmax_age: 86400"),
		).toBeNull();
		expect(
			parseMtaStsPolicy("version: STSv1\nmax_age: 86400"),
		).toBeNull();
	});

	it("returns null when max_age is missing or non-numeric", () => {
		expect(parseMtaStsPolicy("version: STSv1\nmode: enforce")).toBeNull();
		expect(
			parseMtaStsPolicy("version: STSv1\nmode: enforce\nmax_age: forever"),
		).toBeNull();
	});

	it("ignores comment lines and unknown keys", () => {
		const body = [
			"# comment line",
			"version: STSv1",
			"mode: enforce",
			"max_age: 604800",
			"some_future_key: ignored",
		].join("\n");
		const r = parseMtaStsPolicy(body);
		expect(r).toEqual({ mode: "enforce", mx: [], maxAge: 604800 });
	});
});

describe("normalizeDohTxtData", () => {
	it("concatenates multi-string TXT-record fragments without inserting whitespace", () => {
		expect(normalizeDohTxtData('"v=STSv1; " "id=abc123"')).toBe(
			"v=STSv1; id=abc123",
		);
	});

	it("strips surrounding quotes from a single-fragment string", () => {
		expect(normalizeDohTxtData('"v=STSv1; id=abc"')).toBe("v=STSv1; id=abc");
	});

	it("passes raw text through when no quoted fragments are present", () => {
		expect(normalizeDohTxtData("v=STSv1; id=abc")).toBe("v=STSv1; id=abc");
	});
});

// ── DoH + HTTPS integration tests ─────────────────────────────────────────

function fakeKv(initial: Record<string, unknown> = {}): MtaStsKv & {
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

function dohTxtResponse(records: string[]): Response {
	return new Response(
		JSON.stringify({
			Status: 0,
			Answer: records.map((data) => ({
				name: "_mta-sts.acme.com",
				type: 16,
				data,
			})),
		}),
		{ status: 200, headers: { "content-type": "application/dns-json" } },
	);
}

function policyResponse(body: string): Response {
	return new Response(body, {
		status: 200,
		headers: { "content-type": "text/plain" },
	});
}

describe("fetchMtaStsPosture", () => {
	it("resolves a complete posture (TXT + enforce policy)", async () => {
		// Hostname-based dispatch — substring matching on URLs is a CodeQL
		// `js/incomplete-url-substring-sanitization` trip wire (repo CLAUDE.md).
		const fetchImpl = async (url: string, init?: RequestInit) => {
			const u = new URL(url);
			if (u.hostname === "cloudflare-dns.com") {
				expect(u.pathname).toBe("/dns-query");
				expect(u.searchParams.get("name")).toBe("_mta-sts.acme.com");
				return dohTxtResponse(['"v=STSv1; id=20251102"']);
			}
			if (u.hostname === "mta-sts.acme.com") {
				expect(u.pathname).toBe("/.well-known/mta-sts.txt");
				// MTA-STS clients must not follow redirects (RFC 8461 §3.3).
				expect(init?.redirect).toBe("manual");
				return policyResponse(
					"version: STSv1\nmode: enforce\nmx: mail.acme.com\nmax_age: 604800",
				);
			}
			throw new Error(`unexpected fetch host: ${u.hostname}`);
		};
		const r = await fetchMtaStsPosture("acme.com", { fetchImpl });
		expect(r).toEqual({
			mode: "enforce",
			mx: ["mail.acme.com"],
			maxAge: 604800,
			id: "20251102",
		});
	});

	it("returns the empty sentinel when no _mta-sts TXT record exists", async () => {
		const fetchImpl = async () =>
			new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
		const r = await fetchMtaStsPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptyMtaStsPosture());
	});

	it("returns posture with id but null mode/mx/maxAge when policy fetch fails", async () => {
		const fetchImpl = async (url: string) => {
			const u = new URL(url);
			if (u.hostname === "cloudflare-dns.com") {
				return dohTxtResponse(['"v=STSv1; id=abc"']);
			}
			// Policy fetch returns 404 — common during a partial misconfiguration.
			return new Response("not found", { status: 404 });
		};
		const r = await fetchMtaStsPosture("acme.com", { fetchImpl });
		expect(r).toEqual({ mode: null, mx: null, maxAge: null, id: "abc" });
	});

	it("returns posture with id but null fields when policy is malformed", async () => {
		const fetchImpl = async (url: string) => {
			const u = new URL(url);
			if (u.hostname === "cloudflare-dns.com") {
				return dohTxtResponse(['"v=STSv1; id=abc"']);
			}
			return policyResponse("<html>nope</html>");
		};
		const r = await fetchMtaStsPosture("acme.com", { fetchImpl });
		expect(r.id).toBe("abc");
		expect(r.mode).toBeNull();
	});

	it("returns the empty sentinel when DoH fetch rejects", async () => {
		const fetchImpl = async () => {
			throw new Error("network");
		};
		const r = await fetchMtaStsPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptyMtaStsPosture());
	});

	it("returns posture with id but null fields when policy fetch times out (rejects)", async () => {
		const fetchImpl = async (url: string) => {
			const u = new URL(url);
			if (u.hostname === "cloudflare-dns.com") {
				return dohTxtResponse(['"v=STSv1; id=abc"']);
			}
			throw new Error("timeout");
		};
		const r = await fetchMtaStsPosture("acme.com", { fetchImpl });
		expect(r).toEqual({ mode: null, mx: null, maxAge: null, id: "abc" });
	});

	it("rejects oversized policy bodies", async () => {
		// 64 KiB + 1 byte should be refused.
		const oversized = "version: STSv1\nmode: enforce\nmax_age: 86400\n".padEnd(
			65 * 1024,
			"# padding\n",
		);
		const fetchImpl = async (url: string) => {
			const u = new URL(url);
			if (u.hostname === "cloudflare-dns.com") {
				return dohTxtResponse(['"v=STSv1; id=abc"']);
			}
			return policyResponse(oversized);
		};
		const r = await fetchMtaStsPosture("acme.com", { fetchImpl });
		expect(r.id).toBe("abc");
		expect(r.mode).toBeNull();
	});

	it("reads from KV cache keyed by policy id", async () => {
		const cached = {
			mode: "enforce",
			mx: ["cached.acme.com"],
			maxAge: 604800,
			id: "20251102",
		};
		const kv = fakeKv({ "mta-sts:v1:acme.com:20251102": cached });
		let httpsCalls = 0;
		const fetchImpl = async (url: string) => {
			const u = new URL(url);
			if (u.hostname === "cloudflare-dns.com") {
				return dohTxtResponse(['"v=STSv1; id=20251102"']);
			}
			httpsCalls += 1;
			return policyResponse(
				"version: STSv1\nmode: testing\nmax_age: 86400",
			);
		};
		const r = await fetchMtaStsPosture("acme.com", { fetchImpl, kv });
		// Cache hit — never touched the policy URL.
		expect(httpsCalls).toBe(0);
		expect(r.mode).toBe("enforce");
		expect(r.mx).toEqual(["cached.acme.com"]);
	});

	it("re-fetches when the published id changes (cache buster works)", async () => {
		// KV has an entry under the OLD id — when the operator publishes a new
		// id, the cache key changes and we fetch fresh.
		const kv = fakeKv({
			"mta-sts:v1:acme.com:OLD": {
				mode: "enforce",
				mx: [],
				maxAge: 86400,
				id: "OLD",
			},
		});
		const fetchImpl = async (url: string) => {
			const u = new URL(url);
			if (u.hostname === "cloudflare-dns.com") {
				return dohTxtResponse(['"v=STSv1; id=NEW"']);
			}
			return policyResponse(
				"version: STSv1\nmode: testing\nmax_age: 3600",
			);
		};
		const r = await fetchMtaStsPosture("acme.com", { fetchImpl, kv });
		expect(r.id).toBe("NEW");
		expect(r.mode).toBe("testing");
		expect(r.maxAge).toBe(3600);
	});

	it("caches negative results under a distinct key with short TTL", async () => {
		const kv = fakeKv();
		const fetchImpl = async () =>
			new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
		await fetchMtaStsPosture("acme.com", { fetchImpl, kv });
		await new Promise((r) => setTimeout(r, 0));
		expect(kv.store.get("mta-sts:v1:acme.com:none")).toBeDefined();
	});

	it("caches a failed policy fetch with the short TTL, a good one with the long TTL", async () => {
		const ttls = new Map<string, number | undefined>();
		const base = fakeKv();
		const kv: MtaStsKv = {
			get: base.get,
			async put(key, value, opts) {
				ttls.set(key, opts?.expirationTtl);
				await base.put(key, value);
			},
		};
		const makeFetch = (policyStatus: number) => async (url: string) => {
			const u = new URL(url);
			if (u.hostname === "cloudflare-dns.com") {
				return dohTxtResponse(['"v=STSv1; id=abc"']);
			}
			return policyStatus === 200
				? policyResponse("version: STSv1\nmode: enforce\nmx: mail.acme.com\nmax_age: 604800")
				: new Response("unavailable", { status: policyStatus });
		};
		await fetchMtaStsPosture("acme.com", { fetchImpl: makeFetch(503), kv });
		await new Promise((r) => setTimeout(r, 0));
		expect(ttls.get("mta-sts:v1:acme.com:abc")).toBe(5 * 60);

		await fetchMtaStsPosture("good.com", { fetchImpl: makeFetch(200), kv });
		await new Promise((r) => setTimeout(r, 0));
		expect(ttls.get("mta-sts:v1:good.com:abc")).toBe(24 * 60 * 60);
	});

	it("serves a cached negative without a DoH lookup", async () => {
		const kv = fakeKv({ "mta-sts:v1:acme.com:none": emptyMtaStsPosture() });
		let calls = 0;
		const fetchImpl = async () => {
			calls += 1;
			return new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
		};
		const r = await fetchMtaStsPosture("acme.com", { fetchImpl, kv });
		expect(r).toEqual(emptyMtaStsPosture());
		expect(calls).toBe(0);
	});

	it("queries the _mta-sts.<domain> label, not the apex", async () => {
		let captured = "";
		const fetchImpl = async (url: string) => {
			const u = new URL(url);
			if (u.hostname === "cloudflare-dns.com") {
				captured = url;
				return dohTxtResponse([]);
			}
			return new Response("", { status: 404 });
		};
		await fetchMtaStsPosture("acme.com", { fetchImpl });
		const u = new URL(captured);
		expect(u.searchParams.get("name")).toBe("_mta-sts.acme.com");
		expect(u.searchParams.get("type")).toBe("TXT");
	});
});
