// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	emptyDnssecPosture,
	fetchDnssecPosture,
	type DnssecKv,
} from "../../workers/dnssec/posture";

function fakeKv(initial: Record<string, unknown> = {}): DnssecKv & {
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

function adResponse(ad: boolean, answers: Array<{ type: number }> = []): Response {
	return new Response(
		JSON.stringify({
			Status: 0,
			AD: ad,
			Answer: answers,
		}),
		{ status: 200, headers: { "content-type": "application/dns-json" } },
	);
}

function dsResponse(dsRecords: number): Response {
	const Answer = Array.from({ length: dsRecords }, (_, i) => ({
		name: "example.com",
		type: 43,
		TTL: 3600,
		data: `${257 + i} 13 2 abc123`,
	}));
	return new Response(
		JSON.stringify({ Status: 0, AD: true, Answer }),
		{ status: 200, headers: { "content-type": "application/dns-json" } },
	);
}

describe("fetchDnssecPosture", () => {
	it("AD=true with DS present → signed: true, hasDsAtParent: true", async () => {
		// Hostname-based dispatch — substring matching on URLs is a CodeQL
		// `js/incomplete-url-substring-sanitization` trip wire (repo CLAUDE.md).
		let calls = 0;
		const fetchImpl = async (url: string) => {
			const u = new URL(url);
			expect(u.hostname).toBe("cloudflare-dns.com");
			expect(u.pathname).toBe("/dns-query");
			calls += 1;
			if (u.searchParams.get("type") === "A") {
				expect(u.searchParams.get("name")).toBe("example.com");
				expect(u.searchParams.get("cd")).toBe("0");
				return adResponse(true);
			}
			if (u.searchParams.get("type") === "DS") {
				expect(u.searchParams.get("name")).toBe("example.com");
				return dsResponse(1);
			}
			throw new Error(`unexpected type: ${u.searchParams.get("type")}`);
		};
		const r = await fetchDnssecPosture("example.com", { fetchImpl });
		expect(r).toEqual({ signed: true, hasDsAtParent: true });
		expect(calls).toBe(2);
	});

	it("AD=true with DS absent → signed: true, hasDsAtParent: false", async () => {
		const fetchImpl = async (url: string) => {
			const u = new URL(url);
			if (u.searchParams.get("type") === "A") return adResponse(true);
			// No DS records in the Answer section.
			return new Response(
				JSON.stringify({ Status: 0, AD: true, Answer: [] }),
				{ status: 200, headers: { "content-type": "application/dns-json" } },
			);
		};
		const r = await fetchDnssecPosture("example.com", { fetchImpl });
		expect(r).toEqual({ signed: true, hasDsAtParent: false });
	});

	it("AD=false (unsigned domain) → signed: false, no DS query", async () => {
		let dsCalls = 0;
		const fetchImpl = async (url: string) => {
			const u = new URL(url);
			if (u.searchParams.get("type") === "DS") dsCalls += 1;
			return adResponse(false);
		};
		const r = await fetchDnssecPosture("unsigned.example.com", { fetchImpl });
		expect(r).toEqual({ signed: false });
		expect(r).toEqual(emptyDnssecPosture());
		// Short-circuits after the A query — no DS lookup on unsigned domains.
		expect(dsCalls).toBe(0);
	});

	it("DoH timeout on A query → signed: false", async () => {
		const fetchImpl = async () => {
			throw new Error("timeout");
		};
		const r = await fetchDnssecPosture("example.com", { fetchImpl });
		expect(r).toEqual(emptyDnssecPosture());
	});

	it("DoH timeout on DS query when AD=true → signed: true, hasDsAtParent: false", async () => {
		const fetchImpl = async (url: string) => {
			const u = new URL(url);
			if (u.searchParams.get("type") === "A") return adResponse(true);
			throw new Error("timeout");
		};
		const r = await fetchDnssecPosture("example.com", { fetchImpl });
		expect(r).toEqual({ signed: true, hasDsAtParent: false });
	});

	it("non-200 A query → signed: false", async () => {
		const fetchImpl = async () =>
			new Response("server error", { status: 503 });
		const r = await fetchDnssecPosture("example.com", { fetchImpl });
		expect(r).toEqual(emptyDnssecPosture());
	});

	it("reads from KV cache on hit", async () => {
		const cached = { signed: true, hasDsAtParent: true };
		const kv = fakeKv({ "dmarc-dnssec:v1:example.com": cached });
		let httpCalls = 0;
		const fetchImpl = async () => {
			httpCalls += 1;
			return adResponse(false);
		};
		const r = await fetchDnssecPosture("example.com", { fetchImpl, kv });
		expect(httpCalls).toBe(0);
		expect(r).toEqual(cached);
	});

	it("writes result to KV on cache miss", async () => {
		const kv = fakeKv();
		const fetchImpl = async (url: string) => {
			const u = new URL(url);
			if (u.searchParams.get("type") === "A") return adResponse(true);
			return dsResponse(1);
		};
		await fetchDnssecPosture("example.com", { fetchImpl, kv });
		// Allow the fire-and-forget put to settle.
		await new Promise((r) => setTimeout(r, 0));
		expect(kv.store.get("dmarc-dnssec:v1:example.com")).toBeDefined();
		const stored = JSON.parse(kv.store.get("dmarc-dnssec:v1:example.com")!);
		expect(stored).toEqual({ signed: true, hasDsAtParent: true });
	});

	it("queries the apex domain for both A and DS records", async () => {
		const names: string[] = [];
		const fetchImpl = async (url: string) => {
			const u = new URL(url);
			names.push(`${u.searchParams.get("type")}:${u.searchParams.get("name")}`);
			if (u.searchParams.get("type") === "A") return adResponse(true);
			return dsResponse(0);
		};
		await fetchDnssecPosture("acme.com", { fetchImpl });
		expect(names).toContain("A:acme.com");
		expect(names).toContain("DS:acme.com");
	});

	it("returns empty sentinel for empty domain string", async () => {
		const fetchImpl = async () => adResponse(true);
		expect(await fetchDnssecPosture("", { fetchImpl })).toEqual(
			emptyDnssecPosture(),
		);
	});
});
