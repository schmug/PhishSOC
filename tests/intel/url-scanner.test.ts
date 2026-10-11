// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";

import {
	fetchScreenshot,
	getScanResult,
	submitScan,
} from "../../workers/intel/url-scanner";

const UUID = "0b1c2d3e-aaaa-bbbb-cccc-1234567890ab";

function kv(initial: Record<string, string> = {}) {
	const m = new Map(Object.entries(initial));
	return {
		get: async (k: string) => m.get(k) ?? null,
		put: async (k: string, v: string) => void m.set(k, v),
		map: m,
	};
}

function mkEnv(extra: Record<string, unknown> = {}) {
	return {
		URLSCAN_API_TOKEN: "tok",
		URLSCAN_ACCOUNT_ID: "acct",
		BLOOM_KV: kv(),
		...extra,
	} as never;
}

type Call = { pathname: string; method: string; body?: string };

function transport(handlers: { search?: unknown; scanStatus?: number; result?: () => Response }) {
	const calls: Call[] = [];
	const fn = async (url: string, init?: RequestInit) => {
		const u = new URL(url);
		if (u.hostname !== "api.cloudflare.com") throw new Error(`unexpected host ${u.hostname}`);
		calls.push({ pathname: u.pathname, method: init?.method ?? "GET", body: init?.body as string | undefined });
		if (u.pathname.endsWith("/urlscanner/v2/search")) return Response.json(handlers.search ?? { results: [] });
		if (u.pathname.endsWith("/urlscanner/v2/scan")) {
			return handlers.scanStatus && handlers.scanStatus !== 200
				? new Response("x", { status: handlers.scanStatus })
				: Response.json({ uuid: UUID });
		}
		if (u.pathname.includes("/urlscanner/v2/result/")) return handlers.result!();
		if (u.pathname.includes("/urlscanner/v2/screenshots/")) return new Response("png");
		return new Response("nope", { status: 500 });
	};
	return { fn, calls };
}

describe("url-scanner", () => {
	it("returns not_configured without token/account and makes no call", async () => {
		const t = transport({});
		const out = await submitScan({ BLOOM_KV: kv() } as never, "https://evil.example/x", {}, t.fn);
		expect(out).toEqual({ ok: false, reason: "not_configured" });
		expect(t.calls).toHaveLength(0);
	});

	it("always submits visibility Unlisted, even if a caller smuggles Public", async () => {
		const t = transport({});
		const out = await submitScan(mkEnv(), "https://Evil.example/x", { visibility: "Public" } as never, t.fn);
		expect(out).toEqual({ ok: true, uuid: UUID, reused: false });
		const post = t.calls.find((c) => c.method === "POST")!;
		const body = JSON.parse(post.body!);
		expect(body.visibility).toBe("Unlisted");
		expect(body.url).toBe("https://evil.example/x");
		expect(body).not.toHaveProperty("customHeaders");
		expect(body).not.toHaveProperty("referer");
	});

	it("reuses a prior scan found by search; force skips search", async () => {
		const t = transport({ search: { results: [{ task: { uuid: UUID } }] } });
		const out = await submitScan(mkEnv(), "https://evil.example/x", {}, t.fn);
		expect(out).toEqual({ ok: true, uuid: UUID, reused: true });
		expect(t.calls.some((c) => c.method === "POST")).toBe(false);

		const t2 = transport({ search: { results: [{ task: { uuid: UUID } }] } });
		await submitScan(mkEnv(), "https://evil.example/x", { force: true }, t2.fn);
		expect(t2.calls.some((c) => c.pathname.endsWith("/search"))).toBe(false);
		expect(t2.calls.some((c) => c.method === "POST")).toBe(true);
	});

	it("blocks at the monthly cap with no outbound scan call", async () => {
		const now = new Date("2026-10-11T12:00:00Z");
		const env = mkEnv({ BLOOM_KV: kv({ "urlscan:quota:2026-10": "450" }) });
		const t = transport({});
		const out = await submitScan(env, "https://evil.example/x", { force: true, now }, t.fn);
		expect(out).toEqual({ ok: false, reason: "quota", remaining: 0 });
		expect(t.calls).toHaveLength(0);
	});

	it("honors URLSCAN_MONTHLY_CAP and increments the counter", async () => {
		const now = new Date("2026-10-11T12:00:00Z");
		const store = kv({ "urlscan:quota:2026-10": "1" });
		const env = mkEnv({ BLOOM_KV: store, URLSCAN_MONTHLY_CAP: "2" });
		const t = transport({});
		expect((await submitScan(env, "https://a.example/", { force: true, now }, t.fn)).ok).toBe(true);
		expect(store.map.get("urlscan:quota:2026-10")).toBe("2");
		const later = new Date(now.getTime() + 60_000);
		const out = await submitScan(env, "https://b.example/", { force: true, now: later }, t.fn);
		expect(out).toMatchObject({ ok: false, reason: "quota" });
	});

	it("enforces 10s spacing between submits", async () => {
		const now = new Date("2026-10-11T12:00:00Z");
		const env = mkEnv();
		const t = transport({});
		await submitScan(env, "https://a.example/", { force: true, now }, t.fn);
		const n = t.calls.length;
		const out = await submitScan(env, "https://b.example/", { force: true, now: new Date(now.getTime() + 5000) }, t.fn);
		expect(out).toMatchObject({ ok: false, reason: "spacing" });
		expect(t.calls).toHaveLength(n);
	});

	it("treats result 404 as pending and parses a finished result", async () => {
		const pending = transport({ result: () => new Response("", { status: 404 }) });
		expect(await getScanResult(mkEnv(), UUID, pending.fn)).toMatchObject({ status: "pending", malicious: null });

		const done = transport({
			result: () =>
				Response.json({
					verdicts: { overall: { malicious: true, categories: [{ name: "Phishing" }, "Malware"] } },
					page: { url: "https://final.example/landing" },
				}),
		});
		expect(await getScanResult(mkEnv(), UUID, done.fn)).toEqual({
			uuid: UUID,
			status: "done",
			malicious: true,
			categories: ["Phishing", "Malware"],
			finalUrl: "https://final.example/landing",
		});
	});

	it("rejects a malformed uuid and proxies the screenshot path", async () => {
		const t = transport({});
		expect(await getScanResult(mkEnv(), "../etc", t.fn)).toBeNull();
		expect(await fetchScreenshot(mkEnv(), "../etc", t.fn)).toBeNull();
		expect(await fetchScreenshot(mkEnv(), UUID, t.fn)).not.toBeNull();
		expect(t.calls[0].pathname.endsWith(`/screenshots/${UUID}.png`)).toBe(true);
	});
});
