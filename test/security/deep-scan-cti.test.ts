// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Deep-scan + CrowdSec CTI integration tests.
 *
 * The deep-scan stage reaches out to the network for several things (URL
 * resolution, RDAP, DoH, CTI). Here we monkey-patch `globalThis.fetch` to
 * route every outbound call to a deterministic in-test responder so the
 * suite stays hermetic.
 *
 * Two scenarios get end-to-end coverage:
 *   1. CTI-malicious redirect target → reasons + score bump
 *   2. No API key configured → no CTI calls, deep-scan still works
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { runDeepScan } from "../../workers/intel/deep-scan";
import type { Env } from "../../workers/types";

interface FakeUrlRow {
	id: string;
	url: string;
	resolved_url?: string | null;
	page_title?: string | null;
	fetch_status?: string;
	verdict?: string | null;
}

interface FakeKv {
	store: Map<string, string>;
	get: (key: string, type?: "text" | "arrayBuffer") => Promise<string | null>;
	put: (key: string, value: string, opts?: { expirationTtl?: number }) => Promise<void>;
}

function makeKv(): FakeKv {
	const store = new Map<string, string>();
	return {
		store,
		async get(key) {
			return store.get(key) ?? null;
		},
		async put(key, value) {
			store.set(key, value);
		},
	};
}

function makeStub(urls: FakeUrlRow[]) {
	const updates: Record<string, FakeUrlRow> = {};
	const verdictStore = new Map<string, { verdict_json: string; score: number; explanation: string }>();
	const moves: Array<{ id: string; folderId: string }> = [];
	let deepScanStatus: string | null = null;
	const stub = {
		async getStoredVerdict(emailId: string) {
			// A pre-existing sync verdict that the deep-scan can layer onto.
			return {
				verdict: JSON.stringify({
					action: "tag",
					score: 35,
					triage: "score",
					signals: ["base"],
					explanation: "base",
				}),
				score: 35,
			};
		},
		async getUrlsForEmail(_emailId: string) {
			return urls;
		},
		async updateUrlScan(id: string, data: Partial<FakeUrlRow>) {
			updates[id] = { ...(updates[id] ?? { id, url: "" }), ...data, id };
		},
		async getAttachmentsForEmail(_emailId: string) {
			return [];
		},
		async updateAttachmentScan() {},
		async persistSecurityVerdict(emailId: string, data: { verdict_json: string; score: number; explanation: string }) {
			verdictStore.set(emailId, data);
		},
		async moveEmail(id: string, folderId: string) {
			moves.push({ id, folderId });
		},
		async updateDeepScanStatus(_emailId: string, status: string) {
			deepScanStatus = status;
		},
	};
	return { stub, updates, verdictStore, moves, getStatus: () => deepScanStatus };
}

function makeEnv(opts: { apiKey?: string; kv?: FakeKv; stub: unknown }): Env {
	const mailboxNs = {
		idFromName(_n: string) {
			return { toString: () => _n } as unknown as DurableObjectId;
		},
		get(_id: DurableObjectId) {
			return opts.stub as unknown as DurableObjectStub;
		},
	} as unknown as DurableObjectNamespace;
	return {
		CROWDSEC_CTI_API_KEY: opts.apiKey,
		BLOOM_KV: opts.kv as unknown as KVNamespace | undefined,
		MAILBOX: mailboxNs,
	} as unknown as Env;
}

/**
 * Build a fetch mock that dispatches by URL host. Anything unmatched is
 * served as 404 so a missing route surfaces as a test failure rather than
 * a network call.
 */
function makeFetchMock(handlers: Array<(url: string) => Response | Promise<Response> | null>) {
	return vi.fn(async (input: string | URL | Request) => {
		const url = typeof input === "string" ? input : input.toString();
		for (const h of handlers) {
			const out = await h(url);
			if (out) return out;
		}
		return new Response("not mocked: " + url, { status: 404 });
	});
}

const CTI_FIXTURE_MALICIOUS = {
	reputation: "malicious",
	classifications: { classifications: [{ name: "tor" }] },
	behaviors: [{ name: "http:phishing", label: "http:phishing" }],
	scores: { overall: { threat: 5, aggressiveness: 4, trust: 5 } },
};

let originalFetch: typeof fetch;

beforeEach(() => {
	originalFetch = globalThis.fetch;
});
afterEach(() => {
	globalThis.fetch = originalFetch;
	vi.restoreAllMocks();
});

describe("runDeepScan + CrowdSec CTI", () => {
	it("CTI-malicious redirect target adds CTI reasons and bumps score", async () => {
		const fetchMock = makeFetchMock([
			// URL resolver hits the redirect target.
			(url) => {
				if (new URL(url).hostname === "phish.example.com") {
					return new Response("<html><title>Login</title></html>", {
						status: 200,
						headers: { "content-type": "text/html" },
					});
				}
				return null;
			},
			// RDAP — no registration data, treated as no-signal.
			(url) => (new URL(url).hostname === "rdap.org" ? new Response("{}", { status: 200 }) : null),
			// DoH for the resolved hostname.
			(url) => {
				const parsed = new URL(url);
				if (parsed.hostname === "cloudflare-dns.com" && parsed.pathname.startsWith("/dns-query")) {
					return new Response(
						JSON.stringify({
							Answer: [{ name: "phish.example.com.", type: 1, TTL: 60, data: "203.0.113.42" }],
						}),
						{ status: 200, headers: { "content-type": "application/dns-json" } },
					);
				}
				return null;
			},
			// CrowdSec CTI for the resolved IP.
			(url) => {
				const parsed = new URL(url);
				if (parsed.hostname === "cti.api.crowdsec.net" && parsed.pathname.startsWith("/v2/smoke/")) {
					return new Response(JSON.stringify(CTI_FIXTURE_MALICIOUS), {
						status: 200,
						headers: { "content-type": "application/json" },
					});
				}
				return null;
			},
		]);
		globalThis.fetch = fetchMock as unknown as typeof fetch;

		const harness = makeStub([{ id: "u1", url: "https://phish.example.com/login" }]);
		const env = makeEnv({ apiKey: "test-key", kv: makeKv(), stub: harness.stub });

		const result = await runDeepScan({ env, mailboxId: "m@x", emailId: "e1" });

		// CTI signals must surface in deep-scan reasons.
		const reasonsBlob = result.reasons.join(" | ");
		expect(reasonsBlob).toMatch(/redirect target IP 203\.0\.113\.42/);
		expect(reasonsBlob).toMatch(/behavior=crowdsec:http:phishing/);
		// Phishing behavior alone is +25; with reputation:malicious that would
		// be 25+15 but the per-inbound CTI cap of 25 bounds the contribution.
		expect(result.added_score).toBeGreaterThanOrEqual(25);
		// CTI calls actually happened.
		const ctiCalls = fetchMock.mock.calls.filter((c) =>
			new URL(String(c[0])).hostname === "cti.api.crowdsec.net",
		);
		expect(ctiCalls.length).toBe(1);
	});

	it("with no CROWDSEC_CTI_API_KEY: no CTI calls, deep-scan still completes", async () => {
		const fetchMock = makeFetchMock([
			(url) => {
				if (new URL(url).hostname === "phish.example.com") {
					return new Response("<html><title>Login</title></html>", {
						status: 200,
						headers: { "content-type": "text/html" },
					});
				}
				return null;
			},
			(url) => (new URL(url).hostname === "rdap.org" ? new Response("{}", { status: 200 }) : null),
		]);
		globalThis.fetch = fetchMock as unknown as typeof fetch;

		const harness = makeStub([{ id: "u1", url: "https://phish.example.com/login" }]);
		// No apiKey — CTI stage must short-circuit.
		const env = makeEnv({ kv: makeKv(), stub: harness.stub });

		const result = await runDeepScan({ env, mailboxId: "m@x", emailId: "e2" });

		expect(result).toBeDefined();
		// No CTI HTTP calls were made.
		const ctiCalls = fetchMock.mock.calls.filter((c) =>
			new URL(String(c[0])).hostname === "cti.api.crowdsec.net",
		);
		expect(ctiCalls.length).toBe(0);
		// SSRF-guard DoH calls (cloudflare-dns.com) are now made by resolveUrl
		// for every URL hop regardless of CTI configuration; the CTI-stage
		// resolveHostsToIps is still gated on the API key.  Only assert that
		// no CTI API calls happened.
		// No CTI reasons.
		expect(result.reasons.join(" ")).not.toMatch(/redirect target IP/);
	});
});
