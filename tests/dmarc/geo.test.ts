// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Unit tests for `workers/dmarc/geo.ts` — IP → country + ASN enrichment.
 *
 * Mock fetch dispatchers use `new URL(url).hostname` checks (CodeQL gate:
 * no url.startsWith / url.includes). Three cases are exercised:
 *   1. Resolved: both origin and peer Cymru lookups succeed → asn + country
 *   2. PTR-only: origin succeeds but peer lookup returns no answer → bare ASN
 *   3. Unresolved: origin lookup returns no answer → both null
 *
 * A fourth case validates that non-IPv4 addresses (IPv6, garbage) are
 * short-circuited before any fetch is issued.
 */

import { describe, expect, it, vi } from "vitest";
import { lookupIpGeo } from "../../workers/dmarc/geo";

function dohTxtResponse(data: string) {
	return new Response(
		JSON.stringify({
			Status: 0,
			Answer: [{ type: 16, data: `"${data}"` }],
		}),
		{ status: 200, headers: { "content-type": "application/dns-json" } },
	);
}

function dohEmptyResponse() {
	return new Response(
		JSON.stringify({ Status: 0, Answer: [] }),
		{ status: 200, headers: { "content-type": "application/dns-json" } },
	);
}

function makeDispatcher(
	originData: string | null,
	peerData: string | null,
): typeof fetch {
	return vi.fn(async (input: RequestInfo | URL) => {
		const url = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url;
		const u = new URL(url);
		if (u.hostname !== "cloudflare-dns.com") {
			return new Response(null, { status: 404 });
		}
		const name = u.searchParams.get("name") ?? "";
		if (name.includes(".origin.asn.cymru.com")) {
			return originData ? dohTxtResponse(originData) : dohEmptyResponse();
		}
		if (name.includes(".asn.cymru.com")) {
			return peerData ? dohTxtResponse(peerData) : dohEmptyResponse();
		}
		return new Response(null, { status: 404 });
	}) as unknown as typeof fetch;
}

describe("lookupIpGeo", () => {
	it("returns country and full ASN org when both lookups succeed", async () => {
		const fetchImpl = makeDispatcher(
			"15169 | 8.8.8.0/24 | US | arin | 1992-12-01",
			"15169 | US | arin | 1992-12-01 | GOOGLE, US",
		);
		const result = await lookupIpGeo("8.8.8.8", fetchImpl);
		expect(result.country).toBe("US");
		expect(result.asn).toBe("AS15169 GOOGLE, US");
	});

	it("returns bare ASN number when peer lookup finds no TXT answer", async () => {
		const fetchImpl = makeDispatcher(
			"15169 | 8.8.8.0/24 | US | arin | 1992-12-01",
			null,
		);
		const result = await lookupIpGeo("8.8.8.8", fetchImpl);
		expect(result.country).toBe("US");
		expect(result.asn).toBe("AS15169");
	});

	it("returns both null when origin lookup finds no TXT answer (unresolved)", async () => {
		const fetchImpl = makeDispatcher(null, null);
		const result = await lookupIpGeo("192.0.2.1", fetchImpl);
		expect(result.asn).toBeNull();
		expect(result.country).toBeNull();
	});

	it("issues no fetch for IPv6 addresses", async () => {
		const fetchImpl = vi.fn() as unknown as typeof fetch;
		const result = await lookupIpGeo("2001:db8::1", fetchImpl);
		expect(result.asn).toBeNull();
		expect(result.country).toBeNull();
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("issues no fetch for obviously invalid input", async () => {
		const fetchImpl = vi.fn() as unknown as typeof fetch;
		const result = await lookupIpGeo("not-an-ip", fetchImpl);
		expect(result.asn).toBeNull();
		expect(result.country).toBeNull();
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("returns null on DoH error (non-200 status)", async () => {
		const fetchImpl = vi.fn(async () => new Response(null, { status: 503 })) as unknown as typeof fetch;
		const result = await lookupIpGeo("8.8.8.8", fetchImpl);
		expect(result.asn).toBeNull();
		expect(result.country).toBeNull();
	});

	it("reverses IP octets correctly for the origin DNS query", async () => {
		const calls: string[] = [];
		const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url;
			calls.push(new URL(url).searchParams.get("name") ?? "");
			return dohEmptyResponse();
		}) as unknown as typeof fetch;
		await lookupIpGeo("1.2.3.4", fetchImpl);
		expect(calls[0]).toBe("4.3.2.1.origin.asn.cymru.com");
	});
});
