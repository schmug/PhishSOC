// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { describe, expect, it } from "vitest";
import { ipToArpa, PTR_DOH_HOST, resolvePtr } from "../../workers/dmarc/ptr-resolve";
import { buildDmarcSourceLabel, classifyProvider } from "../../shared/dmarc-provider";

// ── ipToArpa ──────────────────────────────────────────────────────────────

describe("ipToArpa", () => {
	it("reverses IPv4 octets and appends .in-addr.arpa", () => {
		expect(ipToArpa("203.0.113.42")).toBe("42.113.0.203.in-addr.arpa");
	});

	it("returns null for non-IPv4 input", () => {
		expect(ipToArpa("2001:db8::1")).toBeNull();
		expect(ipToArpa("not-an-ip")).toBeNull();
		expect(ipToArpa("")).toBeNull();
	});
});

// ── classifyProvider ──────────────────────────────────────────────────────

describe("classifyProvider", () => {
	it("matches Google sending infrastructure", () => {
		expect(classifyProvider("mail-sor-f41.google.com")).toBe("Google");
	});

	it("matches Microsoft 365 protection domain", () => {
		expect(classifyProvider("mx1.mail.protection.outlook.com")).toBe("Microsoft 365");
	});

	it("matches SendGrid", () => {
		expect(classifyProvider("o1.sendgrid.net")).toBe("SendGrid");
	});

	it("matches Amazon SES", () => {
		expect(classifyProvider("a-123.us-east-1.amazonses.amazonaws.com")).toBe("Amazon SES");
	});

	it("returns null for an unknown hostname", () => {
		expect(classifyProvider("mail.example.com")).toBeNull();
	});

	it("is case-insensitive", () => {
		expect(classifyProvider("MAIL-SOR.GOOGLE.COM")).toBe("Google");
	});
});

// ── buildDmarcSourceLabel ────────────────────────────────────────────────

describe("buildDmarcSourceLabel", () => {
	it("returns provider name for a known ESP hostname", () => {
		expect(buildDmarcSourceLabel("mail-sor.google.com")).toBe("Google");
	});

	it("returns the hostname itself for an unknown PTR", () => {
		expect(buildDmarcSourceLabel("mail.acme-corp.com")).toBe("mail.acme-corp.com");
	});

	it("returns null when no hostname was resolved", () => {
		expect(buildDmarcSourceLabel(null)).toBeNull();
	});
});

// ── resolvePtr (DoH) ──────────────────────────────────────────────────────

function ptrDohResponse(ptrs: string[]): Response {
	return new Response(
		JSON.stringify({
			Status: 0,
			Answer: ptrs.map((data) => ({ type: 12, data })),
		}),
		{ status: 200, headers: { "content-type": "application/dns-json" } },
	);
}

function nxdomainResponse(): Response {
	return new Response(
		JSON.stringify({ Status: 3, Answer: [] }),
		{ status: 200, headers: { "content-type": "application/dns-json" } },
	);
}

describe("resolvePtr", () => {
	it("queries cloudflare-dns.com with the reversed ARPA form", async () => {
		let capturedUrl = "";
		const fetchImpl = async (url: string) => {
			capturedUrl = url;
			// Hostname-based dispatch — no url.startsWith / url.includes (CodeQL gate).
			const u = new URL(url);
			expect(u.hostname).toBe(PTR_DOH_HOST);
			return ptrDohResponse(["mail-sor.google.com."]);
		};
		await resolvePtr("203.0.113.42", { fetchImpl });
		expect(new URL(capturedUrl).searchParams.get("type")).toBe("PTR");
		expect(new URL(capturedUrl).searchParams.get("name")).toBe(
			"42.113.0.203.in-addr.arpa",
		);
	});

	it("provider-match: returns Google label for a Google PTR", async () => {
		const fetchImpl = async (_url: string) =>
			ptrDohResponse(["mail-sor-f41.google.com."]);
		const hostname = await resolvePtr("74.125.0.1", { fetchImpl });
		expect(buildDmarcSourceLabel(hostname)).toBe("Google");
	});

	it("PTR-only: returns hostname as label for an unknown PTR", async () => {
		const fetchImpl = async (_url: string) =>
			ptrDohResponse(["mail.acme-corp.com."]);
		const hostname = await resolvePtr("203.0.113.5", { fetchImpl });
		expect(hostname).toBe("mail.acme-corp.com");
		expect(buildDmarcSourceLabel(hostname)).toBe("mail.acme-corp.com");
	});

	it("unresolved: returns null on NXDOMAIN (no PTR answer)", async () => {
		const fetchImpl = async (_url: string) => nxdomainResponse();
		const hostname = await resolvePtr("192.0.2.99", { fetchImpl });
		expect(hostname).toBeNull();
		expect(buildDmarcSourceLabel(hostname)).toBeNull();
	});

	it("unresolved: returns null on HTTP error", async () => {
		const fetchImpl = async (_url: string) =>
			new Response("server error", { status: 500 });
		expect(await resolvePtr("192.0.2.1", { fetchImpl })).toBeNull();
	});

	it("unresolved: returns null when fetch throws (network failure)", async () => {
		const fetchImpl = async (_url: string): Promise<Response> => {
			throw new Error("network failure");
		};
		expect(await resolvePtr("192.0.2.1", { fetchImpl })).toBeNull();
	});

	it("strips the trailing dot from the PTR answer", async () => {
		const fetchImpl = async (_url: string) =>
			ptrDohResponse(["mail.example.com."]);
		expect(await resolvePtr("203.0.113.1", { fetchImpl })).toBe("mail.example.com");
	});

	it("returns null for a non-IPv4 address without making a DoH call", async () => {
		let called = false;
		const fetchImpl = async (_url: string): Promise<Response> => {
			called = true;
			return ptrDohResponse([]);
		};
		expect(await resolvePtr("2001:db8::1", { fetchImpl })).toBeNull();
		expect(called).toBe(false);
	});
});
