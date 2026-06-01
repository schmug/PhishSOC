import { describe, expect, it, vi } from "vitest";
import { resolveSourceLabel, DOH_HOST } from "../../workers/dmarc/source-label";
import { matchProviderByPtr } from "../../shared/dmarc-provider-labels";
import { ingestDmarcReport } from "../../workers/dmarc/ingest";
import type { Email, Attachment } from "postal-mime";

// ---------------------------------------------------------------------------
// matchProviderByPtr (pure, no network)
// ---------------------------------------------------------------------------

describe("matchProviderByPtr", () => {
	it("matches Google", () => {
		expect(matchProviderByPtr("mail-oa1-f73.google.com")).toBe("Google");
	});

	it("matches Microsoft 365 via outbound.protection.outlook.com suffix", () => {
		expect(matchProviderByPtr("mail-db8eur06on2193.outbound.protection.outlook.com")).toBe("Microsoft 365");
	});

	it("matches SendGrid", () => {
		expect(matchProviderByPtr("smtp1.sendgrid.net")).toBe("SendGrid");
	});

	it("matches Amazon SES", () => {
		expect(matchProviderByPtr("a1-5.smtp-out.eu-west-1.amazonses.com")).toBe("Amazon SES");
	});

	it("returns null for an unknown PTR", () => {
		expect(matchProviderByPtr("mail.example.com")).toBeNull();
	});

	it("is case-insensitive", () => {
		expect(matchProviderByPtr("SMTP1.SENDGRID.NET")).toBe("SendGrid");
	});
});

// ---------------------------------------------------------------------------
// resolveSourceLabel — mock fetch; never real network
// ---------------------------------------------------------------------------

function ptrResponse(ptr: string | null): () => Promise<Response> {
	return () => {
		const body = ptr
			? JSON.stringify({ Answer: [{ type: 12, data: `${ptr}.` }] })
			: JSON.stringify({ Answer: [] });
		return Promise.resolve(new Response(body, { status: 200 }));
	};
}

function failFetch(): Promise<Response> {
	return Promise.reject(new Error("network error"));
}

describe("resolveSourceLabel", () => {
	it("returns the provider name when PTR matches a known provider", async () => {
		const mockFetch = ptrResponse("mail-oa1-f73.google.com");
		const label = await resolveSourceLabel("74.125.0.1", mockFetch as unknown as typeof fetch);
		expect(label).toBe("Google");
	});

	it("returns the raw PTR hostname when PTR does not match any provider", async () => {
		const mockFetch = ptrResponse("relay.example.com");
		const label = await resolveSourceLabel("203.0.113.1", mockFetch as unknown as typeof fetch);
		expect(label).toBe("relay.example.com");
	});

	it("returns null when the PTR response has no Answer", async () => {
		const mockFetch = ptrResponse(null);
		const label = await resolveSourceLabel("203.0.113.99", mockFetch as unknown as typeof fetch);
		expect(label).toBeNull();
	});

	it("returns null when fetch throws (network error)", async () => {
		const label = await resolveSourceLabel(
			"198.51.100.1",
			failFetch as unknown as typeof fetch,
		);
		expect(label).toBeNull();
	});

	it("returns null when fetch returns a non-ok status", async () => {
		const mockFetch = () => Promise.resolve(new Response("", { status: 500 }));
		const label = await resolveSourceLabel(
			"192.0.2.1",
			mockFetch as unknown as typeof fetch,
		);
		expect(label).toBeNull();
	});

	it("queries the DoH host (no substring matching — CodeQL rule)", async () => {
		let capturedUrl: string | null = null;
		const mockFetch = (url: string | URL) => {
			capturedUrl = String(url);
			return Promise.resolve(new Response(JSON.stringify({ Answer: [] }), { status: 200 }));
		};
		await resolveSourceLabel("1.2.3.4", mockFetch as unknown as typeof fetch);
		expect(capturedUrl).not.toBeNull();
		// Verify the DoH host via URL parsing, never via substring match (CodeQL gate).
		const parsed = new URL(capturedUrl!);
		expect(parsed.hostname).toBe(DOH_HOST);
		// Confirm the arpa name (1.2.3.4 → 4.3.2.1.in-addr.arpa) appears in the query.
		expect(parsed.searchParams.get("name")).toBe("4.3.2.1.in-addr.arpa");
		expect(parsed.searchParams.get("type")).toBe("PTR");
	});
});

// ---------------------------------------------------------------------------
// ingestDmarcReport integration — verifies PTR is resolved once per new IP
// ---------------------------------------------------------------------------

function makeRuaEmail(xmlText: string): Email {
	const content = new TextEncoder().encode(xmlText).buffer as ArrayBuffer;
	return {
		subject: "Report Domain: example.com Submitter: google.com Report-ID: 123",
		from: { address: "dmarc-noreply@google.com", name: "Google" },
		attachments: [
			{
				mimeType: "application/xml",
				content,
				filename: "example.com!google.com!1000!1001.xml",
				disposition: "attachment",
				headers: [],
			} as unknown as Attachment,
		],
	} as Email;
}

const MINIMAL_RUA = `<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <report_id>test-123</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <p>none</p>
  </policy_published>
  <record>
    <row>
      <source_ip>74.125.0.1</source_ip>
      <count>10</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>pass</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>`;

describe("ingestDmarcReport — source label enrichment", () => {
	function makeStub(overrides: { knownIps?: Set<string> } = {}) {
		const knownIps = overrides.knownIps ?? new Set<string>();
		return {
			insertDmarcReport: vi.fn().mockResolvedValue(undefined),
			getDmarcKnownSourceIps: vi.fn().mockReturnValue(knownIps),
			insertDmarcSourceIfNew: vi.fn(),
		};
	}

	function makeEnv(stub: ReturnType<typeof makeStub>): import("../../workers/types").Env {
		return {
			MAILBOX: {
				idFromName: (_name: string) => ({ toString: () => "test-id" }),
				get: (_id: unknown) => stub,
			},
		} as unknown as import("../../workers/types").Env;
	}

	it("resolves PTR for a new source IP and stores the label", async () => {
		const fetchCalls: string[] = [];
		const mockFetch = (url: string | URL) => {
			fetchCalls.push(String(url));
			const body = JSON.stringify({
				Answer: [{ type: 12, data: "mail-oa1-f73.google.com." }],
			});
			return Promise.resolve(new Response(body, { status: 200 }));
		};
		vi.stubGlobal("fetch", mockFetch);
		const stub = makeStub();
		const env = makeEnv(stub);
		const result = await ingestDmarcReport(env, "mb-1", "msg-1", makeRuaEmail(MINIMAL_RUA));
		expect(result.ingested).toBe(true);
		expect(stub.getDmarcKnownSourceIps).toHaveBeenCalledWith(["74.125.0.1"]);
		expect(stub.insertDmarcSourceIfNew).toHaveBeenCalledWith("74.125.0.1", "Google");
		// Confirm the DoH URL was called; parse hostname — never substring match (CodeQL gate).
		const dohCall = fetchCalls.find((u) => new URL(u).hostname === DOH_HOST);
		expect(dohCall).toBeDefined();
	});

	it("skips PTR resolution when IP is already in dmarc_sources", async () => {
		const fetchCalls: string[] = [];
		vi.stubGlobal("fetch", (url: string | URL) => {
			fetchCalls.push(String(url));
			return Promise.resolve(new Response(JSON.stringify({}), { status: 200 }));
		});
		// Pretend the IP already has a label row.
		const stub = makeStub({ knownIps: new Set(["74.125.0.1"]) });
		const env = makeEnv(stub);
		await ingestDmarcReport(env, "mb-1", "msg-2", makeRuaEmail(MINIMAL_RUA));
		// No DoH calls should have been made for the already-known IP.
		const dohCalls = fetchCalls.filter((u) => new URL(u).hostname === DOH_HOST);
		expect(dohCalls).toHaveLength(0);
		expect(stub.insertDmarcSourceIfNew).not.toHaveBeenCalled();
	});
});
