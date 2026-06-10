import { describe, expect, it } from "vitest";
import { extractTitle, resolveUrl } from "../../workers/intel/url-resolver";

const DOH_HOST = "cloudflare-dns.com";

/**
 * Minimal fetch stub that plays back scripted responses by URL.
 *
 * DoH A/AAAA queries to cloudflare-dns.com are intercepted and answered
 * from `dohMap` (hostname → IP strings, IPv4 and/or IPv6). Entries are
 * routed by record type: dotted-quads answer A queries (type 1), colon
 * forms answer AAAA queries (type 28). When a hostname is absent from
 * `dohMap`, the answer section is empty — the SSRF guard treats an empty
 * answer as "no private IPs found" and allows the request.
 */
function stubFetch(
	chain: Record<string, Response>,
	dohMap: Record<string, string[]> = {},
): typeof fetch {
	return (async (input: string | URL | Request) => {
		const url = typeof input === "string" ? input : (input as Request).url ?? String(input);
		const parsed = new URL(url);
		if (parsed.hostname === DOH_HOST) {
			const name = parsed.searchParams.get("name") ?? "";
			const qtype = parsed.searchParams.get("type") ?? "A";
			const ips = (dohMap[name] ?? []).filter((ip) =>
				qtype === "AAAA" ? ip.includes(":") : !ip.includes(":"),
			);
			const typeNum = qtype === "AAAA" ? 28 : 1;
			return new Response(
				JSON.stringify({ Answer: ips.map((ip) => ({ type: typeNum, data: ip })) }),
				{ status: 200, headers: { "content-type": "application/dns-json" } },
			);
		}
		const res = chain[url];
		if (!res) throw new Error(`unexpected URL: ${url}`);
		return res;
	}) as typeof fetch;
}

describe("extractTitle", () => {
	it("pulls the first <title> from an HTML doc", () => {
		expect(extractTitle("<html><title> Login </title></html>")).toBe("Login");
	});
	it("collapses whitespace and trims", () => {
		expect(extractTitle("<html><title>\n  Sign\n  in\n</title></html>")).toBe("Sign in");
	});
	it("returns null when no title tag is present", () => {
		expect(extractTitle("<html><body>no title</body></html>")).toBeNull();
	});
	it("caps at 200 chars", () => {
		const long = "x".repeat(500);
		expect(extractTitle(`<title>${long}</title>`)?.length).toBe(200);
	});
});

describe("resolveUrl", () => {
	it("follows a single 302 redirect to a new host and flags host_changed", async () => {
		const fetchImpl = stubFetch({
			"https://short.example/abc": new Response("", {
				status: 302,
				headers: { location: "https://target.example/phish" },
			}),
			"https://target.example/phish": new Response("<html><title>Sign in</title></html>", {
				status: 200,
				headers: { "content-type": "text/html" },
			}),
		});
		const r = await resolveUrl("https://short.example/abc", fetchImpl);
		expect(r?.resolved).toBe("https://target.example/phish");
		expect(r?.host_changed).toBe(true);
		expect(r?.title).toBe("Sign in");
		expect(r?.hops).toBe(2);
	});

	it("truncates at the max redirect depth without following indefinitely", async () => {
		// Build a 10-deep chain; MAX_REDIRECT_HOPS is 5.
		const chain: Record<string, Response> = {};
		for (let i = 0; i < 10; i++) {
			chain[`https://hop${i}.example/`] = new Response("", {
				status: 302,
				headers: { location: `https://hop${i + 1}.example/` },
			});
		}
		chain["https://hop10.example/"] = new Response("done", { status: 200 });
		const r = await resolveUrl("https://hop0.example/", stubFetch(chain));
		expect(r?.truncated).toBe(true);
		expect(r?.hops).toBeLessThanOrEqual(5);
	});

	it("returns a result with final_status=0 when the fetch throws", async () => {
		const fetchImpl = (async () => { throw new Error("offline"); }) as typeof fetch;
		const r = await resolveUrl("https://offline.example", fetchImpl);
		expect(r?.final_status).toBe(0);
		expect(r?.resolved).toBe("https://offline.example");
	});

	it("does not change host when the redirect stays on the same domain", async () => {
		const fetchImpl = stubFetch({
			"https://same.example/a": new Response("", {
				status: 302,
				headers: { location: "https://same.example/b" },
			}),
			"https://same.example/b": new Response("ok", { status: 200 }),
		});
		const r = await resolveUrl("https://same.example/a", fetchImpl);
		expect(r?.host_changed).toBe(false);
	});

	it("returns null for a URL that cannot be parsed", async () => {
		const r = await resolveUrl("not a url");
		expect(r).toBeNull();
	});
});

describe("resolveUrl SSRF guard", () => {
	it("blocks non-http/https schemes and returns final_status=0", async () => {
		const r = await resolveUrl("ftp://files.example/payload", stubFetch({}));
		expect(r?.final_status).toBe(0);
		expect(r?.resolved).toBe("ftp://files.example/payload");
	});

	it("blocks direct loopback IPv4 (127.0.0.1) before the first fetch", async () => {
		const fetchSpy = stubFetch({});
		const r = await resolveUrl("http://127.0.0.1/admin", fetchSpy);
		expect(r?.final_status).toBe(0);
	});

	it("blocks direct RFC-1918 IPv4 (10.x.x.x) before the first fetch", async () => {
		const r = await resolveUrl("http://10.0.0.1/internal", stubFetch({}));
		expect(r?.final_status).toBe(0);
	});

	it("blocks cloud-metadata IP (169.254.169.254) before the first fetch", async () => {
		const r = await resolveUrl("http://169.254.169.254/latest/meta-data/", stubFetch({}));
		expect(r?.final_status).toBe(0);
	});

	it("blocks a hostname that resolves to a private IP via DoH", async () => {
		const fetchImpl = stubFetch(
			{},
			{ "internal.corp.example": ["192.168.1.50"] },
		);
		const r = await resolveUrl("http://internal.corp.example/", fetchImpl);
		expect(r?.final_status).toBe(0);
	});

	it("blocks a redirect whose absolutized Location resolves to a private IP", async () => {
		// short.example is public; the redirect target resolves to RFC-1918.
		const fetchImpl = stubFetch(
			{
				"https://short.example/track": new Response("", {
					status: 302,
					headers: { location: "https://intranet.corp.example/portal" },
				}),
			},
			{ "intranet.corp.example": ["172.16.0.5"] },
		);
		const r = await resolveUrl("https://short.example/track", fetchImpl);
		// Chain stopped at short.example; the private hop was never fetched.
		expect(r?.resolved).toBe("https://short.example/track");
	});

	it("allows a URL whose hostname resolves to a public IP", async () => {
		const fetchImpl = stubFetch(
			{
				"https://public.example/page": new Response("<title>Hello</title>", {
					status: 200,
					headers: { "content-type": "text/html" },
				}),
			},
			{ "public.example": ["93.184.216.34"] },
		);
		const r = await resolveUrl("https://public.example/page", fetchImpl);
		expect(r?.resolved).toBe("https://public.example/page");
		expect(r?.final_status).toBe(200);
	});

	it("allows a URL when DoH lookup fails (fail-open)", async () => {
		// DoH throws → resolveHostIps returns [] → no private IPs → allow.
		const fetchImpl = (async (input: string | URL | Request) => {
			const url = typeof input === "string" ? input : String(input);
			if (new URL(url).hostname === DOH_HOST) throw new Error("dns error");
			return new Response("ok", { status: 200 });
		}) as typeof fetch;
		const r = await resolveUrl("https://legit.example/", fetchImpl);
		expect(r?.final_status).toBe(200);
	});
});

describe("resolveUrl SSRF guard — residual gaps (GHSA-vpmq-j44v-vjr6)", () => {
	it("blocks an IPv4-mapped IPv6 loopback literal (http://[::ffff:127.0.0.1]/) before the first fetch", async () => {
		// WHATWG URL serializes the hostname to [::ffff:7f00:1]; the guard must
		// unwrap the embedded IPv4 and treat it as loopback.
		const r = await resolveUrl("http://[::ffff:127.0.0.1]/admin", stubFetch({}));
		expect(r?.final_status).toBe(0);
	});

	it("blocks an IPv4-mapped IPv6 RFC-1918 literal (http://[::ffff:10.0.0.1]/)", async () => {
		const r = await resolveUrl("http://[::ffff:10.0.0.1]/internal", stubFetch({}));
		expect(r?.final_status).toBe(0);
	});

	it("blocks the unspecified-address literals 0.0.0.0 and [::]", async () => {
		const r4 = await resolveUrl("http://0.0.0.0/", stubFetch({}));
		expect(r4?.final_status).toBe(0);
		const r6 = await resolveUrl("http://[::]/", stubFetch({}));
		expect(r6?.final_status).toBe(0);
	});

	it("blocks a hostname whose AAAA record resolves to ::1", async () => {
		const fetchImpl = stubFetch(
			{},
			{ "v6-loopback.example": ["::1"] },
		);
		const r = await resolveUrl("http://v6-loopback.example/", fetchImpl);
		expect(r?.final_status).toBe(0);
	});

	it("blocks a hostname whose AAAA record resolves to a unique-local (fc00::/7) address", async () => {
		const fetchImpl = stubFetch(
			{},
			{ "v6-ula.example": ["fd12:3456:789a::1"] },
		);
		const r = await resolveUrl("http://v6-ula.example/", fetchImpl);
		expect(r?.final_status).toBe(0);
	});

	it("blocks a redirect to a hostname whose AAAA record is private even when its A record is public", async () => {
		const fetchImpl = stubFetch(
			{
				"https://short.example/go": new Response("", {
					status: 302,
					headers: { location: "https://dual.corp.example/portal" },
				}),
			},
			{ "dual.corp.example": ["93.184.216.34", "fc00::5"] },
		);
		const r = await resolveUrl("https://short.example/go", fetchImpl);
		// Chain stopped at short.example; the private-v6 hop was never fetched.
		expect(r?.resolved).toBe("https://short.example/go");
	});

	it("allows a hostname with public A and AAAA records (no happy-path regression)", async () => {
		const fetchImpl = stubFetch(
			{
				"https://dualstack.example/page": new Response("<title>Hi</title>", {
					status: 200,
					headers: { "content-type": "text/html" },
				}),
			},
			{ "dualstack.example": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"] },
		);
		const r = await resolveUrl("https://dualstack.example/page", fetchImpl);
		expect(r?.final_status).toBe(200);
		expect(r?.resolved).toBe("https://dualstack.example/page");
	});
});
