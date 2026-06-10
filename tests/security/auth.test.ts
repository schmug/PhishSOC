import { describe, expect, it } from "vitest";
import {
	emptyVerdict,
	extractReceivedFromIp,
	isPrivateOrLoopbackIp,
	parseAuthResults,
	scoreAuth,
} from "../../workers/security/auth";

function header(name: string, value: string) {
	return { key: name, value };
}

describe("parseAuthResults", () => {
	it("returns all-none when no Authentication-Results header present", () => {
		expect(parseAuthResults([header("from", "a@b.com")])).toEqual(emptyVerdict());
	});

	it("returns all-none when rawHeaders is not an array", () => {
		expect(parseAuthResults(null)).toEqual(emptyVerdict());
		expect(parseAuthResults(undefined)).toEqual(emptyVerdict());
		expect(parseAuthResults("not-an-array")).toEqual(emptyVerdict());
	});

	it("parses a standard gmail-style Authentication-Results header", () => {
		const verdict = parseAuthResults([
			header(
				"Authentication-Results",
				"mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
			),
		]);
		expect(verdict).toMatchObject({ spf: "pass", dkim: "pass", dmarc: "pass", authservId: "mx.google.com" });
	});

	it("captures softfail/fail/temperror/permerror", () => {
		const verdict = parseAuthResults([
			header(
				"Authentication-Results",
				"srv1; spf=softfail smtp.mailfrom=x; dkim=fail; dmarc=temperror",
			),
		]);
		expect(verdict).toMatchObject({ spf: "softfail", dkim: "fail", dmarc: "temperror" });
	});

	it("is case-insensitive on header key and result values", () => {
		const verdict = parseAuthResults([
			header("AUTHENTICATION-RESULTS", "authserv-x; SPF=Pass; DKIM=Fail; DMARC=None"),
		]);
		expect(verdict).toMatchObject({ spf: "pass", dkim: "fail", dmarc: "none", authservId: "authserv-x" });
	});

	it("first-verdict-wins across duplicate Authentication-Results headers", () => {
		// Multiple Authentication-Results headers can appear when mail traverses
		// several verifiers. We trust the first (outermost-recorded) result so a
		// downstream relay cannot override an upstream failure verdict.
		const verdict = parseAuthResults([
			header("Authentication-Results", "inner; spf=fail; dkim=fail; dmarc=fail"),
			header("Authentication-Results", "outer; spf=pass; dkim=pass; dmarc=pass"),
		]);
		expect(verdict).toMatchObject({ spf: "fail", dkim: "fail", dmarc: "fail", authservId: "inner" });
	});

	it("ignores irrelevant headers", () => {
		const verdict = parseAuthResults([
			header("DKIM-Signature", "v=1; a=rsa-sha256; dkim=pass"),
			header("Received-SPF", "pass"),
		]);
		expect(verdict).toEqual(emptyVerdict());
	});

	it("captures authserv-id when no method results are present", () => {
		const verdict = parseAuthResults([
			header("Authentication-Results", "auth.example.com; none"),
		]);
		expect(verdict.authservId).toBe("auth.example.com");
	});
});

describe("parseAuthResults — authserv-id gating", () => {
	// The forgery threat: an attacker-controlled upstream mail server can
	// inject its own Authentication-Results header claiming pass results
	// before sending. Cloudflare Email Routing preserves such headers, so a
	// parser that trusts any Authentication-Results header would accept
	// forged verdicts. These tests pin the defensive behaviour.

	it("ignores headers whose authserv-id is not on the trusted list", () => {
		const v = parseAuthResults(
			[
				header("Authentication-Results", "attacker.example; spf=pass; dkim=pass; dmarc=pass"),
				header("Authentication-Results", "mx.cloudflare.net; spf=fail; dkim=fail; dmarc=fail"),
			],
			{ trustedAuthservIds: ["mx.cloudflare.net"] },
		);
		expect(v).toMatchObject({ spf: "fail", dkim: "fail", dmarc: "fail", authservId: "mx.cloudflare.net", trusted: true });
	});

	it("matches trusted authserv-id as a dotted suffix", () => {
		const v = parseAuthResults(
			[header("Authentication-Results", "mx5.google.com; spf=pass; dkim=pass; dmarc=pass")],
			{ trustedAuthservIds: ["google.com"] },
		);
		expect(v).toMatchObject({ spf: "pass", trusted: true });
	});

	it("returns all-none when no trusted header is present (prefers silence over forged-pass)", () => {
		const v = parseAuthResults(
			[header("Authentication-Results", "attacker.example; spf=pass; dkim=pass; dmarc=pass")],
			{ trustedAuthservIds: ["mx.cloudflare.net"] },
		);
		expect(v).toEqual(emptyVerdict());
	});

	it("parses results with an empty trusted list but does NOT mark them trusted", () => {
		// Back-compat: with no allowlist configured we still parse spf/dkim/dmarc
		// so scoring keeps working. But verdict.trusted stays falsy (F-004): a
		// forged header on an unconfigured deployment must not be treated as
		// authserv-trusted, so it cannot reach the hard-allow short-circuit.
		const v = parseAuthResults(
			[header("Authentication-Results", "anywhere; spf=pass; dkim=pass; dmarc=pass")],
			{ trustedAuthservIds: [] },
		);
		expect(v).toMatchObject({ spf: "pass", dkim: "pass", dmarc: "pass" });
		expect(v.trusted).toBeFalsy();
	});

	it("preserves 'first set wins' — legitimate dkim=none is not overwritten by later headers", () => {
		// Regression: earlier versions used the string 'none' as both the
		// value and the "not yet set" sentinel, so a first header with
		// `dkim=none` let any subsequent header overwrite it — including
		// an attacker-controlled one when gating was off.
		const v = parseAuthResults([
			header("Authentication-Results", "inner; spf=pass; dkim=none; dmarc=pass"),
			header("Authentication-Results", "outer; spf=fail; dkim=pass; dmarc=fail"),
		]);
		expect(v).toMatchObject({ spf: "pass", dkim: "none", dmarc: "pass" });
	});
});

describe("parseAuthResults — DKIM selector observations", () => {
	it("returns an empty observations list when no Authentication-Results header is present", () => {
		const v = parseAuthResults([header("From", "a@b.com")]);
		expect(v.dkimObservations).toEqual([]);
	});

	it("extracts (domain, selector) on a dkim=pass with header.d= and header.s=", () => {
		const v = parseAuthResults([
			header(
				"Authentication-Results",
				"mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com header.s=selector1 header.d=example.com header.b=abc; dmarc=pass",
			),
		]);
		expect(v.dkimObservations).toEqual([
			{ domain: "example.com", selector: "selector1" },
		]);
	});

	it("extracts on dkim=fail too — failing signatures still carry an observed selector", () => {
		const v = parseAuthResults([
			header(
				"Authentication-Results",
				"srv1; dkim=fail header.d=example.com header.s=sel-fail header.b=xyz",
			),
		]);
		expect(v.dkimObservations).toEqual([
			{ domain: "example.com", selector: "sel-fail" },
		]);
	});

	it("extracts every signature from a header with multiple dkim=pass segments", () => {
		// Forwarders frequently re-sign and emit one Authentication-Results
		// header that carries both the original and the forwarder signatures.
		const v = parseAuthResults([
			header(
				"Authentication-Results",
				"mx.google.com; dkim=pass header.d=example.com header.s=sel1 header.b=AAA; dkim=pass header.d=mailinglist.example header.s=fwd-sel header.b=BBB; dmarc=pass",
			),
		]);
		expect(v.dkimObservations).toEqual([
			{ domain: "example.com", selector: "sel1" },
			{ domain: "mailinglist.example", selector: "fwd-sel" },
		]);
	});

	it("dedupes a selector observed twice in the same header (case-insensitive)", () => {
		const v = parseAuthResults([
			header(
				"Authentication-Results",
				"srv; dkim=pass header.d=Example.com header.s=Sel1 header.b=AAA; dkim=pass header.d=example.com header.s=sel1 header.b=BBB",
			),
		]);
		expect(v.dkimObservations).toEqual([
			{ domain: "example.com", selector: "sel1" },
		]);
	});

	it("ignores dkim=none / temperror / permerror — no verified selector to roll up", () => {
		const v = parseAuthResults([
			header(
				"Authentication-Results",
				"srv; dkim=none header.d=example.com header.s=ignored1; dkim=temperror header.d=example.com header.s=ignored2; dkim=permerror header.d=example.com header.s=ignored3",
			),
		]);
		expect(v.dkimObservations).toEqual([]);
	});

	it("skips a dkim=pass segment missing header.d= or header.s=", () => {
		const v = parseAuthResults([
			header(
				"Authentication-Results",
				"srv; dkim=pass header.b=onlybody-no-domain-no-selector",
			),
		]);
		expect(v.dkimObservations).toEqual([]);
	});

	it("does NOT cross method boundaries — header.d= on the SPF segment is not paired with the DKIM selector", () => {
		// `;`-segment scoping prevents misattribution. Without it, an SPF segment
		// carrying `header.d=other` followed by a DKIM segment with `header.s=sel`
		// would emit `(other, sel)` — a wrong observation that would hit DoH for
		// a selector that doesn't exist under that domain.
		const v = parseAuthResults([
			header(
				"Authentication-Results",
				"srv; spf=pass header.d=other.example; dkim=pass header.s=sel1 header.d=example.com",
			),
		]);
		expect(v.dkimObservations).toEqual([
			{ domain: "example.com", selector: "sel1" },
		]);
	});

	it("handles quoted selectors and quoted domains", () => {
		const v = parseAuthResults([
			header(
				"Authentication-Results",
				'srv; dkim=pass header.d="example.com" header.s="sel quoted"',
			),
		]);
		expect(v.dkimObservations).toEqual([
			{ domain: "example.com", selector: "sel quoted" },
		]);
	});

	it("does NOT record observations from headers whose authserv-id is untrusted", () => {
		// Threat model: an attacker-controlled relay can inject an
		// Authentication-Results header claiming `dkim=pass header.d=victim.com
		// header.s=attacker-sel`. Recording that selector would make the
		// dashboard advertise an attacker-chosen DKIM selector as "observed"
		// for victim.com. The trusted-id gate prevents this.
		const v = parseAuthResults(
			[
				header(
					"Authentication-Results",
					"attacker.example; dkim=pass header.d=victim.com header.s=attacker-sel",
				),
				header(
					"Authentication-Results",
					"mx.cloudflare.net; dkim=pass header.d=victim.com header.s=legit-sel",
				),
			],
			{ trustedAuthservIds: ["mx.cloudflare.net"] },
		);
		expect(v.dkimObservations).toEqual([
			{ domain: "victim.com", selector: "legit-sel" },
		]);
	});

	it("dedupes selectors observed across multiple Authentication-Results headers", () => {
		const v = parseAuthResults([
			header(
				"Authentication-Results",
				"inner; dkim=pass header.d=example.com header.s=sel1",
			),
			header(
				"Authentication-Results",
				"outer; dkim=pass header.d=example.com header.s=sel1",
			),
		]);
		expect(v.dkimObservations).toEqual([
			{ domain: "example.com", selector: "sel1" },
		]);
	});
});

describe("scoreAuth", () => {
	it("scores a clean pass as a net-negative (credit)", () => {
		const { score } = scoreAuth({ spf: "pass", dkim: "pass", dmarc: "pass" });
		expect(score).toBe(-10);
	});

	it("scores a DMARC fail as suspicious", () => {
		const { score, reasons } = scoreAuth({ spf: "pass", dkim: "pass", dmarc: "fail" });
		expect(score).toBeGreaterThanOrEqual(20);
		expect(reasons.join(" ")).toMatch(/DMARC/i);
	});

	it("caps multi-fail contribution at 30 (before DMARC-pass credit)", () => {
		const { score } = scoreAuth({ spf: "fail", dkim: "fail", dmarc: "fail" });
		expect(score).toBe(30);
	});

	it("scores SPF softfail identically to SPF fail (treats both as suspicious)", () => {
		const softfail = scoreAuth({ spf: "softfail", dkim: "none", dmarc: "none" });
		const fail = scoreAuth({ spf: "fail", dkim: "none", dmarc: "none" });
		expect(softfail.score).toBe(fail.score);
	});

	it("returns zero for all-none (no auth headers present)", () => {
		const { score } = scoreAuth(emptyVerdict());
		expect(score).toBe(0);
	});
});

describe("extractReceivedFromIp", () => {
	it("returns undefined when there are no Received headers", () => {
		expect(extractReceivedFromIp([header("Authentication-Results", "x; spf=pass")])).toBeUndefined();
	});

	it("returns undefined when rawHeaders is not an array", () => {
		expect(extractReceivedFromIp(null)).toBeUndefined();
		expect(extractReceivedFromIp(undefined)).toBeUndefined();
		expect(extractReceivedFromIp("not-an-array")).toBeUndefined();
	});

	it("extracts an external IPv4 from a bracketed RFC 5321 Received line", () => {
		const headers = [
			header(
				"Received",
				"from mail.example.com (mail.example.com [203.0.113.42]) by mx.cloudflare.com",
			),
		];
		expect(extractReceivedFromIp(headers)).toBe("203.0.113.42");
	});

	it("returns the FIRST external IP (most-recent external hop) when multiple Received lines present", () => {
		// PostalMime preserves header order: most-recent hop first.
		const headers = [
			header(
				"Received",
				"from inbound.cloudflare.net (inbound.cloudflare.net [10.0.0.5]) by mx",
			),
			header(
				"Received",
				"from sender.example.com (sender.example.com [198.51.100.7]) by inbound.cloudflare.net",
			),
			header(
				"Received",
				"from origin.attacker.example (origin.attacker.example [203.0.113.99]) by sender.example.com",
			),
		];
		// 10.0.0.5 is private and is skipped; the next external hop is 198.51.100.7.
		expect(extractReceivedFromIp(headers)).toBe("198.51.100.7");
	});

	it("skips RFC1918 private IPs (10/8, 172.16/12, 192.168/16)", () => {
		expect(
			extractReceivedFromIp([
				header("Received", "from internal (internal [10.1.2.3]) by mx"),
				header("Received", "from public (public [203.0.113.1]) by internal"),
			]),
		).toBe("203.0.113.1");
		expect(
			extractReceivedFromIp([
				header("Received", "from internal (internal [172.16.0.1]) by mx"),
				header("Received", "from public (public [203.0.113.2]) by internal"),
			]),
		).toBe("203.0.113.2");
		expect(
			extractReceivedFromIp([
				header("Received", "from internal (internal [192.168.1.1]) by mx"),
				header("Received", "from public (public [203.0.113.3]) by internal"),
			]),
		).toBe("203.0.113.3");
	});

	it("skips loopback (127/8) and link-local (169.254/16)", () => {
		expect(
			extractReceivedFromIp([
				header("Received", "from local (local [127.0.0.1]) by mx"),
				header("Received", "from external (external [203.0.113.4]) by local"),
			]),
		).toBe("203.0.113.4");
		expect(
			extractReceivedFromIp([
				header("Received", "from ll (ll [169.254.10.10]) by mx"),
				header("Received", "from external (external [203.0.113.5]) by ll"),
			]),
		).toBe("203.0.113.5");
	});

	it("returns undefined when every Received line is internal", () => {
		expect(
			extractReceivedFromIp([
				header("Received", "from a (a [10.0.0.1]) by b"),
				header("Received", "from c (c [192.168.1.1]) by d"),
			]),
		).toBeUndefined();
	});

	it("handles bare-bracket IPv4 without a parenthesized hostname", () => {
		expect(
			extractReceivedFromIp([
				header("Received", "from sender [203.0.113.55] by mx"),
			]),
		).toBe("203.0.113.55");
	});
});

describe("isPrivateOrLoopbackIp — IPv4-mapped IPv6, NAT64, unspecified (GHSA-vpmq-j44v-vjr6)", () => {
	it("blocks IPv4-mapped IPv6 loopback in dotted form (::ffff:127.0.0.1)", () => {
		expect(isPrivateOrLoopbackIp("::ffff:127.0.0.1")).toBe(true);
	});

	it("blocks IPv4-mapped IPv6 loopback in hex form (::ffff:7f00:1)", () => {
		// WHATWG URL serializes http://[::ffff:127.0.0.1]/ to this hex form.
		expect(isPrivateOrLoopbackIp("::ffff:7f00:1")).toBe(true);
	});

	it("blocks IPv4-mapped RFC-1918 space in dotted and hex forms", () => {
		expect(isPrivateOrLoopbackIp("::ffff:10.0.0.1")).toBe(true);
		expect(isPrivateOrLoopbackIp("::ffff:a00:1")).toBe(true); // 10.0.0.1
		expect(isPrivateOrLoopbackIp("::ffff:192.168.1.50")).toBe(true);
		expect(isPrivateOrLoopbackIp("::ffff:169.254.169.254")).toBe(true);
	});

	it("blocks fully-expanded IPv4-mapped loopback (0:0:0:0:0:ffff:7f00:1)", () => {
		expect(isPrivateOrLoopbackIp("0:0:0:0:0:ffff:7f00:1")).toBe(true);
	});

	it("blocks the unspecified addresses 0.0.0.0 and ::", () => {
		expect(isPrivateOrLoopbackIp("0.0.0.0")).toBe(true);
		expect(isPrivateOrLoopbackIp("::")).toBe(true);
		expect(isPrivateOrLoopbackIp("0:0:0:0:0:0:0:0")).toBe(true);
	});

	it("blocks NAT64-wrapped private/loopback (64:ff9b::/96 with embedded private v4)", () => {
		expect(isPrivateOrLoopbackIp("64:ff9b::7f00:1")).toBe(true); // 127.0.0.1
		expect(isPrivateOrLoopbackIp("64:ff9b::127.0.0.1")).toBe(true);
		expect(isPrivateOrLoopbackIp("64:ff9b::a9fe:a9fe")).toBe(true); // 169.254.169.254
	});

	it("still allows public addresses, including public IPv4-mapped and NAT64 forms", () => {
		expect(isPrivateOrLoopbackIp("8.8.8.8")).toBe(false);
		expect(isPrivateOrLoopbackIp("::ffff:8.8.8.8")).toBe(false);
		expect(isPrivateOrLoopbackIp("::ffff:808:808")).toBe(false); // 8.8.8.8
		expect(isPrivateOrLoopbackIp("64:ff9b::808:808")).toBe(false);
		expect(isPrivateOrLoopbackIp("2606:4700:4700::1111")).toBe(false);
	});

	it("keeps blocking the existing IPv6 private ranges", () => {
		expect(isPrivateOrLoopbackIp("::1")).toBe(true);
		expect(isPrivateOrLoopbackIp("fe80::1")).toBe(true);
		expect(isPrivateOrLoopbackIp("fd00::1")).toBe(true);
	});
});
