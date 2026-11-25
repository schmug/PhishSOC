import { describe, expect, it } from "vitest";
import {
	DEFAULT_MCP_MAX_BODY_CHARS,
	MCP_CONTENT_NOTICE,
	MCP_MAX_HEADER_CHARS,
	canDraftIn,
	draftToolsEnabled,
	mailboxDomain,
	mailboxInScope,
	parseMcpScope,
	toAgentEmail,
	toAgentList,
} from "../../workers/mcp/scope";

describe("parseMcpScope", () => {
	it("defaults to read-write, every domain, default body cap", () => {
		expect(parseMcpScope({})).toEqual({
			readOnly: false,
			allowedDomains: null,
			draftMailboxes: null,
			maxBodyChars: DEFAULT_MCP_MAX_BODY_CHARS,
		});
	});

	it("reads MCP_READ_ONLY truthy values only", () => {
		for (const v of ["true", "TRUE", "1", "yes", " on "]) {
			expect(parseMcpScope({ MCP_READ_ONLY: v }).readOnly).toBe(true);
		}
		for (const v of ["", "false", "0", "no", "off", "maybe"]) {
			expect(parseMcpScope({ MCP_READ_ONLY: v }).readOnly).toBe(false);
		}
	});

	it("parses MCP_ALLOWED_DOMAINS as a lower-cased list", () => {
		expect(
			parseMcpScope({ MCP_ALLOWED_DOMAINS: " Dungelo.com, @example.org ,," }).allowedDomains,
		).toEqual(["dungelo.com", "example.org"]);
	});

	it("treats an empty allowlist as unset", () => {
		expect(parseMcpScope({ MCP_ALLOWED_DOMAINS: " , " }).allowedDomains).toBeNull();
	});

	it("ignores an invalid MCP_MAX_BODY_CHARS", () => {
		expect(parseMcpScope({ MCP_MAX_BODY_CHARS: "500" }).maxBodyChars).toBe(500);
		expect(parseMcpScope({ MCP_MAX_BODY_CHARS: "0" }).maxBodyChars).toBe(DEFAULT_MCP_MAX_BODY_CHARS);
		expect(parseMcpScope({ MCP_MAX_BODY_CHARS: "lots" }).maxBodyChars).toBe(DEFAULT_MCP_MAX_BODY_CHARS);
	});
});

describe("mailboxInScope", () => {
	const scoped = parseMcpScope({ MCP_ALLOWED_DOMAINS: "dungelo.com" });

	it("allows everything when no allowlist is set", () => {
		expect(mailboxInScope(parseMcpScope({}), "anyone@anywhere.test")).toBe(true);
	});

	it("allows mailboxes on an allowed domain, any case", () => {
		expect(mailboxInScope(scoped, "hello@dungelo.com")).toBe(true);
		expect(mailboxInScope(scoped, "Hello@DUNGELO.COM")).toBe(true);
	});

	it("refuses other domains, subdomains and look-alikes", () => {
		expect(mailboxInScope(scoped, "me@cortech.online")).toBe(false);
		expect(mailboxInScope(scoped, "me@mail.dungelo.com")).toBe(false);
		expect(mailboxInScope(scoped, "me@dungelo.com.evil.test")).toBe(false);
		expect(mailboxInScope(scoped, "dungelo.com")).toBe(false);
		expect(mailboxInScope(scoped, "me@")).toBe(false);
	});

	it("uses the last @ for the domain", () => {
		expect(mailboxDomain("a@b@dungelo.com")).toBe("dungelo.com");
		expect(mailboxInScope(scoped, "a@dungelo.com@other.test")).toBe(false);
	});
});

describe("draft-only mode", () => {
	const draftOnly = parseMcpScope({
		MCP_READ_ONLY: "true",
		MCP_ALLOWED_DOMAINS: "dungelo.com",
		MCP_DRAFT_MAILBOXES: " Support@Dungelo.com , not-an-address, press@other.test",
	});

	it("parses MCP_DRAFT_MAILBOXES as lower-cased addresses", () => {
		expect(draftOnly.draftMailboxes).toEqual(["support@dungelo.com", "press@other.test"]);
		expect(parseMcpScope({ MCP_DRAFT_MAILBOXES: " , " }).draftMailboxes).toBeNull();
	});

	it("registers draft tools in read-only mode only when a draft list is set", () => {
		expect(draftToolsEnabled(parseMcpScope({}))).toBe(true);
		expect(draftToolsEnabled(parseMcpScope({ MCP_READ_ONLY: "true" }))).toBe(false);
		expect(draftToolsEnabled(draftOnly)).toBe(true);
	});

	it("drafts only in listed mailboxes", () => {
		expect(canDraftIn(draftOnly, "support@dungelo.com")).toBe(true);
		expect(canDraftIn(draftOnly, "SUPPORT@dungelo.com")).toBe(true);
		expect(canDraftIn(draftOnly, "hello@dungelo.com")).toBe(false);
	});

	it("still applies the domain allowlist to listed mailboxes", () => {
		expect(canDraftIn(draftOnly, "press@other.test")).toBe(false);
	});

	it("follows read-only mode when no draft list is set", () => {
		expect(canDraftIn(parseMcpScope({}), "anyone@anywhere.test")).toBe(true);
		expect(canDraftIn(parseMcpScope({ MCP_READ_ONLY: "1" }), "anyone@anywhere.test")).toBe(false);
	});

	it("limits drafts to the list outside read-only mode too", () => {
		const scoped = parseMcpScope({ MCP_DRAFT_MAILBOXES: "support@dungelo.com" });
		expect(canDraftIn(scoped, "support@dungelo.com")).toBe(true);
		expect(canDraftIn(scoped, "other@dungelo.com")).toBe(false);
	});
});

describe("toAgentEmail", () => {
	const scope = { maxBodyChars: 10 };

	it("drops stored HTML and keeps plain text", () => {
		const out = toAgentEmail(
			{
				id: "e1",
				subject: "hi",
				body: "<p>secret html</p>",
				body_html: "<p>secret html</p>",
				body_text: "short",
			},
			scope,
		);
		expect(out).not.toHaveProperty("body");
		expect(out).not.toHaveProperty("body_html");
		expect(out.body_text).toBe("short");
		expect(out).not.toHaveProperty("body_truncated");
		expect(out.content_notice).toBe(MCP_CONTENT_NOTICE);
		expect((out as { id: string }).id).toBe("e1");
	});

	it("caps the plain-text body and says so", () => {
		const out = toAgentEmail({ body_text: "0123456789abcdef" }, scope);
		expect(out.body_text).toBe("0123456789");
		expect(out.body_truncated).toBe(true);
	});

	it("caps raw headers", () => {
		const long = "x".repeat(MCP_MAX_HEADER_CHARS + 5);
		const out = toAgentEmail({ body_text: "", raw_headers: long }, scope);
		expect(out.raw_headers).toHaveLength(MCP_MAX_HEADER_CHARS);
		expect(out.raw_headers_truncated).toBe(true);
	});

	it("omits raw headers when there are none", () => {
		const out = toAgentEmail({ body_text: "", raw_headers: null }, scope);
		expect(out).not.toHaveProperty("raw_headers");
	});
});

describe("toAgentList", () => {
	it("turns HTML snippets into plain text", () => {
		const out = toAgentList([
			{ id: "a", snippet: "<p>Hello <b>there</b></p>" },
			{ id: "b", snippet: null },
		]) as Array<{ id: string; snippet: string | null }>;
		expect(out[0].snippet).not.toContain("<");
		expect(out[0].snippet).toContain("Hello");
		expect(out[1].snippet).toBeNull();
	});

	it("passes non-arrays through", () => {
		expect(toAgentList({ error: "x" })).toEqual({ error: "x" });
	});
});
