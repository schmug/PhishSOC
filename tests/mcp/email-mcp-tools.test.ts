// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// Smoke test for the EmailMCP tool surface. Registers the real tool set on
// the real McpServer and drives it through an in-memory MCP client, so a
// zod / @modelcontextprotocol/sdk / agents upgrade that breaks tool
// registration, JSON-schema generation, or argument parsing fails here
// instead of in production. The `agents/mcp` base class (a Durable Object)
// is stubbed: only `env` and `server` matter for tool registration.
import { describe, expect, it, vi } from "vitest";

vi.mock("agents/mcp", () => ({
	McpAgent: class {
		env: unknown;
		constructor(env: unknown) {
			this.env = env;
		}
	},
}));

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { EmailMCP } from "../../workers/mcp/index";

const EXPECTED_TOOLS = [
	"create_draft",
	"delete_email",
	"draft_reply",
	"get_email",
	"get_thread",
	"list_emails",
	"list_mailboxes",
	"mark_email_read",
	"move_email",
	"search_emails",
	"send_email",
	"send_reply",
	"update_draft",
];

async function connect() {
	const bucket = {
		head: vi.fn(async () => null),
		get: vi.fn(async () => null),
		list: vi.fn(async () => ({ objects: [], truncated: false, delimitedPrefixes: [] })),
	};
	const mcp = new (EmailMCP as unknown as new (env: unknown) => EmailMCP)({ BUCKET: bucket });
	await mcp.init();
	const [clientT, serverT] = InMemoryTransport.createLinkedPair();
	await mcp.server.connect(serverT);
	const client = new Client({ name: "test", version: "0.0.0" });
	await client.connect(clientT);
	return { client, bucket };
}

describe("EmailMCP tool surface", () => {
	it("registers every tool with a JSON-schema input", async () => {
		const { client } = await connect();
		const { tools } = await client.listTools();
		expect(tools.map((t) => t.name).sort()).toEqual(EXPECTED_TOOLS);
		for (const t of tools) expect(t.inputSchema.type).toBe("object");

		const listEmails = tools.find((t) => t.name === "list_emails")!;
		const props = listEmails.inputSchema.properties as Record<string, { type?: string; default?: unknown }>;
		expect(Object.keys(props).sort()).toEqual(["folder", "limit", "mailboxId", "page"]);
		expect(props.limit.type).toBe("number");
		expect(props.limit.default).toBe(20);
		expect(listEmails.inputSchema.required).toContain("mailboxId");
	});

	it("parses arguments and reaches the handler", async () => {
		const { client, bucket } = await connect();
		const res = await client.callTool({
			name: "list_emails",
			arguments: { mailboxId: "nobody@example.com" },
		});
		expect(res.isError).toBe(true);
		expect(JSON.stringify(res.content)).toContain("not found");
		expect(bucket.head).toHaveBeenCalledWith("mailboxes/nobody@example.com.json");
	});

	it("rejects arguments that fail the zod schema before the handler runs", async () => {
		const { client, bucket } = await connect();
		const res = await client
			.callTool({ name: "list_emails", arguments: { mailboxId: "a@example.com", limit: "lots" } })
			.catch((e: unknown) => ({ isError: true, content: String(e) }));
		expect(res.isError).toBe(true);
		expect(bucket.head).not.toHaveBeenCalled();
	});
});
