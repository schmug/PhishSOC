// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { beforeEach, describe, expect, it } from "vitest";
import { normalizeInbound } from "../../workers/providers/cf-routing";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import type { Env } from "../../workers/types";

const MSG = [
	"Received: from mx.origin.test by cf.example.net for <ghost@example.com>; Mon, 6 Jul 2026 10:00:00 +0000",
	"From: sender@origin.test",
	"To: ghost@example.com",
	"Subject: hi",
	"",
	"body",
	"",
].join("\r\n");

function event(to: string) {
	const bytes = new TextEncoder().encode(MSG);
	return {
		raw: new Response(bytes).body as ReadableStream,
		rawSize: bytes.length,
		to,
		from: "sender@origin.test",
	};
}

/** BUCKET fake: no registered mailboxes; example.com has relay enabled. */
function fakeEnv(domainSettings: Record<string, unknown>): Env {
	return {
		EMAIL_ADDRESSES: undefined,
		DOMAINS: "example.com",
		BUCKET: {
			head: async () => null, // no mailbox JSON anywhere
			get: async (key: string) =>
				key === "domains/example.com.json"
					? { etag: "e1", json: async () => domainSettings }
					: null,
		},
	} as unknown as Env;
}

describe("normalizeInbound gateway routing", () => {
	beforeEach(() => clearDomainSettingsCache());

	it("unregistered recipient on a relay-enabled domain → GatewayInbound", async () => {
		const env = fakeEnv({
			relay: { enabled: true, target: { host: "smtp-relay.gmail.com" } },
		});
		const normalized = await normalizeInbound(event("ghost@example.com"), env);
		expect(normalized?.kind).toBe("gateway");
		if (normalized?.kind === "gateway") {
			expect(normalized.recipient).toBe("ghost@example.com");
			expect(normalized.domain).toBe("example.com");
			expect(normalized.envelopeFrom).toBe("sender@origin.test");
		}
	});

	it("relay disabled → falls through to catch-all/drop as before", async () => {
		const env = fakeEnv({ relay: { enabled: false, target: { host: "h" } } });
		const normalized = await normalizeInbound(event("ghost@example.com"), env);
		expect(normalized).toBeNull(); // no catchall_intel configured either
	});

	it("gateway wins precedence over catch-all when both are enabled", async () => {
		const env = fakeEnv({
			relay: { enabled: true, target: { host: "smtp-relay.gmail.com" } },
			catchall_intel: { enabled: true },
		});
		const normalized = await normalizeInbound(event("ghost@example.com"), env);
		expect(normalized?.kind).toBe("gateway");
	});
});
