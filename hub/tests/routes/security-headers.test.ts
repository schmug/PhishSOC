// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { describe, expect, it } from "vitest";
import { Hono } from "hono";
import { secureHeaders } from "hono/secure-headers";
import {
	SECURITY_HEADER_OPTIONS,
	EXPECTED_SECURITY_HEADERS,
} from "../../src/security-headers";

// Drift guard. `secureHeaders()` merges `{ ...DEFAULT_OPTIONS, ...customOptions }`,
// so a `hono` bump that adds a new defaulted-on header, or changes an existing
// default's value, would silently alter the hub Worker's production security posture.
// These tests pin the emitted set in BOTH directions so that fails CI instead.
function headersFor(path = "/") {
	const app = new Hono();
	app.use("*", secureHeaders(SECURITY_HEADER_OPTIONS));
	app.get("*", (c) => c.text("ok"));
	return app.request(path);
}

describe("hub Worker security headers", () => {
	it("emits every pinned header with its pinned value", async () => {
		const res = await headersFor();
		for (const [name, value] of Object.entries(EXPECTED_SECURITY_HEADERS)) {
			expect(res.headers.get(name), name).toBe(value);
		}
	});

	it("emits NO security header beyond the pinned set", async () => {
		const res = await headersFor();
		const seen = [...res.headers.keys()].filter(
			(h) =>
				h.startsWith("x-") ||
				h.startsWith("cross-origin-") ||
				h === "origin-agent-cluster" ||
				h === "referrer-policy" ||
				h === "strict-transport-security",
		);
		expect(seen.sort()).toEqual(Object.keys(EXPECTED_SECURITY_HEADERS).sort());
	});

	it("keeps Cross-Origin-Embedder-Policy off", async () => {
		// COEP would require every cross-origin subresource to opt in via
		// CORP/CORS. Turning it on is a deliberate change, not a Hono default.
		const res = await headersFor();
		expect(res.headers.get("cross-origin-embedder-policy")).toBeNull();
	});

	it("applies to the unauthenticated public feed route too", async () => {
		const res = await headersFor("/feeds/public/destroylist.txt");
		expect(res.headers.get("x-frame-options")).toBe("DENY");
	});
});
