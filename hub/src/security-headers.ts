// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import type { secureHeaders } from "hono/secure-headers";

type SecureHeadersOptions = NonNullable<Parameters<typeof secureHeaders>[0]>;

/**
 * Pinned `secureHeaders()` configuration for the hub Worker entrypoint.
 *
 * EVERY option is set explicitly — including the ones whose value matches
 * Hono's current default. Nothing is inherited from `DEFAULT_OPTIONS`.
 *
 * Why: `secureHeaders()` merges `{ ...DEFAULT_OPTIONS, ...customOptions }`, so
 * any option left out silently takes whatever the installed Hono version
 * decides. A `hono` bump could then change the production security posture of
 * this Worker with no diff in this repo. Pinning moves that decision into
 * source control; `hub/tests/routes/security-headers.test.ts` asserts the exact
 * emitted header set so a Hono version that ADDS a defaulted-on header fails
 * CI instead of shipping silently.
 *
 * Keep this in sync with `workers/lib/security-headers.ts` — the hub is a
 * separate package and cannot import from there.
 */
export const SECURITY_HEADER_OPTIONS = {
	// COEP stays off: it would require every cross-origin subresource to opt in
	// via CORP/CORS, which the hub's responses do not.
	crossOriginEmbedderPolicy: false,
	crossOriginResourcePolicy: "same-origin",
	crossOriginOpenerPolicy: "same-origin",
	originAgentCluster: "?1",
	referrerPolicy: "strict-origin-when-cross-origin",
	strictTransportSecurity: "max-age=31536000; includeSubDomains",
	xContentTypeOptions: "nosniff",
	xDnsPrefetchControl: "off",
	xDownloadOptions: "noopen",
	xFrameOptions: "DENY",
	xPermittedCrossDomainPolicies: "none",
	xXssProtection: "0",
	removePoweredBy: true,
} satisfies SecureHeadersOptions;

/**
 * The exact header set `SECURITY_HEADER_OPTIONS` must produce. The test asserts
 * equality in BOTH directions, so a Hono upgrade that adds a new defaulted-on
 * header — or drops one of these — fails CI.
 */
export const EXPECTED_SECURITY_HEADERS: Record<string, string> = {
	"cross-origin-resource-policy": "same-origin",
	"cross-origin-opener-policy": "same-origin",
	"origin-agent-cluster": "?1",
	"referrer-policy": "strict-origin-when-cross-origin",
	"strict-transport-security": "max-age=31536000; includeSubDomains",
	"x-content-type-options": "nosniff",
	"x-dns-prefetch-control": "off",
	"x-download-options": "noopen",
	"x-frame-options": "DENY",
	"x-permitted-cross-domain-policies": "none",
	"x-xss-protection": "0",
};
