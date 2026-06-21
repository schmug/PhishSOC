// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

export interface Env extends Cloudflare.Env {
	POLICY_AUD: string;
	TEAM_DOMAIN: string;
	// WebAuthn step-up (issue #376) is configured entirely through bindings
	// declared in wrangler.jsonc, so their types come from the generated
	// `Cloudflare.Env` (re-declaring a wrangler var here would widen the
	// generated literal type and break `extends Cloudflare.Env`):
	//   - RP_ID / RP_ORIGIN  — wrangler vars; the Relying Party id + expected
	//     origin, validated against the request origin on every verify.
	//   - WEBAUTHN_DB        — D1 binding; credential + one-shot challenge store
	//     (schema in migrations/webauthn).
	/**
	 * Optional CrowdSec CTI API key. When unset, deep-scan's CTI enrichment
	 * stage no-ops — deploys without a key still work; they just don't get
	 * the enrichment signal. Set with `wrangler secret put CROWDSEC_CTI_API_KEY`.
	 */
	CROWDSEC_CTI_API_KEY?: string;
	/**
	 * Audience tag for the step-up CF Access application scoped to
	 * `/api/v1/confirm`. Set with `wrangler secret put STEP_UP_AUD`.
	 * When absent, the confirm endpoint returns 503.
	 */
	STEP_UP_AUD?: string;
	/**
	 * HS256 signing secret for one-shot confirmation tokens.
	 * Set with `wrangler secret put CONFIRMATION_TOKEN_SECRET`.
	 * When absent, the confirm endpoint returns 503.
	 */
	CONFIRMATION_TOKEN_SECRET?: string;
	/**
	 * HMAC-SHA256 shared secret for authenticating yaramail sidecar callbacks.
	 * Set with `wrangler secret put YARAMAIL_CALLBACK_SECRET`.
	 * When absent, the yaramail callback route returns 503.
	 */
	YARAMAIL_CALLBACK_SECRET?: string;
	/**
	 * Comma-separated hostname allowlist for the community-hub URL
	 * (GHSA-jfj6-w954-96vg f29). A `HUB_SECRET_*` API key is only resolved
	 * and sent when `intel.hub.url` is https AND its hostname is on this
	 * list. Unset/empty → hub credentials are never released, so operators
	 * MUST set this (e.g. `hub.example.com`) to use a hub secret. Pinning
	 * the destination in env (not settings) is the point: settings are
	 * teammate-editable, env vars are operator-only.
	 */
	HUB_ALLOWED_HOSTS?: string;
	/**
	 * Comma-separated hostname allowlist for credential-bearing intel-feed
	 * fetches (GHSA-jfj6-w954-96vg f27). A `FEED_SECRET_*` Authorization
	 * header is only attached when the feed URL is https AND its hostname
	 * is on this list or belongs to a built-in `DEFAULT_FEEDS` entry.
	 * Off-allowlist feeds still fetch — they just never carry the secret.
	 */
	FEED_ALLOWED_HOSTS?: string;
}
