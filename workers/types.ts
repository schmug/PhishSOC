// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

export interface Env extends Cloudflare.Env {
	POLICY_AUD: string;
	TEAM_DOMAIN: string;
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
}
