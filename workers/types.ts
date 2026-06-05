// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

// Augment the global Env (declared in worker-configuration.d.ts as
// `interface Env extends Cloudflare.Env {}`) with app-specific fields.
// We do NOT declare a module-level `interface Env extends Cloudflare.Env`
// because that forms the circular chain:
//   types.ts → Cloudflare.Env → import("./workers/app").CatchallIntelDO
//            → workers/app.ts → workers/types.ts
// which causes TypeScript to resolve CatchallIntelDO as `undefined` on a
// cold build (TS2430/TS2344/TS2300). Using `declare global` augments the
// ambient Env without touching Cloudflare.Env, breaking the cycle.
declare global {
	interface Env {
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
}

// Capture the global Env as a local alias so it can be exported.
// `declare global` augmentations are not local declarations and cannot be
// exported directly (TS2661), but a local type alias is exportable.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type _Env = Env;
export type { _Env as Env };
