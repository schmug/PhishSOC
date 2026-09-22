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
	//   - WEBAUTHN_AAGUID_ALLOWLIST — wrangler var (#506); optional
	//     comma-separated authenticator AAGUID allowlist. Non-empty ⇒
	//     register/verify rejects any authenticator whose AAGUID is not on the
	//     list; empty/unset ⇒ allow all (no change from #376). Declared in
	//     wrangler.jsonc so its type comes from the generated `Cloudflare.Env`.
	/**
	 * Optional CrowdSec CTI API key. When unset, deep-scan's CTI enrichment
	 * stage no-ops — deploys without a key still work; they just don't get
	 * the enrichment signal. Set with `wrangler secret put CROWDSEC_CTI_API_KEY`.
	 */
	CROWDSEC_CTI_API_KEY?: string;
	/**
	 * HS256 signing secret for one-shot confirmation tokens.
	 * Set with `wrangler secret put CONFIRMATION_TOKEN_SECRET`.
	 * When absent, the confirm endpoint returns 503.
	 */
	CONFIRMATION_TOKEN_SECRET?: string;
	/**
	 * PKCS8 PEM private key for ARC sealing on gateway relay (issue #32).
	 * Set with `wrangler secret put ARC_SEAL_PRIVATE_KEY`. Absent → relay
	 * proceeds unsealed.
	 */
	ARC_SEAL_PRIVATE_KEY?: string;
	/**
	 * HMAC-SHA256 shared secret for authenticating yaramail sidecar callbacks.
	 * Set with `wrangler secret put YARAMAIL_CALLBACK_SECRET`.
	 * When absent, the yaramail callback route returns 503.
	 */
	YARAMAIL_CALLBACK_SECRET?: string;
	/**
	 * Optional operator webhook for out-of-band security alerts (issue #376).
	 * When set, a first-passkey (TOFU) enrollment in `register/verify` POSTs the
	 * `webauthn.first_key_registered` audit payload here so the highest-risk
	 * step-up window is actively detectable, not just logged. Dispatch is
	 * fire-and-forget — a failed send never blocks or fails enrollment. When
	 * unset, the dispatch no-ops (the `console.log` audit line still fires).
	 * Set with `wrangler secret put SECURITY_ALERT_WEBHOOK_URL` (kept out of
	 * `wrangler.jsonc` vars so it doesn't widen the generated `Cloudflare.Env`).
	 */
	SECURITY_ALERT_WEBHOOK_URL?: string;
	/**
	 * Optional operator webhook for ops-visibility "new mail" notifications
	 * (issue #563). When set, every non-honeypot, non-report-ingested inbound
	 * email POSTs a `{"text": "..."}` chat message here — the shape Google
	 * Chat and Slack incoming webhooks both accept — with sender, subject,
	 * landing folder, verdict action, and a deep link into the app. This is a
	 * separate, higher-volume channel from `SECURITY_ALERT_WEBHOOK_URL` (that
	 * one is a low-volume security pager; see #511's alert-fatigue note).
	 * Dispatch is fire-and-forget — a failed send never blocks or fails email
	 * receipt. When unset, the dispatch no-ops. Set with
	 * `wrangler secret put NEW_EMAIL_WEBHOOK_URL` (kept out of `wrangler.jsonc`
	 * vars — the URL embeds credentials — so it doesn't widen the generated
	 * `Cloudflare.Env`).
	 */
	NEW_EMAIL_WEBHOOK_URL?: string;
	/**
	 * Optional HMAC-SHA256 signing secret for outbound new-email webhook
	 * requests (issue #700). When set, every `dispatchNewEmailNotification`
	 * request carries an `x-phishsoc-signature: t=<unix-seconds>,v1=<hex>`
	 * header computed over `${timestamp}.${rawBody}`, letting a receiver
	 * verify authenticity and reject stale/replayed deliveries. Applies to
	 * every destination — the global `NEW_EMAIL_WEBHOOK_URL` fallback and
	 * every per-tier `NEW_EMAIL_WEBHOOK_*` secret alike — since signing wraps
	 * the outgoing request rather than any one destination. When unset, the
	 * request is sent exactly as before (no signature header) — fully
	 * backward compatible. Set with
	 * `wrangler secret put NEW_EMAIL_WEBHOOK_SIGNING_SECRET`.
	 */
	NEW_EMAIL_WEBHOOK_SIGNING_SECRET?: string;
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
	/**
	 * Comma-separated operator allowlist of admin emails for the WebAuthn
	 * step-up recovery endpoint (#507). Only an INTERACTIVE Access identity
	 * (email claim — never a service token / MCP) whose email is on this list
	 * may clear another user's lost step-up credentials so they can re-enroll.
	 * Unset/empty → no admin recovery is possible (fail closed), so operators
	 * MUST set this (e.g. `op@example.com`) to enable recovery. Kept in env,
	 * not teammate-editable settings: admin authority is operator-only. Set with
	 * `wrangler secret put WEBAUTHN_ADMIN_EMAILS` (or as a wrangler var).
	 */
	WEBAUTHN_ADMIN_EMAILS?: string;
}
