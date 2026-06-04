## 2026-05-21 - [Added global security headers]
**Vulnerability:** The application was missing basic security headers globally across the entire API and web interface, making it susceptible to MIME sniffing and clickjacking, and lacking strict HSTS enforcement.
**Learning:** Hono does not add security headers out-of-the-box in its routing, even if it runs securely on Cloudflare. We need to explicitly attach these headers in a global middleware (`app.use('*', ...)`).
**Prevention:** Whenever provisioning a new entrypoint or Hono application, ensure `c.header` or `secureHeaders()` is implemented immediately.
## 2026-05-24 - [Enforce Dynamic Secret Prefix]
**Vulnerability:** The threat intel hub allows configuring an inbound peer via an API endpoint that takes an `api_key_secret_name` parameter. This parameter dynamically accesses an environment variable to retrieve a secret. Without restriction, an operator could inadvertently or maliciously exfiltrate unrelated system secrets (like `HUB_ADMIN_KEY` or AWS keys) by sending requests to a malicious upstream server they control.
**Learning:** Dynamic access to environment variables based on user input or API parameters represents a Confused Deputy / Secret Exfiltration vulnerability. Validating these inputs strictly, especially enforcing mandatory prefixes (like `PEER_SECRET_`), restricts access purely to intended credentials and ensures safe behavior.
**Prevention:** Always validate dynamic secret names against an explicit prefix or denylist before accessing them from the environment or secret manager.

## 2024-05-30 - Add missing security headers to hub application
**Vulnerability:** Missing security headers (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Strict-Transport-Security`) in the `hub/src/index.ts` Hono application initialization.
**Learning:** Hono applications in this codebase do not add security headers out-of-the-box. When provisioning a new application or sub-application, they must be added manually. The root application `workers/app.ts` had them, but the `hub` application did not.
**Prevention:** Whenever provisioning a new entrypoint or Hono application, ensure `c.header` or `secureHeaders()` is implemented immediately.

## 2026-06-04 - [Enforce FEED_SECRET_ and HUB_SECRET_ Prefixes]
**Vulnerability:** Similar to the previous PEER_SECRET_ exfiltration issue, `workers/lib/hub-config.ts` and `workers/intel/feeds.ts` dynamically loaded secrets using user-controlled parameters (`api_key_secret_name` and `auth_secret`) without verifying prefix patterns. This would allow a confused deputy / secret exfiltration attack. A specific attack vector allowed mailbox members with settings-write access to exfiltrate worker environment variables to an attacker-controlled url by setting the `api_key_secret_name` field to the target secret and hitting `/report-phish`.
**Learning:** The dynamic secret access pattern was identified and fixed in the peer configuration but remained vulnerable in hub configs and feed configurations.
**Prevention:** Apply consistent prefix validation for all dynamic secret lookups (`HUB_SECRET_` and `FEED_SECRET_`) across the codebase before accessing the environment, and always enforce input validation at the schema layer (e.g. `shared/mailbox-settings.ts`) for defense-in-depth.
