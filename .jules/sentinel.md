## 2026-05-21 - [Added global security headers]
**Vulnerability:** The application was missing basic security headers globally across the entire API and web interface, making it susceptible to MIME sniffing and clickjacking, and lacking strict HSTS enforcement.
**Learning:** Hono does not add security headers out-of-the-box in its routing, even if it runs securely on Cloudflare. We need to explicitly attach these headers in a global middleware (`app.use('*', ...)`).
**Prevention:** Whenever provisioning a new entrypoint or Hono application, ensure `c.header` or `secureHeaders()` is implemented immediately.
## 2026-05-24 - [Enforce Dynamic Secret Prefix]
**Vulnerability:** The threat intel hub allows configuring an inbound peer via an API endpoint that takes an `api_key_secret_name` parameter. This parameter dynamically accesses an environment variable to retrieve a secret. Without restriction, an operator could inadvertently or maliciously exfiltrate unrelated system secrets (like `HUB_ADMIN_KEY` or AWS keys) by sending requests to a malicious upstream server they control.
**Learning:** Dynamic access to environment variables based on user input or API parameters represents a Confused Deputy / Secret Exfiltration vulnerability. Validating these inputs strictly, especially enforcing mandatory prefixes (like `PEER_SECRET_`), restricts access purely to intended credentials and ensures safe behavior.
**Prevention:** Always validate dynamic secret names against an explicit prefix or denylist before accessing them from the environment or secret manager.
