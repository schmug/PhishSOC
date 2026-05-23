## 2026-05-21 - [Added global security headers]
**Vulnerability:** The application was missing basic security headers globally across the entire API and web interface, making it susceptible to MIME sniffing and clickjacking, and lacking strict HSTS enforcement.
**Learning:** Hono does not add security headers out-of-the-box in its routing, even if it runs securely on Cloudflare. We need to explicitly attach these headers in a global middleware (`app.use('*', ...)`).
**Prevention:** Whenever provisioning a new entrypoint or Hono application, ensure `c.header` or `secureHeaders()` is implemented immediately.
