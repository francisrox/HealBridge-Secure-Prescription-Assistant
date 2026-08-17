# Phase 3 Changelog

- Added trusted-host validation.
- Tightened CORS configuration and added 127.0.0.1 development origin.
- Added defense-in-depth Origin checking for unsafe methods.
- Added security response headers: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, CORP, COOP.
- Added optional HSTS configuration for HTTPS deployments.
- Added safe 422 validation response handling.
- Added generic 500 response handling and request IDs.
- Added Retry-After to rate-limit responses.
- Added dummy password hash verification for unknown login accounts.
- Added cleanup of expired revoked-token records.
- Added `backend/test_phase3.py`.
- Updated `.env.example` with Phase 3 configuration.
