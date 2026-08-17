# HealBridge — Phase 3 Complete: OWASP & Backend Security

Phase 3 hardens the backend-wide security controls without changing the core prescription workflow.

## Implemented controls

1. **Trusted Host protection** — FastAPI `TrustedHostMiddleware` restricts accepted Host headers to configured development hosts.
2. **Restrictive CORS** — explicit frontend origins only; credentials are disabled because authentication uses an Authorization bearer token rather than cookies.
3. **Defense-in-depth cross-origin protection** — unsafe browser requests carrying an Origin header are rejected unless the origin is explicitly configured. This supplements the bearer-token model; classic cookie CSRF is not applicable because browsers do not automatically attach the bearer token.
4. **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`, CSP, `Referrer-Policy`, `Permissions-Policy`, CORP and COOP are returned on API responses.
5. **Optional HSTS** — disabled by default for local HTTP development; can be enabled behind HTTPS using `enable_hsts=true`.
6. **Safe validation errors** — Pydantic validation failures return a controlled 422 response without a server traceback.
7. **Safe unexpected errors** — unhandled server exceptions return a generic 500 message rather than internal stack traces.
8. **Request correlation** — every response receives an `X-Request-ID` for troubleshooting without exposing internal paths.
9. **Rate-limit response hardening** — 429 responses include `Retry-After`.
10. **Authentication timing hardening** — login performs password verification against a dummy hash when the account does not exist, reducing timing-based account enumeration.
11. **Revoked-session cleanup** — expired JWT revocation records are removed opportunistically to prevent unbounded growth.
12. **Pinned dependencies** — security-sensitive dependencies remain pinned in `requirements.txt`.

## OWASP mapping

| Control | Primary OWASP area |
|---|---|
| Trusted hosts / CORS / security headers | A02 Security Misconfiguration |
| Cross-origin request defense | A01 / A04 |
| Safe validation and error handling | A10 Mishandling of Exceptional Conditions |
| Rate limiting | A07 Identification and Authentication Failures |
| Dummy-hash login verification | A07 Identification and Authentication Failures |
| Session revocation cleanup | A07 / A09 |
| Pinned dependencies | A03 Software Supply Chain Failures |

## Important CSRF note

HealBridge uses a bearer token in the `Authorization` header. Browsers do not automatically attach this header cross-site, so the classic cookie-based CSRF attack model does not apply to the authentication mechanism. Phase 3 additionally checks the `Origin` header on unsafe methods as defense-in-depth. If the project is later changed to cookie-based authentication, a synchronizer token or equivalent CSRF mechanism must be introduced.

## Verification

`backend/test_phase3.py` contains static security configuration checks. The checks passed during packaging. Runtime verification on the student's Windows environment is still required for final evidence.
