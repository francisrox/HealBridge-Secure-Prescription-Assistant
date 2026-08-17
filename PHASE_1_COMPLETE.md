# HealBridge Phase 1 — Authentication & Access Security

## Completed controls

- Registration with server-side validation and password hashing (Argon2id via pwdlib).
- Strong password policy: minimum 10 characters plus uppercase, lowercase, and numeric character.
- Login with generic invalid-credential response.
- Login rate limit: 8 requests/minute per client address.
- Protected API routes using signed, expiring JWT bearer tokens.
- JWT `jti` values and server-side revocation table.
- Logout now revokes the current JWT; replaying that token returns HTTP 401.
- Role-based authorization for admin endpoints.
- Patient prescription ownership checks on view/download/delete.
- Cross-user access attempts generate `UNAUTHORIZED_ACCESS` audit events and return HTTP 403.
- Invalid/expired/forged tokens return HTTP 401.
- No public role-selection field exists during registration; new accounts default to `PATIENT`.
- Admin test endpoint is protected by the same server-side role check.

## Regression test

From `healbridge/backend` after installing `requirements.txt`:

```powershell
python test_phase1.py
```

The test uses a temporary SQLite database and does not modify the normal project database.

## Phase 1 test mapping

| Test | Expected | Status |
|---|---|---|
| Unauthenticated protected route | 401 | PASS in regression test |
| T01 cross-user prescription | 403 + audit | PASS in regression test |
| T02 patient -> admin endpoint | 403 + audit | PASS in regression test |
| Invalid/forged token | 401 | PASS in regression test |
| Logout token replay | 401 | PASS in regression test |
| Weak password | 422 | PASS in regression test |
| SQLi-like login input | 401/422, no bypass | PASS in regression test |
| Admin role | 200 on protected admin endpoint | PASS in regression test |

## OWASP mapping

- A01 Broken Access Control: RBAC + ownership checks + deny-by-default protected routes.
- A04 Cryptographic Failures: Argon2id password hashing + signed expiring JWTs + token revocation.
- A07 Authentication Failures: password policy, generic login errors, rate limiting, expiry, revocation.
- A09 Logging/Monitoring: unauthorized access and authentication/security events are audited.

## Important limitation

The regression test is automated, but the final assignment evidence should still include screenshots from the running application/API for the required demonstration cases.
