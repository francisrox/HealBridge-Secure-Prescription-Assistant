# HealBridge OWASP Top 10 Defense Matrix

> This matrix describes the defenses implemented in the academic prototype. A control being implemented does not by itself mean every security test has passed; use the test report for evidence.

| ID | Area | HealBridge control | Evidence to capture |
|---|---|---|---|
| A01 | Broken Access Control | RBAC + server-side prescription ownership checks | User A attempting User B record |
| A02 | Security Misconfiguration | Restricted CORS, security headers, controlled errors | Response headers / safe error |
| A03 | Software Supply Chain Failures | Minimal pinned dependencies | requirements.txt / package.json |
| A04 | Cryptographic Failures | Argon2id password hashing, signed expiring tokens, SHA-256 file fingerprint | Auth/database/file record |
| A05 | Injection | SQLAlchemy queries + validation | SQL injection test |
| A06 | Insecure Design | Least privilege, deny-by-default, verification workflow | Design + uncertainty test |
| A07 | Authentication Failures | Password policy, protected routes, expiry, revocation, rate limits | Login/session tests |
| A08 | Software/Data Integrity Failures | Magic-byte validation, safe filenames, file hashing | Upload tests |
| A09 | Logging & Alerting Failures | Authentication, upload, access and attack audit events | Security Center / exported audit CSV |
| A10 | Mishandling Exceptional Conditions | Controlled 4xx/429/500 responses | Malformed request tests |

## Terminology note
The category labels above follow the naming used by the project implementation. In the final academic report, use the exact OWASP edition/version required by your instructor and do not silently substitute a different taxonomy.

## Phase 2 hardening update

- **A03 Injection:** database access remains parameterized; search input is treated as data and Phase 2 adds input-security regression coverage.
- **A08 Software/Data Integrity Failures:** extension, MIME, magic-byte and parser-level validation; SHA-256; generated storage names; safe filename normalization.
- **A10 Mishandling of Exceptional Conditions:** controlled 400/413/429/500 responses; malformed PDF/image uploads are rejected without exposing internal traces.
- **A04 Insecure Design:** incremental reads, PDF page limits and image pixel limits reduce resource-abuse risk.
- **A05 Security Misconfiguration:** private generated storage names and strict upload allowlisting reduce accidental exposure.
