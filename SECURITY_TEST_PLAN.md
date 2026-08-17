# HealBridge Security Test Plan

T01 A01: cross-user prescription -> 403 + UNAUTHORIZED_ACCESS.
T02 A01: patient -> admin endpoint -> 403.
T03 A02: unexpected error -> generic 500, no stack trace.
T04 A03: inspect requirements/package versions -> pinned direct dependencies.
T05 A04: inspect DB -> Argon2id hash, no plaintext password.
T06 A05: login injection `' OR '1'='1` -> bypass fails.
T07 A06: unauthorized action -> denied.
T08 A07: repeated login failures -> 429 rate limit.
T09 A08: invalid extension/signature/MIME -> 400.
T10 A09: unauthorized access -> audit event.
T11 A10: invalid prescription ID -> controlled 404.
T12 A10: malformed upload -> controlled 400.

Capture screenshots: login, dashboard, upload rejection, verified result, uncertainty result, 403 authorization defense, Security Center, audit log.

## Phase 2 File & Input Tests

| ID | Attack/input | Expected |
|---|---|---|
| T03 | Executable renamed to PDF | Reject signature mismatch |
| T04 | Correct extension + wrong MIME | Reject |
| T05 | Malformed PDF with PDF header | Reject parser validation |
| T06 | `.exe` upload | Reject extension |
| T07 | Upload larger than 5 MB | Reject with 413 |
| T08 | `../../secret.pdf` filename | Normalize basename; never use as storage path |
| T09 | Filename containing control characters | Remove control characters |
| T10 | SQLi-style search string | No query manipulation or authorization bypass |
