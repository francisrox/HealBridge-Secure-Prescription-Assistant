# HealBridge Security & Safety Test Report

## Test result format

| Test ID | Category | Action | Expected result | Actual result | Status | Screenshot |
|---|---|---|---|---|---|---|
| S01 | Authentication | Request protected endpoint without token | 401 | | | |
| S02 | Access control | User A requests User B record | 403 | | | |
| S03 | RBAC | Patient requests admin endpoint | 403 | | | |
| S04 | Session | Replay revoked token after logout | 401 | | | |
| S05 | Injection | SQLi-style login input | No bypass | | | |
| S06 | XSS | Submit script payload | Not executed | | | |
| S07 | Upload | Upload unsupported executable | Rejected | | | |
| S08 | Upload | Rename executable to .pdf | Rejected | | | |
| S09 | Rate limit | Repeated failed login | 429 | | | |
| S10 | Error handling | Send malformed request | Safe controlled response | | | |
| SAF01 | Safety | Clear fictional prescription | Verified | | | |
| SAF02 | Safety | Blurry/uncertain sample | Verification required | | | |
| SAF03 | Safety | Missing dosage | Verification required | | | |
| SAF04 | Safety | Ambiguous medicine | Verification required | | | |
| SAF05 | Safety | Incomplete prescription | Verification required | | | |
| SAF06 | Safety | Unexpected extraction | Verification required | | | |

## Evidence rule
For every security test, record the request/action, expected response, actual response and a screenshot or log reference. Do not mark a test as passed only because a corresponding code path exists.
