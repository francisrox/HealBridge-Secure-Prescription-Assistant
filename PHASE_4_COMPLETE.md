# HealBridge Phase 4 — Security & Safety Testing

## Status
Phase 4 completes the project's security/safety regression framework. It converts the controls implemented in Phases 1–3 into repeatable tests and verifies the application's uncertainty workflow. The automated suite uses an isolated temporary SQLite database and does not modify the normal project database.

## Test suite
Run from the project root after installing `backend/requirements.txt`:

```powershell
python backend\test_phase4.py
```

The suite covers:

- unauthenticated access (`401`)
- cross-user IDOR (`403`)
- patient-to-admin RBAC (`403`)
- forged token rejection (`401`)
- SQL-injection-style authentication input
- XSS-style search input handling
- hostile `Origin` rejection (`403`)
- security response headers
- unsupported executable upload (`400`)
- renamed executable/signature mismatch (`400`)
- malformed PDF rejection (`400`)
- oversized upload rejection (`413`)
- invalid resource identifier handling (`422`)
- logout/session revocation and token replay (`401`)
- uncertainty/verification-required workflow
- audit evidence for unauthorized access and upload
- frontend raw-HTML injection invariant (`dangerouslySetInnerHTML` absent)

## Evidence matrix

| ID | Scenario | Expected | Evidence source |
|---|---|---:|---|
| P4-01 | Unauthenticated API request | 401 | automated test |
| P4-07 | User A reads User B record | 403 | automated test + audit event |
| P4-08 | Patient opens admin endpoint | 403 | automated test |
| P4-09 | Forged token | 401 | automated test |
| P4-10 | SQLi-style login | no bypass | automated test |
| P4-11 | XSS-style search | handled as data | automated test + frontend invariant |
| P4-12 | Hostile Origin | 403 | automated test |
| P4-13 | Security headers | present | automated test |
| P4-14 | `.exe` upload | 400 | automated test |
| P4-15 | `.exe` renamed `.pdf` | 400 | automated test |
| P4-16 | Malformed PDF | 400 | automated test |
| P4-17 | >5 MB upload | 413 | automated test |
| P4-19/P4-20 | Logout + token replay | 200 then 401 | automated test |
| P4-22 | Uncertain sample | verification required | automated test |
| P4-23/P4-24 | Audit events | recorded | automated test |

## Safety test coverage

The project supports a controlled uncertainty workflow. The final test evidence should include:

1. clear sample → verified when all required fields are confidently available;
2. blurry/uncertain filename case → verification required;
3. missing dosage → verification required;
4. ambiguous medicine → verification required;
5. incomplete prescription → verification required;
6. unexpected extraction → do not silently present uncertain information as reliable.

The current prototype uses controlled structured extraction for fictional samples and does **not** claim medical-grade OCR or clinical decision support.

## Runtime evidence note
The suite is designed to be executed on the student's Windows environment after dependencies are installed. A report should record the actual console result and screenshots from the running application rather than claiming a test passed solely because the code contains a defense.
