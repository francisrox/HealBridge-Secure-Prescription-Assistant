# HealBridge 2.0 — Secure Prescription Explanation System

HealBridge is an academic Web Application and Defenses prototype. Version 2.0 adds a familiar productivity-style UI with light/dark themes, a searchable prescription vault, dashboard security activity, secure original-file download, and server-side demo extraction for the fictional PDF samples.

## Run backend (Windows PowerShell)

From the project root:

```powershell
cd healbridge
.\backend\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
uvicorn backend.main:app --reload
```

Keep this terminal running. API: http://127.0.0.1:8000

Swagger: http://127.0.0.1:8000/docs

## Run frontend

Open a second PowerShell:

```powershell
cd healbridge\frontend
npm install
npm run dev
```

Open http://localhost:5173

## New features

- Light/dark theme toggle, persisted in the browser.
- Prescription Vault with search by medicine/filename and status filters.
- Dashboard security activity feed.
- Dashboard summary endpoint for total/verified/review/security-event counts.
- Secure original-file download with server-side ownership checks.
- Server-side PDF text extraction for the fictional test samples; the app still does not claim medical-grade OCR.
- Better integrity details with SHA-256 fingerprints.
- Improved upload feedback and drag-and-drop UI.
- Responsive desktop/tablet/mobile layout.
- Security Center with OWASP Top 10 mapping and audit trail.

## Security controls retained

A01 access control: RBAC + server-side ownership checks for records and downloads.
A02 misconfiguration: restricted CORS, security headers, safe errors.
A03 supply chain: pinned dependencies and minimal frontend package set.
A04 cryptography: Argon2id password hashing and expiring signed JWTs.
A05 injection: SQLAlchemy parameterized queries + Pydantic validation.
A06 insecure design: least privilege, deny-by-default, uncertainty workflow.
A07 authentication: protected routes, password hashing, token expiry, rate limits.
A08 integrity: extension/MIME/magic-byte validation, generated filenames, SHA-256.
A09 logging: authentication, upload, access, download, deletion and attack events.
A10 exceptional conditions: controlled 4xx/429/500 responses without stack traces.

## Admin demo

Register normally, then set that account to ADMIN in SQLite:

```sql
UPDATE users SET role='ADMIN' WHERE email='your-email@example.com';
```

Never expose public admin registration.

## Test samples

Use the separate `HealBridge_Test_Samples_v2.zip` supplied with this project. The ten PDFs have different medicines, different visual layouts, and two intentionally incomplete samples for the verification-warning workflow.

All sample documents are fictional academic test data and must not be treated as medical advice.

## Phase 1 — Authentication & Access Security

Phase 1 adds session revocation on logout, a stronger registration password policy, protected admin regression endpoint, and automated authentication/RBAC/IDOR regression tests.

Run the regression test from `backend/`:

```powershell
python test_phase1.py
```

See `PHASE_1_COMPLETE.md` for the completed controls and test mapping.


## Phase 5 — Finalization & Presentation

Phase 5 makes the project submission-ready without changing the core security model. It adds active navigation states, a final demo-readiness path on the dashboard, ADMIN audit CSV export, and a complete documentation/evidence pack.

Key files:
- `PHASE_5_COMPLETE.md` — phase completion summary.
- `ARCHITECTURE.md` — system architecture and trust boundaries.
- `OWASP_MATRIX.md` — defense-to-OWASP mapping and evidence guidance.
- `DEMO_SCRIPT.md` — recommended classroom demonstration sequence.
- `TEST_REPORT_TEMPLATE.md` — security and safety test result table.
- `FINAL_SUBMISSION_CHECKLIST.md` — final application/report/presentation checklist.

The project includes a classroom demonstration script and checklist in the documentation. ADMIN users can export recent audit events from the Security Center as `healbridge-audit-log.csv`.

## Phase 2 — File & Input Security

Phase 2 strengthens upload and input handling with layered extension/MIME/magic-byte validation, parser-level PDF and image validation, incremental 5 MB upload limits, a 30-page PDF limit, a 25-million-pixel image limit, safe filename normalization, random private storage names, path-containment checks, and SHA-256 integrity fingerprints.

Run the regression suite:

```powershell
python backend\test_phase2.py
```

See `PHASE_2_COMPLETE.md` for the controls and test matrix.

## Final consolidated report

The final implementation is documented in:
- `FINAL_PROJECT_REPORT.md` — complete project report from architecture through security testing.
- `HealBridge_Final_Report.docx` — editable report for submission.
- `HealBridge_Final_Report.pdf` — print/share version.
- `FINAL_IMPLEMENTATION_README.md` — final run instructions.
- `PHASE_4_COMPLETE.md` — final security and safety test suite.

Run the final Phase 4 regression suite with `python backend\test_phase4.py` after installing the backend requirements.
