# Phase 2 — File & Input Security

## Status
**Implementation complete. Runtime regression tests should be executed locally with `python backend/test_phase2.py`.**

## Controls implemented

### 1. Layered upload validation
Every prescription upload is checked server-side using:
- allowlisted extensions: PDF, PNG, JPG/JPEG
- required browser-reported MIME type
- magic-byte/content signature
- parser-level PDF validation with `pypdf`
- parser-level image validation with Pillow
- empty-file rejection

Client-side checks are only for usability; the server remains authoritative.

### 2. Resource limits
- Maximum upload size remains 5 MB by configuration.
- Uploads are read incrementally in 1 MB chunks and rejected once the limit is exceeded.
- PDFs are limited to 30 pages.
- Pillow image pixel count is capped at 25 million pixels to reduce decompression-bomb risk.

### 3. Safe storage
- Original filenames are never used as filesystem paths.
- Storage names are random 32-character hexadecimal identifiers plus a validated extension.
- A resolved-path containment check prevents accidental storage outside the private uploads directory.
- Original filenames are normalized to a basename and control characters are removed before persistence/display.

### 4. Integrity
Accepted files receive a SHA-256 fingerprint that is stored with the prescription record and displayed in the detail view.

### 5. Input handling
- Pydantic validation protects authentication inputs.
- SQLAlchemy is used for database access; no user-controlled SQL is concatenated into queries.
- Search input is treated as data.
- React renders user-controlled strings as text rather than raw HTML.
- Error responses are controlled and do not expose stack traces.

## Phase 2 test matrix

| ID | Test | Expected result |
|---|---|---|
| T01 | Valid PDF | Accepted |
| T02 | Valid PNG | Accepted |
| T03 | Executable renamed `.pdf` | Rejected by signature validation |
| T04 | MIME mismatch | Rejected |
| T05 | Malformed PDF | Rejected by parser |
| T06 | `.exe` upload | Rejected |
| T07 | >5 MB upload | Rejected with 413 |
| T08 | Path traversal filename | Normalized; safe generated storage name |
| T09 | Filename control characters | Removed |
| T10 | SQLi-style search input | No query manipulation/bypass |

## OWASP relevance
Phase 2 primarily strengthens:
- A03 Injection
- A08 Software/Data Integrity Failures
- A10 Mishandling of Exceptional Conditions

It also contributes to A04 Insecure Design and A05 Security Misconfiguration through layered validation, least exposure, safe storage and controlled errors.

## Runtime command

```powershell
cd healbridge
.\\backend\\.venv\\Scripts\\Activate.ps1
pip install -r backend\\requirements.txt
python backend\\test_phase2.py
```

All sample documents are fictional academic test data.
