# Phase 2 Change Log

- Added parser-level PDF validation using `pypdf`.
- Added real image decoding/verification using Pillow.
- Added incremental upload reading with a hard 5 MB ceiling.
- Added 30-page PDF limit.
- Added 25-million-pixel image limit.
- Added safe original filename normalization.
- Added private generated storage filename/path containment check.
- Added frontend pre-validation for type, size and MIME mismatch.
- Added `backend/test_phase2.py` with ten regression tests.
- Added Phase 2 documentation and OWASP/test-plan updates.
