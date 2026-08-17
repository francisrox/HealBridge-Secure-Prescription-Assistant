"""Phase 3 static/security configuration checks.
Run from the project root with: python backend/test_phase3.py
"""
from pathlib import Path
import re

MAIN = Path(__file__).with_name('main.py').read_text(encoding='utf-8')
REQ = Path(__file__).with_name('requirements.txt').read_text(encoding='utf-8')
checks = [
    ('P01 trusted host middleware', 'TrustedHostMiddleware' in MAIN),
    ('P02 restrictive CORS origins', "allow_origins=allowed_origins" in MAIN and "allow_credentials=False" in MAIN),
    ('P03 origin defense for unsafe methods', "Cross-origin request blocked" in MAIN),
    ('P04 security headers', all(x in MAIN for x in ['X-Content-Type-Options','X-Frame-Options','Content-Security-Policy','Referrer-Policy','Permissions-Policy'])),
    ('P05 cross-origin isolation headers', 'Cross-Origin-Resource-Policy' in MAIN and 'Cross-Origin-Opener-Policy' in MAIN),
    ('P06 safe validation errors', 'RequestValidationError' in MAIN and "Request validation failed" in MAIN),
    ('P07 generic 500 error response', "An unexpected error occurred." in MAIN),
    ('P08 rate limit Retry-After', "'Retry-After': '60'" in MAIN),
    ('P09 no account enumeration timing', 'DUMMY_PASSWORD_HASH' in MAIN and 'valid_password = pwd.verify' in MAIN),
    ('P10 revoked-token cleanup', 'RevokedToken).filter(RevokedToken.expires_at < now)' in MAIN),
    ('P11 pinned dependencies', bool(re.search(r'fastapi==', REQ)) and bool(re.search(r'slowapi==', REQ)) and bool(re.search(r'PyJWT==', REQ))),
]
failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
if failed:
    raise SystemExit(f"{len(failed)} Phase 3 checks failed")
print('\nPHASE 3 STATIC SECURITY CHECKS PASSED')
