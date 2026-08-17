"""HealBridge Phase 4 security and safety regression suite.

Run from the project root after installing backend requirements:
    python backend/test_phase4.py

The suite uses an isolated temporary SQLite database and TestClient. It does
not modify the normal healbridge.db or uploads directory.
"""
import io
import os
import re
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix='healbridge_phase4_'))
os.environ['DATABASE_URL'] = f"sqlite:///{_tmp / 'test.db'}"
os.environ['SECRET_KEY'] = 'phase4-test-secret-key-only-for-isolated-tests'
os.environ['ALLOWED_ORIGINS'] = 'http://testserver'
os.environ['TRUSTED_HOSTS'] = 'testserver'
os.environ['MAX_UPLOAD_MB'] = '5'

from fastapi.testclient import TestClient
from pypdf import PdfWriter
from main import app, Audit, Prescription, SessionLocal, User

client = TestClient(app)

def valid_pdf():
    buf = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.write(buf)
    return buf.getvalue()

def register(email, password='StrongPass123'):
    return client.post('/api/auth/register', json={'name':'Phase Four','email':email,'password':password})

def login(email, password='StrongPass123'):
    return client.post('/api/auth/login', json={'email':email,'password':password})

def auth(token):
    return {'Authorization': f'Bearer {token}'}

results=[]
def check(label, ok, detail=''):
    results.append((label, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f" — {detail}" if detail else ''))
    if not ok:
        raise AssertionError(f"{label}: {detail}")

# P4-01 unauthenticated access
r=client.get('/api/prescriptions')
check('P4-01 unauthenticated protected route -> 401', r.status_code == 401, r.text)

# Register two users
check('P4-02 register user A', register('phase4a@example.com').status_code == 200)
check('P4-03 register user B', register('phase4b@example.com').status_code == 200)

la=login('phase4a@example.com')
lb=login('phase4b@example.com')
check('P4-04 login user A', la.status_code == 200)
check('P4-05 login user B', lb.status_code == 200)
a=la.json()['access_token']; b=lb.json()['access_token']

# Create an owned prescription for user B via the real upload endpoint.
r=client.post('/api/prescriptions/upload', headers=auth(b), files={'file':('owned.pdf',valid_pdf(),'application/pdf')})
check('P4-06 valid upload', r.status_code == 200, r.text)
pid=r.json()['id']

# IDOR / ownership
r=client.get(f'/api/prescriptions/{pid}', headers=auth(a))
check('P4-07 cross-user IDOR -> 403', r.status_code == 403, r.text)

# Patient -> admin
r=client.get('/api/admin/ping', headers=auth(a))
check('P4-08 patient -> admin endpoint -> 403', r.status_code == 403, r.text)

# Forged token
r=client.get('/api/auth/me', headers=auth('forged.token.value'))
check('P4-09 forged token -> 401', r.status_code == 401, r.text)

# SQL injection login bypass
r=client.post('/api/auth/login', json={'email':"' OR '1'='1",'password':"' OR '1'='1"})
check('P4-10 SQL injection login bypass blocked', r.status_code in (401,422), r.text)

# XSS-style search input remains ordinary data and cannot escape the query scope.
xss='<script>alert(1)</script>'
r=client.get('/api/prescriptions', params={'q':xss}, headers=auth(a))
check('P4-11 XSS-style search input handled as data', r.status_code == 200 and isinstance(r.json(),list), r.text)

# Cross-origin unsafe request defense
r=client.post('/api/auth/logout', headers={**auth(a),'Origin':'https://evil.example'})
check('P4-12 hostile Origin blocked -> 403', r.status_code == 403, r.text)

# Security headers
r=client.get('/api/health')
required=['X-Content-Type-Options','X-Frame-Options','Content-Security-Policy','Referrer-Policy','Permissions-Policy','Cross-Origin-Resource-Policy','Cross-Origin-Opener-Policy','X-Request-ID']
check('P4-13 security headers present', all(h in r.headers for h in required), str({h:r.headers.get(h) for h in required}))

# Malicious/invalid uploads
r=client.post('/api/prescriptions/upload', headers=auth(a), files={'file':('payload.exe',b'MZ'+b'X'*100,'application/octet-stream')})
check('P4-14 executable extension rejected -> 400', r.status_code == 400, r.text)
r=client.post('/api/prescriptions/upload', headers=auth(a), files={'file':('fake.pdf',b'MZ'+b'X'*100,'application/pdf')})
check('P4-15 renamed executable signature rejected -> 400', r.status_code == 400, r.text)
r=client.post('/api/prescriptions/upload', headers=auth(a), files={'file':('broken.pdf',b'%PDF-1.7\nnot a real pdf','application/pdf')})
check('P4-16 malformed PDF rejected -> 400', r.status_code == 400, r.text)

# Oversized upload. This is a raw request body just over 5 MB; the endpoint rejects it.
large=b'%PDF-' + b'X'*(5*1024*1024)
r=client.post('/api/prescriptions/upload', headers=auth(a), files={'file':('large.pdf',large,'application/pdf')})
check('P4-17 oversized upload rejected -> 413', r.status_code == 413, r.text)

# Controlled invalid identifier / exceptional condition
r=client.get('/api/prescriptions/not-an-id', headers=auth(a))
check('P4-18 invalid prescription id -> controlled 422', r.status_code == 422, r.text)

# Logout + token replay
r=client.post('/api/auth/logout', headers=auth(a))
check('P4-19 logout succeeds', r.status_code == 200, r.text)
r=client.get('/api/auth/me', headers=auth(a))
check('P4-20 revoked token replay -> 401', r.status_code == 401, r.text)

# Safety: filename-triggered uncertainty workflow with a valid PDF.
l2=login('phase4b@example.com')
check('P4-21 fresh session for safety test', l2.status_code == 200)
b2=l2.json()['access_token']
r=client.post('/api/prescriptions/upload', headers=auth(b2), files={'file':('uncertain-dosage.pdf',valid_pdf(),'application/pdf')})
check('P4-22 uncertainty case accepted and flagged', r.status_code == 200 and r.json().get('verified') is False, r.text)

# Audit evidence for IDOR and upload.
with SessionLocal() as d:
    events=[x.event for x in d.query(Audit).all()]
check('P4-23 audit trail contains unauthorized-access event', 'UNAUTHORIZED_ACCESS' in events)
check('P4-24 audit trail contains upload event', 'PRESCRIPTION_UPLOAD' in events)

# Frontend XSS safety invariant: no raw HTML injection helper is used.
frontend=Path(__file__).resolve().parents[1] / 'frontend' / 'src'
source='\n'.join(p.read_text(encoding='utf-8') for p in frontend.glob('*.jsx'))
check('P4-25 frontend does not use dangerouslySetInnerHTML', 'dangerouslySetInnerHTML' not in source)


# Rate limiting: use a distinct client address so earlier tests do not consume the bucket.
rate_client = TestClient(app, client=("10.0.0.99", 45678))
rate_client.post('/api/auth/register', json={'name':'Rate Test','email':'ratetest@example.com','password':'StrongPass123'})
rate_results=[]
for i in range(9):
    rr=rate_client.post('/api/auth/login', json={'email':'ratetest@example.com','password':'WrongPass123'})
    rate_results.append(rr.status_code)
check('P4-26 repeated login failures trigger rate limit -> 429', 429 in rate_results, str(rate_results))

# Static backend invariants for centralized exception handling and rate-limit headers.
backend_source=Path(__file__).with_name('main.py').read_text(encoding='utf-8')
check('P4-27 generic 500 handler does not expose traceback', "An unexpected error occurred." in backend_source and "except Exception:" in backend_source)
check('P4-28 rate-limit response includes Retry-After', "'Retry-After': '60'" in backend_source)

print('\nPHASE 4 TESTS PASSED')
print(f'Executed checks: {len(results)}')
print(f'Isolated database: {_tmp / "test.db"}')
