"""HealBridge Phase 2 — file and input security regression tests.

Run from backend/ after installing requirements:
    python test_phase2.py

Uses an isolated temporary SQLite database and never touches the normal DB.
"""
import os
import io
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix='healbridge_phase2_'))
os.environ['DATABASE_URL'] = f"sqlite:///{_tmp / 'test.db'}"
os.environ['SECRET_KEY'] = 'phase2-test-secret-key-please-change-in-real-use'
os.environ['ALLOWED_ORIGINS'] = 'http://testserver'
os.environ['MAX_UPLOAD_MB'] = '5'

from fastapi.testclient import TestClient
from pypdf import PdfWriter
from PIL import Image
from main import app

client = TestClient(app)


def register_and_login(email='phase2@example.com'):
    r = client.post('/api/auth/register', json={
        'name': 'Phase Two', 'email': email, 'password': 'StrongPass123'
    })
    assert r.status_code == 200, r.text
    r = client.post('/api/auth/login', json={
        'email': email, 'password': 'StrongPass123'
    })
    assert r.status_code == 200, r.text
    return {'Authorization': f"Bearer {r.json()['access_token']}"}


def valid_pdf():
    buf = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.write(buf)
    return buf.getvalue()


def valid_png():
    buf = io.BytesIO()
    Image.new('RGB', (80, 80), (240, 240, 240)).save(buf, format='PNG')
    return buf.getvalue()

headers = register_and_login()

# T01 — valid PDF accepted and server-side parser validation succeeds.
r = client.post('/api/prescriptions/upload', headers=headers,
                files={'file': ('sample.pdf', valid_pdf(), 'application/pdf')})
assert r.status_code == 200, r.text
assert r.json()['file_sha256'] and len(r.json()['file_sha256']) == 64
print('T01 Valid PDF: PASS')

# T02 — valid PNG accepted through real image decoding, not only magic bytes.
r = client.post('/api/prescriptions/upload', headers=headers,
                files={'file': ('sample.png', valid_png(), 'image/png')})
assert r.status_code == 200, r.text
print('T02 Valid PNG parser validation: PASS')

# T03 — executable renamed to PDF must fail magic-byte validation.
r = client.post('/api/prescriptions/upload', headers=headers,
                files={'file': ('invoice.pdf', b'MZ' + b'X' * 100, 'application/pdf')})
assert r.status_code == 400
assert 'signature' in r.json()['detail'].lower()
print('T03 Renamed executable/magic-byte mismatch: PASS')

# T04 — spoofed MIME type must fail even when the extension is allowed.
r = client.post('/api/prescriptions/upload', headers=headers,
                files={'file': ('sample.pdf', valid_pdf(), 'image/png')})
assert r.status_code == 400
assert 'mime' in r.json()['detail'].lower()
print('T04 MIME mismatch: PASS')

# T05 — malformed PDF with a valid PDF signature must fail parser validation.
r = client.post('/api/prescriptions/upload', headers=headers,
                files={'file': ('broken.pdf', b'%PDF-1.7\nnot a real pdf', 'application/pdf')})
assert r.status_code == 400
assert 'malformed' in r.json()['detail'].lower() or 'invalid' in r.json()['detail'].lower()
print('T05 Malformed PDF: PASS')

# T06 — unsupported executable extension rejected.
r = client.post('/api/prescriptions/upload', headers=headers,
                files={'file': ('payload.exe', b'MZ' + b'X' * 50, 'application/octet-stream')})
assert r.status_code == 400
assert 'unsupported' in r.json()['detail'].lower()
print('T06 Unsupported extension: PASS')

# T07 — oversized request is rejected before it can be stored.
large = b'%PDF-' + b'X' * (5 * 1024 * 1024)
r = client.post('/api/prescriptions/upload', headers=headers,
                files={'file': ('large.pdf', large, 'application/pdf')})
assert r.status_code == 413
assert 'maximum size' in r.json()['detail'].lower()
print('T07 Oversized upload: PASS')

# T08 — path traversal filename is reduced to a basename; storage remains generated.
r = client.post('/api/prescriptions/upload', headers=headers,
                files={'file': ('../../secret.pdf', valid_pdf(), 'application/pdf')})
assert r.status_code == 200, r.text
body = r.json()
assert body['original_filename'] == 'secret.pdf'
assert '..' not in body['original_filename']
assert '/' not in body['original_filename']
assert body['file_sha256']
print('T08 Path traversal filename normalization: PASS')

# T09 — control characters in filename are removed.
r = client.post('/api/prescriptions/upload', headers=headers,
                files={'file': ('safe\x00<script>.pdf', valid_pdf(), 'application/pdf')})
assert r.status_code == 200, r.text
name = r.json()['original_filename']
assert '\x00' not in name
print('T09 Filename control-character sanitization: PASS')

# T10 — SQLi-style search input is treated as ordinary data and cannot alter ownership scope.
r = client.get('/api/prescriptions?q=%27%20OR%201%3D1%20--', headers=headers)
assert r.status_code == 200, r.text
assert isinstance(r.json(), list)
print('T10 SQLi-style search input: PASS')

print('\nPHASE 2 TESTS PASSED')
