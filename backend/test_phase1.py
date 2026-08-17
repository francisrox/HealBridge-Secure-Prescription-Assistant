"""HealBridge Phase 1 security regression tests.

Run from backend/ after installing requirements:
    python test_phase1.py

These tests use an isolated temporary SQLite database and do not touch the
normal healbridge.db file.
"""
import os
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix='healbridge_phase1_'))
os.environ['DATABASE_URL'] = f"sqlite:///{_tmp / 'test.db'}"
os.environ['SECRET_KEY'] = 'phase1-test-secret-key-please-change-in-real-use'
os.environ['ALLOWED_ORIGINS'] = 'http://testserver'

from fastapi.testclient import TestClient
from main import app, Audit, Prescription, SessionLocal, User

client = TestClient(app)


def register(email, password='StrongPass123'):
    return client.post('/api/auth/register', json={
        'name': 'Test User', 'email': email, 'password': password
    })


def login(email, password='StrongPass123'):
    return client.post('/api/auth/login', json={
        'email': email, 'password': password
    })


def auth(token):
    return {'Authorization': f'Bearer {token}'}


# --- T01/T02: account + RBAC setup ---
assert register('alice@example.com').status_code == 200
assert register('bob@example.com').status_code == 200

alice_login = login('alice@example.com')
assert alice_login.status_code == 200
alice_token = alice_login.json()['access_token']

bob_login = login('bob@example.com')
assert bob_login.status_code == 200
bob_token = bob_login.json()['access_token']

with SessionLocal() as d:
    bob = d.query(User).filter_by(email='bob@example.com').one()
    p = Prescription(
        user_id=bob.id,
        medicine='TestMed', strength='10 mg', frequency='Once daily',
        timing='Morning', duration='7 days', explanation='Test', verified=True,
    )
    d.add(p)
    d.commit()
    d.refresh(p)
    bob_pid = p.id

# Unauthenticated protected route -> 401
assert client.get(f'/api/prescriptions/{bob_pid}').status_code == 401

# T01: cross-user IDOR -> 403 + audit event
r = client.get(f'/api/prescriptions/{bob_pid}', headers=auth(alice_token))
assert r.status_code == 403, r.text

# T02: patient -> admin endpoint -> 403
r = client.get('/api/admin/ping', headers=auth(alice_token))
assert r.status_code == 403, r.text

# T06: SQLi-like login input cannot bypass validation/authentication
r = client.post('/api/auth/login', json={
    'email': "' OR '1'='1",
    'password': "' OR '1'='1",
})
assert r.status_code in (401, 422), r.text

# Invalid/forged token -> 401
assert client.get('/api/auth/me', headers=auth('not-a-real-token')).status_code == 401

# Logout revokes the exact JWT; reusing it must fail -> 401
r = client.post('/api/auth/logout', headers=auth(alice_token))
assert r.status_code == 200, r.text
assert client.get('/api/auth/me', headers=auth(alice_token)).status_code == 401

# A different user's session remains valid
assert client.get('/api/auth/me', headers=auth(bob_token)).status_code == 200

# Password policy rejects weak password
assert register('weak@example.com', 'passwordonly').status_code == 422

# Promote Bob locally for admin regression test; this is not a public API.
with SessionLocal() as d:
    bob = d.query(User).filter_by(email='bob@example.com').one()
    bob.role = 'ADMIN'
    d.commit()

admin_login = login('bob@example.com')
assert admin_login.status_code == 200
admin_token = admin_login.json()['access_token']
assert client.get('/api/admin/ping', headers=auth(admin_token)).status_code == 200

# Verify the access-control denial produced an audit event.
with SessionLocal() as d:
    events = [x.event for x in d.query(Audit).all()]
    assert 'UNAUTHORIZED_ACCESS' in events

print('PHASE 1 TESTS PASSED')
print('T01 IDOR: PASS')
print('T02 RBAC: PASS')
print('Authentication/session revocation: PASS')
print('Password policy: PASS')
print('SQLi login bypass: PASS')
print('Unauthorized access audit: PASS')
