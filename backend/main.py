from pathlib import Path
from datetime import datetime, timezone, timedelta
import hashlib, secrets, re, io, unicodedata

import jwt
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, field_validator
from pydantic_settings import BaseSettings
from sqlalchemy import create_engine, String, DateTime, ForeignKey, Text, Boolean, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from pwdlib import PasswordHash
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None

try:
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = 25_000_000
except Exception:
    Image = None

class Settings(BaseSettings):
    secret_key: str = 'CHANGE_ME'
    database_url: str = 'sqlite:///./healbridge.db'
    allowed_origins: str = 'http://localhost:5173,http://127.0.0.1:5173'
    max_upload_mb: int = 5
    access_token_expire_minutes: int = 30
    trusted_hosts: str = 'localhost,127.0.0.1'
    enable_hsts: bool = False
    class Config:
        env_file = '.env'

s = Settings()
ROOT = Path(__file__).resolve().parent
UPLOADS = ROOT / 'uploads'
UPLOADS.mkdir(exist_ok=True)
engine = create_engine(s.database_url, connect_args={'check_same_thread': False})
SessionLocal = sessionmaker(bind=engine)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default='PATIENT')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Prescription(Base):
    __tablename__ = 'prescriptions'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    medicine: Mapped[str] = mapped_column(String(150))
    strength: Mapped[str] = mapped_column(String(80))
    frequency: Mapped[str] = mapped_column(String(100))
    timing: Mapped[str] = mapped_column(String(100))
    duration: Mapped[str] = mapped_column(String(100))
    explanation: Mapped[str] = mapped_column(Text)
    verified: Mapped[bool] = mapped_column(Boolean, default=True)
    original_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    stored_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class RevokedToken(Base):
    __tablename__ = 'revoked_tokens'
    id: Mapped[int] = mapped_column(primary_key=True)
    jti: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Audit(Base):
    __tablename__ = 'audit_logs'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    event: Mapped[str] = mapped_column(String(80), index=True)
    details: Mapped[str] = mapped_column(Text, default='')
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

Base.metadata.create_all(engine)

def db():
    x = SessionLocal()
    try:
        yield x
    finally:
        x.close()

pwd = PasswordHash.recommended()
DUMMY_PASSWORD_HASH = pwd.hash('HealBridge-Dummy-Password-Only-For-Timing')
bearer = HTTPBearer(auto_error=False)

def audit(d: Session, event: str, details: str = '', user: User | None = None, ip: str | None = None):
    d.add(Audit(user_id=user.id if user else None, event=event, details=details[:1000], ip=ip))
    d.commit()

def token(uid: int, role: str):
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {'sub': str(uid), 'role': role, 'iat': int(now.timestamp()),
         'exp': int((now + timedelta(minutes=s.access_token_expire_minutes)).timestamp()),
         'jti': secrets.token_urlsafe(12)},
        s.secret_key, algorithm='HS256'
    )

def current(creds: HTTPAuthorizationCredentials = Depends(bearer), d: Session = Depends(db)):
    if not creds or creds.scheme.lower() != 'bearer':
        raise HTTPException(401, 'Authentication required')
    try:
        payload = jwt.decode(creds.credentials, s.secret_key, algorithms=['HS256'])
        uid = int(payload['sub'])
        jti = str(payload['jti'])
        exp = datetime.fromtimestamp(int(payload['exp']), tz=timezone.utc)
    except Exception:
        raise HTTPException(401, 'Invalid or expired token')
    revoked = d.scalar(select(RevokedToken).where(RevokedToken.jti == jti))
    if revoked:
        raise HTTPException(401, 'Session has been revoked')
    # Opportunistically remove expired revocations to keep the session-revocation table bounded.
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    d.query(RevokedToken).filter(RevokedToken.expires_at < now).delete(synchronize_session=False)
    d.commit()
    u = d.get(User, uid)
    if not u:
        raise HTTPException(401, 'Invalid authentication')
    return u

def admin(request: Request, u: User = Depends(current), d: Session = Depends(db)):
    if u.role != 'ADMIN':
        audit(d, 'UNAUTHORIZED_ACCESS', 'Attempted administrator endpoint', u, get_remote_address(request))
        raise HTTPException(403, 'Administrator access required')
    return u

class Register(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)

    @field_validator('password')
    @classmethod
    def validate_password(cls, value: str) -> str:
        if not re.search(r'[A-Z]', value) or not re.search(r'[a-z]', value) or not re.search(r'\d', value):
            raise ValueError('Password must contain uppercase, lowercase, and a number')
        return value

class Login(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

app = FastAPI(title='HealBridge Secure Prescription Explanation System')
limiter = Limiter(key_func=get_remote_address, default_limits=['120/minute'])
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
trusted_hosts = [x.strip() for x in s.trusted_hosts.split(',') if x.strip()]
if trusted_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)
allowed_origins = [x.strip().rstrip('/') for x in s.allowed_origins.split(',') if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=['GET', 'POST', 'DELETE', 'OPTIONS'],
    allow_headers=['Authorization', 'Content-Type', 'X-Request-ID'],
    allow_credentials=False,
)

@app.middleware('http')
async def security_middleware(request, call_next):
    # Bearer tokens are not automatically attached by browsers, so classic cookie CSRF
    # does not apply. As defense-in-depth, reject unsafe cross-origin browser requests
    # when an Origin header is present and is not one of the configured origins.
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        origin = request.headers.get('origin')
        if origin and origin.rstrip('/') not in allowed_origins:
            return JSONResponse(status_code=403, content={'detail': 'Cross-origin request blocked'})
    request_id = request.headers.get('X-Request-ID') or secrets.token_hex(12)
    try:
        response = await call_next(request)
    except Exception:
        response = JSONResponse(status_code=500, content={'detail': 'An unexpected error occurred.'})
    response.headers.update({
        'X-Request-ID': request_id,
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        'Cross-Origin-Resource-Policy': 'same-origin',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cache-Control': 'no-store' if request.url.path.startswith('/api/auth/') else 'no-cache',
    })
    if s.enable_hsts:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={'detail': 'Request validation failed', 'errors': exc.errors()})

@app.exception_handler(RateLimitExceeded)
async def rate(request, exc):
    return JSONResponse(status_code=429, content={'detail': 'Too many requests. Try again later.'}, headers={'Retry-After': '60'})

@app.get('/api/health')
def health():
    return {'status': 'ok', 'service': 'HealBridge', 'version': '2.0'}

@app.post('/api/auth/register')
@limiter.limit('5/minute')
def register(p: Register, request: Request, d: Session = Depends(db)):
    email = p.email.lower().strip()
    if d.scalar(select(User).where(User.email == email)):
        raise HTTPException(400, 'Registration could not be completed')
    u = User(name=p.name.strip(), email=email, password_hash=pwd.hash(p.password))
    d.add(u); d.commit(); d.refresh(u)
    audit(d, 'REGISTER', 'New account', u, get_remote_address(request))
    return {'id': u.id, 'name': u.name, 'email': u.email, 'role': u.role}

@app.post('/api/auth/login')
@limiter.limit('8/minute')
def login(p: Login, request: Request, d: Session = Depends(db)):
    email = p.email.lower().strip()
    u = d.scalar(select(User).where(User.email == email))
    # Always perform a password-hash verification, even for an unknown account,
    # to reduce observable timing differences that can aid account enumeration.
    valid_password = pwd.verify(p.password, u.password_hash if u else DUMMY_PASSWORD_HASH)
    if not u or not valid_password:
        audit(d, 'LOGIN_FAILURE', 'Failed login attempt', u, get_remote_address(request))
        raise HTTPException(401, 'Invalid email or password')
    audit(d, 'LOGIN_SUCCESS', 'Successful login', u, get_remote_address(request))
    return {'access_token': token(u.id, u.role), 'token_type': 'bearer'}

@app.get('/api/auth/me')
def me(u: User = Depends(current)):
    return {'id': u.id, 'name': u.name, 'email': u.email, 'role': u.role}

@app.post('/api/auth/logout')
def logout(request: Request, creds: HTTPAuthorizationCredentials = Depends(bearer), u: User = Depends(current), d: Session = Depends(db)):
    if not creds or creds.scheme.lower() != 'bearer':
        raise HTTPException(401, 'Authentication required')
    try:
        payload = jwt.decode(creds.credentials, s.secret_key, algorithms=['HS256'])
        jti = str(payload['jti'])
        exp = datetime.fromtimestamp(int(payload['exp']), tz=timezone.utc)
    except Exception:
        raise HTTPException(401, 'Invalid or expired token')
    if not d.scalar(select(RevokedToken).where(RevokedToken.jti == jti)):
        d.add(RevokedToken(jti=jti, expires_at=exp))
        d.commit()
    audit(d, 'LOGOUT', 'Session revoked', u, get_remote_address(request))
    return {'message': 'Logged out'}

@app.get('/api/dashboard/summary')
def dashboard_summary(u: User = Depends(current), d: Session = Depends(db)):
    rows = list(d.scalars(select(Prescription).where(Prescription.user_id == u.id).order_by(Prescription.created_at.desc()).limit(50)))
    verified = sum(1 for p in rows if p.verified)
    return {
        'total': len(rows),
        'verified': verified,
        'needs_review': len(rows) - verified,
        'recent_upload': rows[0].created_at if rows else None,
        'security_events': d.scalar(select(func.count(Audit.id)).where(Audit.user_id == u.id)) or 0,
    }

def serialize_prescription(p: Prescription):
    return {
        'id': p.id, 'user_id': p.user_id, 'medicine': p.medicine, 'strength': p.strength,
        'frequency': p.frequency, 'timing': p.timing, 'duration': p.duration,
        'explanation': p.explanation, 'verified': p.verified,
        'original_filename': p.original_filename, 'file_sha256': p.file_sha256,
        'created_at': p.created_at,
    }

@app.get('/api/prescriptions')
def prescriptions(q: str = '', status: str = 'all', u: User = Depends(current), d: Session = Depends(db)):
    stmt = select(Prescription).where(Prescription.user_id == u.id).order_by(Prescription.created_at.desc())
    items = list(d.scalars(stmt))
    q = q.strip().lower()
    if q:
        items = [p for p in items if q in p.medicine.lower() or q in (p.original_filename or '').lower()]
    if status == 'verified':
        items = [p for p in items if p.verified]
    elif status == 'review':
        items = [p for p in items if not p.verified]
    return [serialize_prescription(p) for p in items]

def extract_demo_fields(data: bytes, filename: str):
    text = ''
    if filename.lower().endswith('.pdf') and PdfReader:
        try:
            import io
            reader = PdfReader(io.BytesIO(data))
            text = '\n'.join((page.extract_text() or '') for page in reader.pages)
        except Exception:
            text = ''
    fields = {}
    for key in ['Medicine', 'Strength', 'Frequency', 'Timing', 'Duration']:
        match = re.search(rf'{key}\s*:\s*([^\n]+)', text, flags=re.I)
        if match:
            fields[key.lower()] = match.group(1).strip()
    name = filename.lower()
    catalog = {
        'metformin': ('Metformin', '500 mg', 'Twice daily', 'After food', '30 days'),
        'amoxicillin': ('Amoxicillin', '500 mg', 'Three times daily', 'After food', '7 days'),
        'omeprazole': ('Omeprazole', '20 mg', 'Once daily', 'Before breakfast', '14 days'),
        'paracetamol': ('Paracetamol', '500 mg', 'As directed', 'After food', '5 days'),
        'cetirizine': ('Cetirizine', '10 mg', 'Once daily', 'At night', '10 days'),
        'azithromycin': ('Azithromycin', '250 mg', 'Once daily', 'After food', '5 days'),
        'ibuprofen': ('Ibuprofen', '200 mg', 'As directed', 'After food', '3 days'),
        'losartan': ('Losartan', '50 mg', 'Once daily', 'Morning', '30 days'),
        'atorvastatin': ('Atorvastatin', '10 mg', 'Once daily', 'At night', '30 days'),
        'levothyroxine': ('Levothyroxine', '50 mcg', 'Once daily', 'Before breakfast', '30 days'),
    }
    if not fields.get('medicine'):
        for k, v in catalog.items():
            if k in name:
                fields = dict(zip(['medicine', 'strength', 'frequency', 'timing', 'duration'], v)); break
    return fields

def clean_original_filename(filename: str | None) -> str:
    """Create a safe display/download name; storage never uses this value."""
    raw = Path(filename or 'prescription').name
    raw = ''.join(ch for ch in raw if unicodedata.category(ch)[0] != 'C')
    raw = raw.strip().replace('\x00', '')
    if not raw or raw in {'.', '..'}:
        raw = 'prescription'
    # Keep the original extension only after validation; avoid header/control abuse.
    return raw[:180]

async def read_upload_limited(file: UploadFile, limit: int) -> bytes:
    """Read an upload incrementally and stop as soon as it exceeds the limit."""
    chunks = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise HTTPException(413, 'Upload rejected: file exceeds the maximum size')
        chunks.append(chunk)
    return b''.join(chunks)

def validate_pdf(data: bytes) -> None:
    if PdfReader is None:
        raise HTTPException(503, 'PDF validation is unavailable on this server')
    try:
        reader = PdfReader(io.BytesIO(data), strict=True)
        if not reader.pages:
            raise ValueError('PDF has no pages')
        if len(reader.pages) > 30:
            raise ValueError('PDF has too many pages')
    except Exception:
        raise HTTPException(400, 'Upload rejected: invalid or malformed PDF')

def validate_image(data: bytes, ext: str) -> None:
    if Image is None:
        raise HTTPException(503, 'Image validation is unavailable on this server')
    try:
        with Image.open(io.BytesIO(data)) as img:
            expected = {'.jpg': 'JPEG', '.jpeg': 'JPEG', '.png': 'PNG'}[ext]
            if img.format != expected:
                raise ValueError('image format mismatch')
            img.verify()
    except Exception:
        raise HTTPException(400, 'Upload rejected: invalid or malformed image')

@app.post('/api/prescriptions/upload')
@limiter.limit('10/minute')
async def upload(request: Request, file: UploadFile = File(...), u: User = Depends(current), d: Session = Depends(db)):
    original = clean_original_filename(file.filename)
    ext = Path(original).suffix.lower()
    allowed = {'.jpg', '.jpeg', '.png', '.pdf'}
    if ext not in allowed:
        raise HTTPException(400, 'Upload rejected: unsupported file type')
    if not file.content_type:
        raise HTTPException(400, 'Upload rejected: missing content type')
    data = await read_upload_limited(file, s.max_upload_mb * 1024 * 1024)
    if not data:
        raise HTTPException(400, 'Upload rejected: empty file')
    signatures = {'.jpg': b'\xff\xd8\xff', '.jpeg': b'\xff\xd8\xff', '.png': b'\x89PNG\r\n\x1a\n', '.pdf': b'%PDF-'}
    if not data.startswith(signatures[ext]):
        raise HTTPException(400, 'Upload rejected: content signature mismatch')
    expected_mimes = {'.jpg': {'image/jpeg'}, '.jpeg': {'image/jpeg'}, '.png': {'image/png'}, '.pdf': {'application/pdf'}}
    if file.content_type.lower() not in expected_mimes[ext]:
        raise HTTPException(400, 'Upload rejected: MIME/content mismatch')
    if ext == '.pdf':
        validate_pdf(data)
    else:
        validate_image(data, ext)
    sha = hashlib.sha256(data).hexdigest()
    safe = secrets.token_hex(16) + ext
    destination = (UPLOADS / safe).resolve()
    if destination.parent != UPLOADS.resolve():
        raise HTTPException(500, 'Upload storage error')
    destination.write_bytes(data)
    fields = extract_demo_fields(data, original)
    uncertain = any(x in original.lower() for x in ['blurry', 'uncertain', 'illegible', 'review'])
    medicine = fields.get('medicine', 'Demo medicine')
    strength = fields.get('strength', 'Dosage unclear' if uncertain else 'Not detected')
    frequency = fields.get('frequency', 'Uncertain' if uncertain else 'Not detected')
    timing = fields.get('timing', 'Uncertain' if uncertain else 'Not detected')
    duration = fields.get('duration', 'Uncertain' if uncertain else 'Not detected')
    verified = bool(fields.get('medicine') and fields.get('strength') and fields.get('frequency') and not uncertain)
    explanation = ('The prototype could not establish all fields confidently. Check the original prescription and consult a doctor or pharmacist.'
                   if not verified else f'This demo record lists {medicine} ({strength}) with the supplied frequency and timing. HealBridge does not change or recommend medication instructions.')
    p = Prescription(user_id=u.id, medicine=medicine, strength=strength, frequency=frequency, timing=timing,
                     duration=duration, explanation=explanation, verified=verified, original_filename=original,
                     stored_filename=safe, file_sha256=sha)
    d.add(p); d.commit(); d.refresh(p)
    audit(d, 'PRESCRIPTION_UPLOAD', f'Prescription {p.id}; SHA-256 {sha}', u, get_remote_address(request))
    return serialize_prescription(p)

@app.get('/api/prescriptions/{pid}')
def getp(pid: int, request: Request, u: User = Depends(current), d: Session = Depends(db)):
    p = d.get(Prescription, pid)
    if not p: raise HTTPException(404, 'Prescription not found')
    if p.user_id != u.id:
        audit(d, 'UNAUTHORIZED_ACCESS', f'Attempted prescription {pid}', u, get_remote_address(request))
        raise HTTPException(403, 'You do not have access to this prescription')
    audit(d, 'PRESCRIPTION_VIEW', f'Prescription {pid}', u, get_remote_address(request))
    return serialize_prescription(p)

@app.get('/api/prescriptions/{pid}/download')
def download(pid: int, request: Request, u: User = Depends(current), d: Session = Depends(db)):
    p = d.get(Prescription, pid)
    if not p: raise HTTPException(404, 'Prescription not found')
    if p.user_id != u.id:
        audit(d, 'UNAUTHORIZED_ACCESS', f'Download attempt {pid}', u, get_remote_address(request))
        raise HTTPException(403, 'You do not have access to this prescription')
    path = UPLOADS / (p.stored_filename or '')
    if not path.exists(): raise HTTPException(404, 'Original file is unavailable')
    audit(d, 'PRESCRIPTION_DOWNLOAD', f'Prescription {pid}', u, get_remote_address(request))
    return FileResponse(path, filename=p.original_filename or 'prescription')

@app.delete('/api/prescriptions/{pid}')
def deletep(pid: int, request: Request, u: User = Depends(current), d: Session = Depends(db)):
    p = d.get(Prescription, pid)
    if not p: raise HTTPException(404, 'Prescription not found')
    if p.user_id != u.id:
        audit(d, 'UNAUTHORIZED_ACCESS', f'Delete attempt {pid}', u, get_remote_address(request))
        raise HTTPException(403, 'You do not have access to this prescription')
    if p.stored_filename: (UPLOADS / p.stored_filename).unlink(missing_ok=True)
    d.delete(p); d.commit(); audit(d, 'PRESCRIPTION_DELETE', f'Prescription {pid}', u, get_remote_address(request))
    return {'message': 'Deleted'}

@app.get('/api/account/activity')
def activity(u: User = Depends(current), d: Session = Depends(db)):
    rows = d.scalars(select(Audit).where(Audit.user_id == u.id).order_by(Audit.created_at.desc()).limit(12))
    return [{'id': x.id, 'event': x.event, 'details': x.details, 'created_at': x.created_at} for x in rows]

@app.get('/api/admin/ping')
def admin_ping(u: User = Depends(admin)):
    return {'status': 'ok', 'role': u.role}

@app.get('/api/admin/audit-logs')
def logs(u: User = Depends(admin), d: Session = Depends(db)):
    rows = d.scalars(select(Audit).order_by(Audit.created_at.desc()).limit(200))
    return [{'id': x.id, 'user_id': x.user_id, 'event': x.event, 'details': x.details, 'ip': x.ip, 'created_at': x.created_at} for x in rows]

@app.get('/api/security/owasp')
def owasp(u: User = Depends(admin)):
    return {
        'A01': ('Broken Access Control', 'RBAC and server-side ownership checks'),
        'A02': ('Security Misconfiguration', 'Restricted CORS, security headers, safe errors'),
        'A03': ('Software Supply Chain Failures', 'Pinned minimal dependencies'),
        'A04': ('Cryptographic Failures', 'Argon2id password hashing and expiring signed tokens'),
        'A05': ('Injection', 'SQLAlchemy parameterized queries and validation'),
        'A06': ('Insecure Design', 'Least privilege, deny-by-default, uncertainty workflow'),
        'A07': ('Authentication Failures', 'Hashing, protected routes, expiry, rate limits'),
        'A08': ('Software/Data Integrity Failures', 'Magic-byte validation, safe filenames, SHA-256'),
        'A09': ('Security Logging & Alerting Failures', 'Authentication, upload, access and attack audit events'),
        'A10': ('Mishandling of Exceptional Conditions', 'Safe centralized error handling'),
    }
