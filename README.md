# HealBridge — Secure Prescription Assistant

A security-focused web application prototype for authenticated prescription
document management, designed as part of a Web Application and Defenses project.

HealBridge combines a modern web interface with a FastAPI backend and applies
multiple defensive security controls inspired by the OWASP Top 10.

---

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


## Project Overview

Prescription documents can contain medicine names, strengths, frequencies,
timings and durations that may be difficult for users to interpret.

HealBridge provides an authenticated workspace where users can:

- Create an account
- Securely sign in
- Upload prescription documents
- Review uploaded prescriptions
- Manage their own prescription records
- Access protected resources
- Receive verification-oriented handling when information is uncertain

The system is designed as an academic security prototype and does not replace
medical professionals or provide clinical diagnosis.

---

## Key Features

### Authentication

- Secure user registration
- Password hashing
- Password policy enforcement
- JWT-based authentication
- Token expiration
- Logout/token revocation
- Protected API endpoints

### Authorization

- Patient/admin role separation
- Server-side authorization
- Prescription ownership verification
- IDOR protection
- Protected administrative functionality

### Secure File Upload

- File extension allow-listing
- MIME/type validation
- File signature/parser validation
- Maximum upload size
- Resource limits
- Safe generated filenames
- Private file storage
- File integrity hashing

### Backend Security

- Trusted host validation
- Restrictive CORS
- Origin validation
- Security response headers
- Rate limiting
- Request IDs
- Controlled error responses
- Audit logging

### Safety-Oriented Handling

HealBridge is designed to avoid confidently guessing when prescription
information is unclear or incomplete.

Instead, uncertain information should lead to verification.

---

## OWASP-Oriented Security

| OWASP Area | HealBridge Defense |
|---|---|
| Broken Access Control | RBAC + ownership checks |
| Security Misconfiguration | Security headers + trusted hosts + CORS |
| Supply Chain Risks | Dependency management |
| Cryptographic Failures | Password hashing + signed/expiring tokens |
| Injection | Input validation + parameterized database access |
| Insecure Design | Defense-in-depth architecture |
| Authentication Failures | Password policy + JWT expiry + revocation + rate limiting |
| Software/Data Integrity | File validation + private storage + hashing |
| Logging & Monitoring | Audit logging + request IDs |
| Exceptional Conditions | Validation + controlled errors + resource limits |

---

## Architecture

```text
                   ┌──────────────────────┐
                   │    React Frontend    │
                   │                      │
                   │ Login / Dashboard    │
                   │ Upload / Prescriptions│
                   └──────────┬───────────┘
                              │
                              ▼
                   ┌──────────────────────┐
                   │    FastAPI Backend   │
                   │                      │
                   │ Authentication       │
                   │ Authorization        │
                   │ Validation           │
                   │ Upload Security      │
                   │ Rate Limiting        │
                   │ Audit Logging        │
                   └───────┬───────┬──────┘
                           │       │
                ┌──────────▼───┐ ┌─▼──────────────┐
                │   Database   │ │ Private File   │
                │              │ │   Storage      │
                │ Users        │ │                │
                │ Prescriptions│ │ Validated docs │
                │ Audit data   │ │                │
                └──────────────┘ └────────────────┘
