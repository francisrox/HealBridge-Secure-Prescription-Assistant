# HealBridge Architecture

## High-level flow

```text
Browser / React UI
        |
        | HTTP + Bearer authentication
        v
FastAPI application
        |
        +--> Authentication / RBAC
        +--> Prescription API
        +--> Upload validation
        +--> Audit logging
        +--> OWASP Security Center
        |
        v
SQLite database       Private uploads directory
```

## Main layers

### Frontend
React + React Router. Responsibilities:
- Authentication screens
- Dashboard
- Prescription vault
- Secure upload UI
- Prescription detail page
- Admin Security Center
- Theme persistence

### Backend
FastAPI. Responsibilities:
- Authentication and authorization
- Password hashing
- Token validation/revocation
- Prescription ownership checks
- Upload validation
- Structured demo extraction
- Audit logging
- Rate limiting
- Security response handling

### Database
SQLite is used for the MVP. It stores users, prescriptions, audit records and revoked token identifiers.

### File storage
Accepted files are stored outside the public frontend directory using generated server-side filenames. The database retains the original display filename and SHA-256 fingerprint.

## Trust boundaries

1. Browser → API: untrusted client input.
2. Upload → validation: file extension, MIME and content signature are checked server-side.
3. User → prescription: every record operation performs an ownership check.
4. User → admin functions: ADMIN role is enforced server-side.
5. Database/files → UI: only authorized API responses are exposed.
