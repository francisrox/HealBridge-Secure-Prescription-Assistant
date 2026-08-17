# HealBridge Final Classroom Demo Script

Recommended length: 7–10 minutes.

## 1. Introduction — 30 seconds

Say:
> HealBridge is an academic secure web application for explaining fictional prescription information. Its main focus is secure authentication, controlled document handling, uncertainty handling, and OWASP-oriented defenses.

## 2. Register and login — 1 minute

- Open the application.
- Register a demo patient.
- Use a strong password such as `HealBridge123`.
- Sign in.
- Point out that the workspace is protected and the role is shown in the profile area.

## 3. Upload — 1 minute

- Open Secure Upload.
- Select one fictional PDF.
- Point out the server-side validation message and secure storage explanation.
- Upload the file.

## 4. Verification result — 1 minute

- Open the generated record.
- Show medicine, strength, frequency, timing and duration.
- Show the verification badge.
- Explain that the prototype does not prescribe or change medication instructions.

## 5. Vault — 45 seconds

- Open Prescription Vault.
- Search by medicine.
- Filter by Verified / Needs review.
- Open another record.

## 6. Uncertainty safety case — 1 minute

- Upload an intentionally uncertain/incomplete fictional sample.
- Show `Verification required`.
- Explain that uncertain information is not silently presented as reliable.

## 7. Security Center — 1–2 minutes

For an ADMIN account:
- Open Security Center.
- Show OWASP control cards.
- Show audit events.
- Export the audit CSV.

## 8. Security evidence — 1–2 minutes

Show selected test evidence:
- Unauthenticated endpoint → 401.
- Cross-user prescription → 403.
- Invalid file → rejected.
- SQL injection attempt → no authentication bypass.
- Rate limit → 429.

## Closing

Say:
> The prototype demonstrates security controls and testing evidence rather than claiming to be a production medical system. Its purpose is to show how web application defenses can be designed, implemented and tested around a realistic document workflow.
