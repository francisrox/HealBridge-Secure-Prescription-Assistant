# HealBridge Final Implementation

This package is the consolidated final implementation after Phases 1–5.

## Start backend (Windows PowerShell)

```powershell
cd healbridge
python -m venv backend\.venv
.\backend\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r backend\requirements.txt
uvicorn backend.main:app --reload
```

Backend: `http://127.0.0.1:8000`
Swagger: `http://127.0.0.1:8000/docs`

## Start frontend

In another PowerShell:

```powershell
cd healbridge\frontend
npm install
npm run dev
```

Open the Vite URL, normally `http://localhost:5173`.

## Run regression tests

```powershell
python backend\test_phase1.py
python backend\test_phase2.py
python backend\test_phase3.py
python backend\test_phase4.py
```

## Important

- Use a strong development `SECRET_KEY` in `backend/.env`.
- Never expose public ADMIN registration.
- Use fictional test documents only.
- The prototype does not diagnose, prescribe or change medication instructions.
- Runtime test output should be captured on the target Windows machine for the final assignment evidence.
