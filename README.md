# SIEM-Lite

A lightweight Security Information and Event Management (SIEM) system designed for analysing **Sysmon** Windows Event Logs (`.evtx` files).

---

## Overview

SIEM-Lite ingests Sysmon logs, parses every event, evaluates them against a set of detection rules, persists findings in a local SQLite database, and presents them through a clean React dashboard.

```
siem-lite/
├── backend/
│   ├── main.py        # FastAPI application & REST endpoints
│   ├── parser.py      # EVTX file parser (python-evtx)
│   ├── rules.py       # Detection rules engine
│   ├── alerts.py      # Alert CRUD helpers
│   ├── correlator.py  # Multi-event correlation scenarios
│   └── database.py    # SQLAlchemy models & DB initialisation
├── frontend/          # React + Vite + TailwindCSS SPA
├── requirements.txt
└── README.md
```

---

## Features

| Feature | Details |
|---|---|
| EVTX ingestion | Upload Sysmon `.evtx` files via the web UI or REST API |
| Detection rules | PowerShell obfuscation, LSASS access, remote thread injection, suspicious network connections, ADS creation |
| Event correlation | Recon→Execution and Lateral Movement multi-step scenarios |
| MITRE ATT&CK mapping | Each rule maps to a tactic and technique ID |
| REST API | FastAPI with automatic OpenAPI docs at `/docs` |
| Dashboard | Live stats, severity breakdown, recent alerts |
| Pagination | Event browser with server-side pagination |

---

## Quick Start

### Backend

```bash
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the API server
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API docs available at: `http://localhost:8000/docs`

### Frontend

```bash
cd frontend
npm install
npm run dev
```

UI available at: `http://localhost:5173`

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/api/upload` | Upload a Sysmon `.evtx` file |
| GET | `/api/events` | List parsed log events (paginated) |
| GET | `/api/alerts` | List alerts (filterable by severity) |
| DELETE | `/api/alerts/{id}` | Delete a specific alert |
| GET | `/api/stats` | Dashboard statistics |

---

## Detection Rules

| Rule | Severity | MITRE Technique |
|---|---|---|
| Suspicious PowerShell Execution | High | T1059.001 |
| LSASS Memory Access | Critical | T1003.001 |
| Remote Thread Injection | High | T1055.003 |
| Suspicious Outbound Network Connection | Medium | T1071 |
| Alternate Data Stream Created | Medium | T1564.004 |

---

## Correlation Scenarios

- **Recon → Execution**: DNS query (Event ID 22) followed by PowerShell (Event ID 1) within 5 minutes.
- **Lateral Movement**: Network connection (Event ID 3) followed by CreateRemoteThread (Event ID 8) within 5 minutes.

---

## Tech Stack

- **Backend**: Python 3.11+, FastAPI, SQLAlchemy, python-evtx, SQLite
- **Frontend**: React 18, Vite 5, TailwindCSS 3
