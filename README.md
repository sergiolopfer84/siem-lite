# ThreatScope

A lightweight **Security Information and Event Management (SIEM)** system for analysing Windows Event Logs (`.evtx` files) — built to learn how Blue Team tools work from the inside.

> Applies the same detection principles used by professional SIEMs (Splunk, Microsoft Sentinel, IBM QRadar) at a didactic scale.

---

## Overview

ThreatScope ingests Windows event logs, parses every event, evaluates them against detection rules mapped to **MITRE ATT&CK**, correlates multi-step attack sequences, persists findings in a local SQLite database, and presents them through a clean React dashboard.

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
| EVTX ingestion | Upload `.evtx` files via the web UI or REST API |
| Detection rules | 12 rules covering Sysmon, Windows Security, and PowerShell logs |
| Event correlation | 4 multi-step attack scenarios with configurable time windows |
| MITRE ATT&CK mapping | Every rule maps to a tactic and technique ID |
| REST API | FastAPI with automatic OpenAPI docs at `/docs` |
| Dashboard | Live stats, severity breakdown, recent alerts |
| Pagination | Event browser with server-side pagination |

---

## Supported Log Sources

| Source | Channel (.evtx) | What it monitors |
|---|---|---|
| Sysmon | Microsoft-Windows-Sysmon/Operational | Processes, network, injection, ADS, LSASS access |
| Windows Security | Security | Logons, user creation, privileges, scheduled tasks |
| PowerShell | Microsoft-Windows-PowerShell/Operational | Script blocks, downloads, obfuscation |

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
| POST | `/api/upload` | Upload a `.evtx` file |
| GET | `/api/events` | List parsed log events (paginated) |
| GET | `/api/alerts` | List alerts (filterable by severity) |
| DELETE | `/api/alerts/{id}` | Delete a specific alert |
| GET | `/api/stats` | Dashboard statistics |

---

## Detection Rules

| Rule | Severity | Tactic | Technique | Source |
|---|---|---|---|---|
| Obfuscated PowerShell (Process) | High | Execution | T1059.001 | Sysmon |
| LSASS Memory Access | Critical | Credential Access | T1003.001 | Sysmon |
| Remote Thread Injection | High | Defense Evasion | T1055.003 | Sysmon |
| Suspicious Outbound Network Connection | Medium | Command & Control | T1071 | Sysmon |
| Alternate Data Stream Created | Medium | Defense Evasion | T1564.004 | Sysmon |
| Failed Logon | Medium | Credential Access | T1110 | Security |
| Explicit Credentials Used (4648) | High | Lateral Movement | T1550.002 | Security |
| Sensitive Privilege Assigned | High | Privilege Escalation | T1134 | Security |
| New User Account Created | High | Persistence | T1136.001 | Security |
| Scheduled Task Created | Medium | Persistence | T1053.005 | Security |
| Suspicious Script Block (4104) | High | Execution | T1059.001 | PowerShell |
| PowerShell Download (4103) | High | Command & Control | T1105 | PowerShell |

---

## Correlation Scenarios

Multi-step attack detection evaluates sequences of events within a 5-minute window.

| Scenario | Severity | Pattern |
|---|---|---|
| Recon → Execution | High | DNS query (Sysmon ID 22) → PowerShell spawn (Sysmon ID 1) |
| Lateral Movement | Critical | Network connection (Sysmon ID 3) → CreateRemoteThread (Sysmon ID 8) |
| Brute Force | Critical | 5+ failed logons (Security ID 4625) |
| Privilege Escalation after Failure | Critical | Failed logon (Security ID 4625) → Sensitive privileges assigned (Security ID 4672) |

---

## Practice Logs

No Windows machine? You can use `.evtx` samples from these platforms:

- [BOTS — Splunk](https://www.splunk.com/en_us/blog/security/botsv3-dataset-release.html)
- [Blue Team Labs Online](https://blueteamlabs.online/)
- [CyberDefenders](https://cyberdefenders.org/)

---

## Tech Stack

- **Backend**: Python 3.11+, FastAPI, SQLAlchemy, python-evtx, SQLite
- **Frontend**: React 18, Vite 5, TailwindCSS 3

---

## About

ThreatScope was built to understand how SIEMs work from first principles — parsing raw logs, writing detection logic, and correlating multi-event attack patterns. It's useful as a learning tool, a CTF companion, or a portfolio project for Blue Team and SOC analyst roles.
