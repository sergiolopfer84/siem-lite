"""
SIEM-Lite – FastAPI backend entry point.

Run:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""
import os
import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

import database as db_module
from database import get_db, LogEvent
import alerts as alert_mgr
import correlator
from parser import parse_evtx_file
from rules import evaluate

app = FastAPI(
    title="SIEM-Lite",
    description="Lightweight SIEM for Sysmon log analysis",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    db_module.init_db()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Log ingestion
# ---------------------------------------------------------------------------

@app.post("/api/upload", tags=["logs"])
async def upload_evtx(
    file: Annotated[UploadFile, File(description="Sysmon .evtx log file")],
    db: Session = Depends(get_db),
):
    """
    Upload a Sysmon .evtx file. Events are parsed, stored, and evaluated
    against detection rules. Correlation is run after ingestion.
    """
    if not file.filename.endswith(".evtx"):
        raise HTTPException(status_code=400, detail="Only .evtx files are accepted.")

    contents = await file.read()

    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    events_added = 0
    alerts_triggered = []

    try:
        for event in parse_evtx_file(tmp_path):
            log_event = LogEvent(
                event_id=event.get("event_id"),
                source=event.get("source"),
                channel=event.get("channel"),
                computer=event.get("computer"),
                user=event.get("user"),
                process_name=event.get("process_name"),
                command_line=event.get("command_line"),
                raw_xml=event.get("raw_xml"),
            )
            db.add(log_event)
            db.flush()

            for alert_data in evaluate(event):
                alert_mgr.create_alert(db, alert_data, log_event_id=log_event.id)
                alerts_triggered.append(alert_data["rule_name"])

            events_added += 1

        db.commit()
        correlator.run_all_correlations(db)
    finally:
        os.unlink(tmp_path)

    return {
        "events_parsed": events_added,
        "alerts_triggered": len(alerts_triggered),
        "alert_rules": list(set(alerts_triggered)),
    }


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@app.get("/api/events", tags=["logs"])
def list_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    event_id: int | None = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(LogEvent)
    if event_id is not None:
        query = query.filter(LogEvent.event_id == event_id)
    total = query.count()
    events = query.order_by(LogEvent.timestamp.desc()).offset(skip).limit(limit).all()
    return {
        "total": total,
        "items": [
            {
                "id": e.id,
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "source": e.source,
                "computer": e.computer,
                "user": e.user,
                "process_name": e.process_name,
                "command_line": e.command_line,
            }
            for e in events
        ],
    }


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@app.get("/api/alerts", tags=["alerts"])
def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    db: Session = Depends(get_db),
):
    items = alert_mgr.get_alerts(db, skip=skip, limit=limit, severity=severity)
    return {
        "total": len(items),
        "items": [
            {
                "id": a.id,
                "timestamp": a.timestamp,
                "severity": a.severity,
                "rule_name": a.rule_name,
                "description": a.description,
                "mitre_tactic": a.mitre_tactic,
                "mitre_technique": a.mitre_technique,
            }
            for a in items
        ],
    }


@app.delete("/api/alerts/{alert_id}", tags=["alerts"])
def delete_alert(alert_id: int, db: Session = Depends(get_db)):
    deleted = alert_mgr.delete_alert(db, alert_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Dashboard statistics
# ---------------------------------------------------------------------------

@app.get("/api/stats", tags=["dashboard"])
def get_stats(db: Session = Depends(get_db)):
    severity_counts = alert_mgr.get_severity_counts(db)
    recent = alert_mgr.get_recent_alerts(db, limit=5)
    total_events = db.query(LogEvent).count()
    total_alerts = sum(severity_counts.values())
    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "severity_counts": severity_counts,
        "recent_alerts": [
            {
                "id": a.id,
                "timestamp": a.timestamp,
                "severity": a.severity,
                "rule_name": a.rule_name,
            }
            for a in recent
        ],
    }
