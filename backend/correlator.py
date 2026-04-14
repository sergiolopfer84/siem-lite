"""
Event correlator – detects multi-step attack patterns by analysing sequences
of events stored in the database within a configurable time window.
"""
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_

from database import LogEvent, Alert
import alerts as alert_mgr


# Time window used for sequence correlation (minutes)
CORRELATION_WINDOW_MINUTES = 5


def _events_in_window(db: Session, minutes: int = CORRELATION_WINDOW_MINUTES) -> list[LogEvent]:
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    return db.query(LogEvent).filter(LogEvent.timestamp >= cutoff).all()


def _find_by_event_id(events: list[LogEvent], event_id: int) -> list[LogEvent]:
    return [e for e in events if e.event_id == event_id]


# ---------------------------------------------------------------------------
# Correlation scenarios
# ---------------------------------------------------------------------------

def correlate_recon_then_execution(db: Session) -> list[dict]:
    """
    Scenario: PowerShell spawned shortly after a suspicious DNS query (recon → exec).
    Sysmon IDs: 22 (DNS) → 1 (ProcessCreate with PowerShell)
    """
    alerts_generated = []
    recent = _events_in_window(db)

    dns_events = _find_by_event_id(recent, 22)
    proc_events = _find_by_event_id(recent, 1)

    powershell_procs = [
        e for e in proc_events
        if e.process_name and "powershell" in e.process_name.lower()
    ]

    if dns_events and powershell_procs:
        alert_data = {
            "severity": "high",
            "rule_name": "Recon followed by PowerShell Execution",
            "description": (
                f"DNS recon ({len(dns_events)} queries) followed by PowerShell execution "
                f"within {CORRELATION_WINDOW_MINUTES} minutes."
            ),
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059.001",
        }
        alert_mgr.create_alert(db, alert_data)
        alerts_generated.append(alert_data)

    return alerts_generated


def correlate_lateral_movement(db: Session) -> list[dict]:
    """
    Scenario: Network connection followed by CreateRemoteThread (lateral movement attempt).
    Sysmon IDs: 3 (Network) → 8 (CreateRemoteThread)
    """
    alerts_generated = []
    recent = _events_in_window(db)

    net_events = _find_by_event_id(recent, 3)
    crt_events = _find_by_event_id(recent, 8)

    if net_events and crt_events:
        alert_data = {
            "severity": "critical",
            "rule_name": "Possible Lateral Movement",
            "description": (
                "Outbound network connection followed by remote thread injection "
                f"within {CORRELATION_WINDOW_MINUTES} minutes."
            ),
            "mitre_tactic": "Lateral Movement",
            "mitre_technique": "T1021",
        }
        alert_mgr.create_alert(db, alert_data)
        alerts_generated.append(alert_data)

    return alerts_generated


def run_all_correlations(db: Session) -> list[dict]:
    """Run every correlation scenario and return all generated alerts."""
    results = []
    results.extend(correlate_recon_then_execution(db))
    results.extend(correlate_lateral_movement(db))
    return results
