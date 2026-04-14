"""
Alert management – CRUD helpers and severity statistics.
"""
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from database import Alert


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def create_alert(db: Session, alert_data: dict, log_event_id: int | None = None) -> Alert:
    alert = Alert(
        severity=alert_data.get("severity", "low"),
        rule_name=alert_data.get("rule_name", "Unknown Rule"),
        description=alert_data.get("description", ""),
        event_id=alert_data.get("event_id"),
        log_event_id=log_event_id,
        mitre_tactic=alert_data.get("mitre_tactic"),
        mitre_technique=alert_data.get("mitre_technique"),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def get_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    severity: str | None = None,
    rule_name: str | None = None,
) -> list[Alert]:
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if rule_name:
        query = query.filter(Alert.rule_name.ilike(f"%{rule_name}%"))
    return query.order_by(desc(Alert.timestamp)).offset(skip).limit(limit).all()


def get_alert_by_id(db: Session, alert_id: int) -> Alert | None:
    return db.query(Alert).filter(Alert.id == alert_id).first()


def delete_alert(db: Session, alert_id: int) -> bool:
    alert = get_alert_by_id(db, alert_id)
    if not alert:
        return False
    db.delete(alert)
    db.commit()
    return True


def get_severity_counts(db: Session) -> dict:
    rows = (
        db.query(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
        .all()
    )
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for severity, count in rows:
        counts[severity] = count
    return counts


def get_recent_alerts(db: Session, limit: int = 10) -> list[Alert]:
    return (
        db.query(Alert)
        .order_by(desc(Alert.timestamp))
        .limit(limit)
        .all()
    )
