from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./siem_lite.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String(255))
    channel = Column(String(255))
    computer = Column(String(255))
    user = Column(String(255), nullable=True)
    process_name = Column(String(512), nullable=True)
    command_line = Column(Text, nullable=True)
    raw_xml = Column(Text, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    severity = Column(String(20))   # low | medium | high | critical
    rule_name = Column(String(255))
    description = Column(Text)
    event_id = Column(Integer, nullable=True)
    log_event_id = Column(Integer, nullable=True)
    mitre_tactic = Column(String(255), nullable=True)
    mitre_technique = Column(String(50), nullable=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
