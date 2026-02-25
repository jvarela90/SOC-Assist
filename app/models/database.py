"""
Database models for SOC Assist
Supports SQLite (default) and PostgreSQL via DATABASE_URL env var (#51).
"""
import json
import os
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Float,
    DateTime, Boolean, Text, ForeignKey, text
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import bcrypt as _bcrypt

# ── Database URL (#51) ────────────────────────────────────────────────────────
# Set DATABASE_URL env var to switch to PostgreSQL:
#   DATABASE_URL=postgresql://user:pass@host:5432/soc_assist
# Heroku-style postgres:// is automatically normalised to postgresql://
DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite:///./soc_assist.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

_is_sqlite = DATABASE_URL.startswith("sqlite")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Incident(Base):
    __tablename__ = "incidents"

    id             = Column(Integer, primary_key=True, index=True)
    timestamp      = Column(DateTime, default=datetime.utcnow, nullable=False)
    base_score     = Column(Float, default=0.0)
    final_score    = Column(Float, default=0.0)
    multiplier     = Column(Float, default=1.0)
    classification = Column(String(50), nullable=False)
    hard_rule_id   = Column(String(100), nullable=True)
    resolution     = Column(String(50), nullable=True)   # fp / tp_resolved / tp_escalated / ongoing
    analyst_notes  = Column(Text, nullable=True)
    escalated      = Column(Boolean, default=False)
    analyst_name   = Column(String(100), nullable=True)
    assigned_to     = Column(String(100), nullable=True)   # assigned analyst username (#46)
    network_context = Column(Text, nullable=True)           # JSON: {ip_src, ip_dst, direction, url, mac, ti_summary}
    ti_enrichment   = Column(Text, nullable=True)           # JSON: full TI lookup results
    ti_adjusted     = Column(Boolean, default=False)        # True if analyst applied TI score adjustment

    answers        = relationship("IncidentAnswer",  back_populates="incident", cascade="all, delete-orphan")
    comments       = relationship("IncidentComment", back_populates="incident", cascade="all, delete-orphan",
                                  order_by="IncidentComment.created_at")


class IncidentAnswer(Base):
    __tablename__ = "incident_answers"

    id              = Column(Integer, primary_key=True, index=True)
    incident_id     = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    question_id     = Column(String(20), nullable=False)
    module          = Column(String(50), nullable=False)
    value           = Column(String(100), nullable=False)
    raw_score       = Column(Float, default=0.0)
    contribution    = Column(Float, default=0.0)

    incident        = relationship("Incident", back_populates="answers")


class IncidentComment(Base):
    """Collaborative analyst comments per incident (#45)."""
    __tablename__ = "incident_comments"

    id          = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    author      = Column(String(100), nullable=False)
    text        = Column(Text, nullable=False)
    created_at  = Column(DateTime, default=datetime.utcnow)

    incident    = relationship("Incident", back_populates="comments")


class AuditLog(Base):
    """Admin action audit trail (#54)."""
    __tablename__ = "audit_log"

    id         = Column(Integer, primary_key=True, index=True)
    timestamp  = Column(DateTime, default=datetime.utcnow, nullable=False)
    username   = Column(String(100), nullable=False)
    action     = Column(String(200), nullable=False)
    target     = Column(String(200), nullable=True)   # e.g. "incident/42", "user/3"
    details    = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)


class WeightHistory(Base):
    __tablename__ = "weight_history"

    id           = Column(Integer, primary_key=True, index=True)
    adjusted_at  = Column(DateTime, default=datetime.utcnow)
    question_id  = Column(String(20), nullable=True)
    module       = Column(String(50), nullable=True)
    change_type  = Column(String(50), nullable=False)   # question_weight / module_weight / threshold
    old_value    = Column(Float, nullable=False)
    new_value    = Column(Float, nullable=False)
    reason       = Column(String(200), nullable=True)


class CalibrationLog(Base):
    __tablename__ = "calibration_logs"

    id               = Column(Integer, primary_key=True, index=True)
    run_at           = Column(DateTime, default=datetime.utcnow)
    total_incidents  = Column(Integer, default=0)
    true_positives   = Column(Integer, default=0)
    false_positives  = Column(Integer, default=0)
    false_negatives  = Column(Integer, default=0)
    adjustments_made = Column(Integer, default=0)
    notes            = Column(Text, nullable=True)


class User(Base):
    __tablename__ = "users"

    id                  = Column(Integer, primary_key=True, index=True)
    username            = Column(String(50), unique=True, nullable=False, index=True)
    password_hash       = Column(String(200), nullable=False)
    role                = Column(String(20), nullable=False, default="analyst")  # analyst | admin
    is_active           = Column(Boolean, default=True)
    created_at          = Column(DateTime, default=datetime.utcnow)
    last_login          = Column(DateTime, nullable=True)
    # Traceability fields
    login_count         = Column(Integer, default=0)              # total successful logins
    password_changed_at = Column(DateTime, nullable=True)         # last password change timestamp
    notes               = Column(Text, nullable=True)             # admin notes about this user
    # Recovery code (single-use, stored as bcrypt hash)
    recovery_code_hash  = Column(String(200), nullable=True)
    recovery_set_at     = Column(DateTime, nullable=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    _run_migrations()
    _ensure_default_admin()


def _run_migrations():
    """Add new columns to existing tables without dropping data (SQLite ALTER TABLE)."""
    if not _is_sqlite:
        return  # PostgreSQL handles schema via create_all
    _new_cols = [
        ("incidents", "network_context",   "TEXT"),
        ("incidents", "ti_enrichment",     "TEXT"),
        ("incidents", "ti_adjusted",       "BOOLEAN DEFAULT 0"),
        # User traceability
        ("users", "login_count",           "INTEGER DEFAULT 0"),
        ("users", "password_changed_at",   "TIMESTAMP"),
        ("users", "notes",                 "TEXT"),
        ("users", "recovery_code_hash",    "VARCHAR(200)"),
        ("users", "recovery_set_at",       "TIMESTAMP"),
    ]
    with engine.connect() as conn:
        for table, col, ddl in _new_cols:
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"))
                conn.commit()
            except Exception:
                pass  # Column already exists — safe to ignore


def _ensure_default_admin():
    """Create default admin/admin123 on first run if no users exist."""
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            db.add(User(
                username="admin",
                password_hash=_bcrypt.hashpw(b"admin123", _bcrypt.gensalt()).decode(),
                role="admin",
            ))
            db.commit()
    finally:
        db.close()


def audit(db, username: str, action: str, target: str = None,
          details: str = None, ip: str = None):
    """Helper to write an audit log entry."""
    db.add(AuditLog(
        username=username,
        action=action,
        target=target,
        details=details,
        ip_address=ip,
    ))
