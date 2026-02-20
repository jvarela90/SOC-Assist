"""
Database models for SOC Assist
"""
import json
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Float,
    DateTime, Boolean, Text, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = "sqlite:///./soc_assist.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
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

    answers        = relationship("IncidentAnswer", back_populates="incident", cascade="all, delete-orphan")


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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
