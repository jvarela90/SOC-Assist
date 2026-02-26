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


# ── Multi-Tenant: Organizations ───────────────────────────────────────────────

class Organization(Base):
    """
    Hierarchical organization model.
    org_type: central | regional | provincial | local | flat | shift
      - central:    Sede/Sucursal Central (root, único)
      - regional:   Sede Regional (SUR, CENTRO, NORTE…)
      - provincial: Sede Provincial (agrupa locales)
      - local:      Mini-sede / sede local
      - flat:       Organización sin jerarquía (único nivel)
      - shift:      Organización gestionada por turnos
    """
    __tablename__ = "organizations"

    id         = Column(Integer, primary_key=True, index=True)
    name       = Column(String(200), nullable=False)
    slug       = Column(String(100), unique=True, nullable=False, index=True)
    org_type   = Column(String(20), default="flat")
    parent_id  = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    is_active  = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    settings   = Column(Text, nullable=True)   # JSON: overrides (webhooks, etc.)
    description = Column(Text, nullable=True)

    # Self-referential hierarchy
    parent   = relationship("Organization", remote_side=[id], back_populates="children")
    children = relationship("Organization", back_populates="parent")

    users    = relationship("User",     back_populates="organization")
    incidents = relationship("Incident", back_populates="organization")
    assets   = relationship("Asset",    back_populates="organization")
    notifications = relationship("Notification", back_populates="organization")


# ── Asset Inventory (CMDB) ───────────────────────────────────────────────────

class Asset(Base):
    """
    Inventario de activos de la organización.
    Permite enriquecer el scoring de incidentes con contexto de criticidad.
    Criticality: 1=Mínimo, 2=Bajo, 3=Medio, 4=Alto, 5=Crítico
    Score multipliers applied to incidents matching this asset:
      5 → ×1.5  (incidente involucra activo crítico → más urgente)
      4 → ×1.3
      3 → ×1.1
      2 → ×0.9  (activo conocido/rutinario → levemente menos urgente)
      1 → ×0.8  (activo de muy bajo impacto → puede tratarse como rutina)
    """
    __tablename__ = "assets"

    id              = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name            = Column(String(200), nullable=False)
    asset_type      = Column(String(50), nullable=False)
    # asset_type values: ip | hostname | server | service | network_segment
    #                    user_account | critical_user | other
    identifier      = Column(String(500), nullable=False)   # IP, CIDR, hostname, username…
    criticality     = Column(Integer, default=3)            # 1–5
    description     = Column(Text, nullable=True)
    is_active       = Column(Boolean, default=True)
    tags            = Column(Text, nullable=True)           # JSON list of strings
    extra_data      = Column(Text, nullable=True)           # JSON misc metadata
    review_cycle    = Column(Integer, default=6)            # months: 3 or 6
    last_reviewed_at = Column(DateTime, nullable=True)
    next_review_at  = Column(DateTime, nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)
    updated_at      = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="assets")
    contacts     = relationship("AssetContact",  back_populates="asset", cascade="all, delete-orphan")
    locations    = relationship("AssetLocation", back_populates="asset", cascade="all, delete-orphan")
    incidents    = relationship("Incident",      back_populates="asset")
    notifications = relationship("Notification", back_populates="asset")


class AssetContact(Base):
    """Responsible person(s) for an asset."""
    __tablename__ = "asset_contacts"

    id              = Column(Integer, primary_key=True, index=True)
    asset_id        = Column(Integer, ForeignKey("assets.id"), nullable=False)
    contact_type    = Column(String(30), default="responsible")
    # contact_type: responsible | admin_user | backup | escalation
    name            = Column(String(200), nullable=False)
    email           = Column(String(200), nullable=True)
    phone_personal  = Column(String(50), nullable=True)
    phone_corporate = Column(String(50), nullable=True)
    notes           = Column(Text, nullable=True)

    asset = relationship("Asset", back_populates="contacts")


class AssetLocation(Base):
    """Physical or logical location(s) for an asset."""
    __tablename__ = "asset_locations"

    id       = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    label    = Column(String(200), nullable=False)   # "Sede Central — Rack 3, U12"
    address  = Column(Text, nullable=True)           # dirección física opcional

    asset = relationship("Asset", back_populates="locations")


# ── In-App Notifications ──────────────────────────────────────────────────────

class Notification(Base):
    """
    In-app notifications for asset review reminders and other alerts.
    Shown on the home page (/) when user logs in.
    """
    __tablename__ = "notifications"

    id              = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    user_id         = Column(Integer, ForeignKey("users.id"), nullable=True)
    # user_id=None means shown to all admins/analysts of the org
    notif_type      = Column(String(50), nullable=False)
    # notif_type: asset_review_due | asset_review_overdue | asset_review_upcoming
    #             incident_critical | system
    title           = Column(String(300), nullable=False)
    body            = Column(Text, nullable=True)
    asset_id        = Column(Integer, ForeignKey("assets.id"), nullable=True)
    is_read         = Column(Boolean, default=False)
    created_at      = Column(DateTime, default=datetime.utcnow)
    expires_at      = Column(DateTime, nullable=True)

    organization = relationship("Organization", back_populates="notifications")
    asset        = relationship("Asset", back_populates="notifications")


# ── Core Models ───────────────────────────────────────────────────────────────

class Incident(Base):
    __tablename__ = "incidents"

    id             = Column(Integer, primary_key=True, index=True)
    timestamp      = Column(DateTime, default=datetime.utcnow, nullable=False)
    base_score     = Column(Float, default=0.0)
    final_score    = Column(Float, default=0.0)
    multiplier     = Column(Float, default=1.0)
    classification = Column(String(50), nullable=False)
    hard_rule_id   = Column(String(100), nullable=True)
    resolution     = Column(String(50), nullable=True)
    analyst_notes  = Column(Text, nullable=True)
    escalated      = Column(Boolean, default=False)
    analyst_name   = Column(String(100), nullable=True)
    assigned_to    = Column(String(100), nullable=True)
    network_context = Column(Text, nullable=True)
    ti_enrichment   = Column(Text, nullable=True)
    ti_adjusted     = Column(Boolean, default=False)
    # Multi-tenant
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    # Asset linkage
    asset_id                 = Column(Integer, ForeignKey("assets.id"), nullable=True)
    asset_criticality_applied = Column(Boolean, default=False)
    # SLA + tagging (Fase 10)
    resolved_at = Column(DateTime, nullable=True)   # set when resolution is first assigned
    tags        = Column(Text, nullable=True)        # JSON list of free-form tag strings

    answers      = relationship("IncidentAnswer",      back_populates="incident", cascade="all, delete-orphan")
    comments     = relationship("IncidentComment",     back_populates="incident", cascade="all, delete-orphan",
                                order_by="IncidentComment.created_at")
    attachments  = relationship("IncidentAttachment",  back_populates="incident", cascade="all, delete-orphan",
                                order_by="IncidentAttachment.created_at")
    organization = relationship("Organization", back_populates="incidents")
    asset        = relationship("Asset", back_populates="incidents")


class IncidentAnswer(Base):
    __tablename__ = "incident_answers"

    id           = Column(Integer, primary_key=True, index=True)
    incident_id  = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    question_id  = Column(String(20), nullable=False)
    module       = Column(String(50), nullable=False)
    value        = Column(String(100), nullable=False)
    raw_score    = Column(Float, default=0.0)
    contribution = Column(Float, default=0.0)

    incident = relationship("Incident", back_populates="answers")


class IncidentComment(Base):
    __tablename__ = "incident_comments"

    id          = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    author      = Column(String(100), nullable=False)
    text        = Column(Text, nullable=False)
    created_at  = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="comments")


class IncidentAttachment(Base):
    """Evidence files attached to an incident (#48)."""
    __tablename__ = "incident_attachments"

    id          = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    uploaded_by = Column(String(100), nullable=False)
    filename    = Column(String(300), nullable=False)    # original display name
    stored_name = Column(String(300), nullable=False)    # UUID-based on-disk name
    file_size   = Column(Integer, nullable=False)        # bytes
    mime_type   = Column(String(100), nullable=True)
    description = Column(String(500), nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="attachments")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id              = Column(Integer, primary_key=True, index=True)
    timestamp       = Column(DateTime, default=datetime.utcnow, nullable=False)
    username        = Column(String(100), nullable=False)
    action          = Column(String(200), nullable=False)
    target          = Column(String(200), nullable=True)
    details         = Column(Text, nullable=True)
    ip_address      = Column(String(50), nullable=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)


class WeightHistory(Base):
    __tablename__ = "weight_history"

    id          = Column(Integer, primary_key=True, index=True)
    adjusted_at = Column(DateTime, default=datetime.utcnow)
    question_id = Column(String(20), nullable=True)
    module      = Column(String(50), nullable=True)
    change_type = Column(String(50), nullable=False)
    old_value   = Column(Float, nullable=False)
    new_value   = Column(Float, nullable=False)
    reason      = Column(String(200), nullable=True)


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
    role                = Column(String(20), nullable=False, default="analyst")
    # role values: analyst | admin | super_admin
    is_active           = Column(Boolean, default=True)
    created_at          = Column(DateTime, default=datetime.utcnow)
    last_login          = Column(DateTime, nullable=True)
    login_count         = Column(Integer, default=0)
    password_changed_at = Column(DateTime, nullable=True)
    notes               = Column(Text, nullable=True)
    recovery_code_hash  = Column(String(200), nullable=True)
    recovery_set_at     = Column(DateTime, nullable=True)
    # Multi-tenant
    organization_id     = Column(Integer, ForeignKey("organizations.id"), nullable=True)

    organization  = relationship("Organization", back_populates="users")
    notifications = relationship("Notification", foreign_keys=[Notification.user_id],
                                 primaryjoin="User.id == Notification.user_id")


# ── DB Helpers ────────────────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_descendant_org_ids(db, org_id: int) -> list[int]:
    """BFS: returns org_id + all descendant org ids."""
    visited, queue = set(), [org_id]
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        children = db.query(Organization.id).filter(
            Organization.parent_id == current,
            Organization.is_active == True
        ).all()
        queue.extend([c[0] for c in children])
    return list(visited)


def get_visible_org_ids(user_dict: dict, db) -> list[int] | None:
    """
    Returns list of org_ids visible to this user.
    super_admin → None (means ALL orgs, no filter)
    admin/analyst → their org + all descendants
    """
    if user_dict.get("role") == "super_admin":
        return None  # no filter → see all
    org_id = user_dict.get("org_id")
    if not org_id:
        return []
    return get_descendant_org_ids(db, org_id)


def audit(db, username: str, action: str, target: str = None,
          details: str = None, ip: str = None, org_id: int = None):
    """Helper to write an audit log entry."""
    db.add(AuditLog(
        username=username,
        action=action,
        target=target,
        details=details,
        ip_address=ip,
        organization_id=org_id,
    ))


def init_db():
    Base.metadata.create_all(bind=engine)
    _run_migrations()
    _seed_default_org()
    _ensure_default_admin()


def _run_migrations():
    """Add new columns to existing tables without dropping data (SQLite ALTER TABLE)."""
    if not _is_sqlite:
        return  # PostgreSQL handles schema via create_all
    _new_cols = [
        # Existing (kept for safety on older DBs)
        ("incidents", "network_context",   "TEXT"),
        ("incidents", "ti_enrichment",     "TEXT"),
        ("incidents", "ti_adjusted",       "BOOLEAN DEFAULT 0"),
        ("users", "login_count",           "INTEGER DEFAULT 0"),
        ("users", "password_changed_at",   "TIMESTAMP"),
        ("users", "notes",                 "TEXT"),
        ("users", "recovery_code_hash",    "VARCHAR(200)"),
        ("users", "recovery_set_at",       "TIMESTAMP"),
        # Multi-tenant new columns
        ("incidents", "organization_id",            "INTEGER"),
        ("incidents", "asset_id",                   "INTEGER"),
        ("incidents", "asset_criticality_applied",  "BOOLEAN DEFAULT 0"),
        ("users",     "organization_id",            "INTEGER"),
        ("audit_log", "organization_id",            "INTEGER"),
        # Fase 10 — SLA + tags
        ("incidents", "resolved_at",               "TIMESTAMP"),
        ("incidents", "tags",                      "TEXT"),
    ]
    with engine.connect() as conn:
        for table, col, ddl in _new_cols:
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"))
                conn.commit()
            except Exception:
                pass  # Column already exists — safe to ignore


def _seed_default_org():
    """
    Create the default organization on first run.
    Assign all existing users and incidents to it.
    """
    db = SessionLocal()
    try:
        # Create default org if none exist
        if db.query(Organization).count() == 0:
            default_org = Organization(
                name="Organización Principal",
                slug="default",
                org_type="flat",
                description="Organización por defecto — renombrar desde Administración > Organizaciones",
            )
            db.add(default_org)
            db.commit()
            db.refresh(default_org)
            org_id = default_org.id
        else:
            org = db.query(Organization).filter(Organization.slug == "default").first()
            if not org:
                return
            org_id = org.id

        # Assign existing users with no org
        db.query(User).filter(User.organization_id == None).update(
            {"organization_id": org_id}, synchronize_session=False
        )
        # Assign existing incidents with no org
        db.query(Incident).filter(Incident.organization_id == None).update(
            {"organization_id": org_id}, synchronize_session=False
        )
        db.commit()
    finally:
        db.close()


def _ensure_default_admin():
    """Create default super_admin on first run if no users exist."""
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            org = db.query(Organization).filter(Organization.slug == "default").first()
            db.add(User(
                username="admin",
                password_hash=_bcrypt.hashpw(b"admin123", _bcrypt.gensalt()).decode(),
                role="super_admin",
                organization_id=org.id if org else None,
            ))
            db.commit()
    finally:
        db.close()
