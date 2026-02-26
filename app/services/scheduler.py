"""
SOC Assist — Scheduler de notificaciones periódicas
Revisa activos con revisión pendiente y genera notificaciones in-app.
Email semanal: estructura preparada, pendiente configuración SMTP.
"""
import logging
from datetime import datetime, timedelta
from app.models.database import SessionLocal, Asset, Notification

logger = logging.getLogger(__name__)


def check_asset_reviews():
    """
    Daily job: find assets with upcoming or overdue reviews.
    Creates in-app Notification records for each org.
    Runs at startup and can be scheduled via APScheduler.
    """
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        upcoming_threshold = now + timedelta(days=30)

        # Overdue assets (next_review_at < now)
        overdue = db.query(Asset).filter(
            Asset.is_active == True,
            Asset.next_review_at != None,
            Asset.next_review_at < now,
        ).all()

        # Upcoming assets (due within 30 days)
        upcoming = db.query(Asset).filter(
            Asset.is_active == True,
            Asset.next_review_at != None,
            Asset.next_review_at >= now,
            Asset.next_review_at <= upcoming_threshold,
        ).all()

        # Group by org
        from collections import defaultdict
        by_org_overdue: dict[int, list] = defaultdict(list)
        by_org_upcoming: dict[int, list] = defaultdict(list)

        for a in overdue:
            by_org_overdue[a.organization_id].append(a)
        for a in upcoming:
            by_org_upcoming[a.organization_id].append(a)

        all_org_ids = set(by_org_overdue.keys()) | set(by_org_upcoming.keys())

        for org_id in all_org_ids:
            od = by_org_overdue.get(org_id, [])
            up = by_org_upcoming.get(org_id, [])

            # Check if we already sent this notification today
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            existing = db.query(Notification).filter(
                Notification.organization_id == org_id,
                Notification.notif_type.in_(["asset_review_overdue", "asset_review_upcoming"]),
                Notification.created_at >= today_start,
            ).first()
            if existing:
                continue  # Already notified today

            expires = now + timedelta(days=7)

            if od:
                names = ", ".join(a.name for a in od[:5])
                extra = f" (+{len(od) - 5} más)" if len(od) > 5 else ""
                db.add(Notification(
                    organization_id=org_id,
                    notif_type="asset_review_overdue",
                    title=f"{len(od)} activo{'s' if len(od) > 1 else ''} con revisión VENCIDA",
                    body=f"Activos que requieren revisión inmediata: {names}{extra}",
                    is_read=False,
                    expires_at=expires,
                ))

            if up:
                names = ", ".join(a.name for a in up[:5])
                extra = f" (+{len(up) - 5} más)" if len(up) > 5 else ""
                db.add(Notification(
                    organization_id=org_id,
                    notif_type="asset_review_upcoming",
                    title=f"{len(up)} activo{'s' if len(up) > 1 else ''} próximos a revisar (30 días)",
                    body=f"Revisión pendiente en los próximos 30 días: {names}{extra}",
                    is_read=False,
                    expires_at=expires,
                ))

        db.commit()
        logger.info(f"[Scheduler] Revisión de activos: {len(overdue)} vencidos, {len(upcoming)} próximos")

    except Exception as e:
        logger.error(f"[Scheduler] Error en check_asset_reviews: {e}")
    finally:
        db.close()


def get_unread_notifications(org_id: int, user_id: int) -> list:
    """
    Return unread notifications for a user's org.
    Filters expired notifications.
    """
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        notifs = db.query(Notification).filter(
            Notification.organization_id == org_id,
            Notification.is_read == False,
            (Notification.expires_at == None) | (Notification.expires_at > now),
        ).order_by(Notification.created_at.desc()).all()
        return notifs
    finally:
        db.close()


def mark_notifications_read(org_id: int):
    """Mark all notifications for an org as read."""
    db = SessionLocal()
    try:
        db.query(Notification).filter(
            Notification.organization_id == org_id,
            Notification.is_read == False,
        ).update({"is_read": True}, synchronize_session=False)
        db.commit()
    finally:
        db.close()
