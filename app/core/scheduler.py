import logging
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import delete, select
from app.core.config import get_settings
from app.db.session import AsyncSessionLocal
from app.db.models import AuditLog, AuditPayload, Project

logger = logging.getLogger(__name__)


def _utcnow_naive() -> datetime:
    # audit_logs.timestamp is naive UTC; asyncpg rejects tz-aware params for it
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def _delete_in_batches(session, log_id_query, batch_size: int, delete_logs: bool) -> int:
    """Repeatedly take up to batch_size matching audit_log ids, delete their payloads
    (and the log rows themselves if delete_logs), and commit each batch."""
    total = 0
    while True:
        ids = (await session.execute(log_id_query.limit(batch_size))).scalars().all()
        if not ids:
            return total
        res = await session.execute(delete(AuditPayload).where(AuditPayload.audit_log_id.in_(ids)))
        if delete_logs:
            res = await session.execute(delete(AuditLog).where(AuditLog.id.in_(ids)))
        total += res.rowcount
        await session.commit()
        if len(ids) < batch_size:
            return total


async def cleanup_old_payloads() -> dict:
    settings = get_settings()
    batch = max(1, settings.CLEANUP_BATCH_SIZE)
    logger.info("Starting scheduled retention cleanup (batch size %d)...", batch)
    stats = {"payloads": 0, "audit_logs": 0}
    async with AsyncSessionLocal() as session:
        try:
            projects = (await session.execute(select(Project))).scalars().all()
            for project in projects:
                cutoff = _utcnow_naive() - timedelta(days=project.retention_days)
                q = (
                    select(AuditLog.id)
                    .join(AuditPayload, AuditPayload.audit_log_id == AuditLog.id)
                    .where(AuditLog.project_id == project.id, AuditLog.timestamp < cutoff)
                )
                stats["payloads"] += await _delete_in_batches(session, q, batch, delete_logs=False)

            if settings.AUDIT_LOG_RETENTION_DAYS > 0:
                cutoff = _utcnow_naive() - timedelta(days=settings.AUDIT_LOG_RETENTION_DAYS)
                q = select(AuditLog.id).where(AuditLog.timestamp < cutoff)
                stats["audit_logs"] += await _delete_in_batches(session, q, batch, delete_logs=True)
            logger.info(
                "Cleanup complete. Deleted %d payloads and %d audit_logs rows.",
                stats["payloads"], stats["audit_logs"],
            )
        except Exception as e:
            await session.rollback()
            logger.exception(f"Cleanup failed: {e}")
    return stats


scheduler = AsyncIOScheduler(timezone="UTC")


def start_scheduler() -> AsyncIOScheduler:
    settings = get_settings()
    scheduler.add_job(
        cleanup_old_payloads,
        trigger="cron",
        hour=settings.CLEANUP_HOUR_UTC,
        minute=settings.CLEANUP_MINUTE_UTC,
        id="payload_cleanup",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    scheduler.start()
    logger.info(
        "Scheduled retention cleanup daily at %02d:%02d UTC (audit_logs window: %s days)",
        settings.CLEANUP_HOUR_UTC, settings.CLEANUP_MINUTE_UTC, settings.AUDIT_LOG_RETENTION_DAYS,
    )
    return scheduler
