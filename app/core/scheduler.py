import logging
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import delete, select
from app.db.session import AsyncSessionLocal
from app.db.models import AuditLog, AuditPayload, Project

logger = logging.getLogger(__name__)


async def cleanup_old_payloads() -> None:
    logger.info("Starting scheduled payload cleanup...")
    async with AsyncSessionLocal() as session:
        try:
            projects = (await session.execute(select(Project))).scalars().all()
            total_deleted = 0
            for project in projects:
                cutoff = datetime.now(timezone.utc) - timedelta(days=project.retention_days)
                stmt = delete(AuditPayload).where(
                    AuditPayload.audit_log_id.in_(
                        select(AuditLog.id).where(
                            AuditLog.project_id == project.id,
                            AuditLog.timestamp < cutoff,
                        )
                    )
                )
                result = await session.execute(stmt)
                total_deleted += result.rowcount
            await session.commit()
            logger.info(f"Cleanup complete. Deleted {total_deleted} payloads.")
        except Exception as e:
            await session.rollback()
            logger.exception(f"Cleanup failed: {e}")


scheduler = AsyncIOScheduler(timezone="UTC")


def start_scheduler() -> AsyncIOScheduler:
    from app.core.config import get_settings
    settings = get_settings()
    scheduler.add_job(
        cleanup_old_payloads,
        trigger="cron",
        hour=settings.CLEANUP_HOUR_UTC,
        minute=0,
        id="payload_cleanup",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    scheduler.start()
    logger.info(f"Scheduled payload cleanup to run daily at {settings.CLEANUP_HOUR_UTC}:00 UTC")
    return scheduler
