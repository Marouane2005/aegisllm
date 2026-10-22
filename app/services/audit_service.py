import logging
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import AuditLog, AuditPayload

logger = logging.getLogger(__name__)


async def write_audit_record(
    db: AsyncSession,
    project_id: uuid.UUID,
    request_id: str,
    provider: str,
    model: str,
    latency_ms: int,
    input_tokens: int,
    output_tokens: int,
    action_taken: str,
    threat_summary: dict,
    status_code: int,
    client_ip: Optional[str],
    raw_request: Optional[str] = None,
    masked_request: Optional[str] = None,
    raw_response: Optional[str] = None,
    masked_response: Optional[str] = None,
) -> None:
    try:
        log = AuditLog(
            project_id=project_id,
            request_id=request_id,
            provider=provider,
            model=model,
            latency_ms=latency_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            action_taken=action_taken,
            threat_summary=threat_summary,
            status_code=status_code,
            client_ip=client_ip,
            timestamp=datetime.utcnow(),
        )
        db.add(log)
        await db.flush()

        if any([raw_request, masked_request, raw_response, masked_response]):
            payload = AuditPayload(
                audit_log_id=log.id,
                raw_request=raw_request,
                masked_request=masked_request,
                raw_response=raw_response,
                masked_response=masked_response,
            )
            db.add(payload)

        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.exception(f"Failed to write audit record {request_id}: {e}")
        raise
