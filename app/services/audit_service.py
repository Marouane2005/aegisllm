import logging
import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.clock import utcnow_naive
from app.core.config import get_settings
from app.db.models import AuditLog, AuditPayload
from app.services.pii_detector import detect_pii, mask_text

logger = logging.getLogger(__name__)


def mask_payload(text: Optional[str]) -> Optional[str]:
    if not text:
        return text
    return mask_text(text, detect_pii(text))


def _scrub(value):
    """Mask PII that leaked into nested audit metadata (evidence snippets)."""
    if isinstance(value, str):
        return mask_payload(value)
    if isinstance(value, dict):
        return {key: _scrub(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    return value


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
    # Always derive the masked copy from the original body when we have it.
    # A caller-supplied "masked" string is not trusted: it may still contain PII.
    request_source = raw_request if raw_request is not None else masked_request
    response_source = raw_response if raw_response is not None else masked_response
    masked_request = mask_payload(request_source)
    masked_response = mask_payload(response_source)
    threat_summary = _scrub(threat_summary or {})
    if not get_settings().STORE_RAW_PAYLOADS:
        raw_request = raw_response = None
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
            timestamp=utcnow_naive(),
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
