import json
import logging
import math
import time
import uuid
from typing import cast

from fastapi import Depends, HTTPException, Request
from limits import parse
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.api.deps import authenticate_api_key
from app.core.config import get_settings
from app.db.models import ApiKey
from app.db.session import AsyncSessionLocal
from app.services.audit_service import write_audit_record

logger = logging.getLogger(__name__)

# Single shared limiter so all routes use the configured (Redis) storage and
# limits are shared across workers and restarts.
limiter = Limiter(key_func=get_remote_address, storage_uri=get_settings().REDIS_URL)


def _per_key_limit():
    return parse(f"{get_settings().RATE_LIMIT_PER_MINUTE}/minute")


async def _requested_model(request: Request) -> str:
    # Only peek at bodies that declare a size within the normal request limit, so
    # a throttled client can't make us buffer something we would reject anyway.
    try:
        size = int(request.headers.get("content-length", ""))
    except ValueError:
        return "unknown"
    if size > get_settings().MAX_REQUEST_BODY_BYTES:
        return "unknown"
    try:
        body = json.loads(await request.body())
    except Exception:
        return "unknown"
    model = body.get("model") if isinstance(body, dict) else None
    return model[:100] if isinstance(model, str) and model else "unknown"


async def _audit_rate_limited(request: Request, api_key: ApiKey, limit: int, retry_after: int) -> None:
    """Record the rejected call. The body is not stored: it never left the gateway."""
    provider = (request.headers.get("X-Aegis-Provider") or "unknown").lower()[:50]
    try:
        async with AsyncSessionLocal() as session:
            await write_audit_record(
                db=session,
                project_id=cast(uuid.UUID, api_key.project_id),
                request_id=str(uuid.uuid4()),
                provider=provider,
                model=await _requested_model(request),
                latency_ms=0,
                input_tokens=0,
                output_tokens=0,
                action_taken="rate_limited",
                threat_summary={"rate_limit": {"limit_per_minute": limit, "retry_after_seconds": retry_after}},
                status_code=429,
                client_ip=request.client.host if request.client else None,
            )
    except Exception:
        # The caller still gets the 429; a failed audit write is logged, not surfaced.
        logger.exception("Failed to audit rate-limited request for key %s", api_key.id)


async def rate_limited_api_key(request: Request, api_key: ApiKey = Depends(authenticate_api_key)) -> ApiKey:
    """Authenticate the API key, then enforce RATE_LIMIT_PER_MINUTE per key using the
    shared (Redis) limiter storage. Over the limit -> 429 with Retry-After (seconds),
    and an audit row with action_taken=rate_limited."""
    if get_settings().RATE_LIMIT_PER_MINUTE <= 0:
        return api_key
    item = _per_key_limit()
    strategy = limiter.limiter
    key = str(api_key.id)
    if not strategy.hit(item, "v1-apikey", key):
        reset_at, _remaining = strategy.get_window_stats(item, "v1-apikey", key)
        retry_after = max(1, math.ceil(reset_at - time.time()))
        await _audit_rate_limited(request, api_key, item.amount, retry_after)
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for this API key",
            headers={"Retry-After": str(retry_after), "X-RateLimit-Limit": str(item.amount)},
        )
    return api_key
