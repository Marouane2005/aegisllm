from slowapi import Limiter
from slowapi.util import get_remote_address
from app.core.config import get_settings

# Single shared limiter so all routes use the configured (Redis) storage and
# limits are shared across workers/restarts.
limiter = Limiter(key_func=get_remote_address, storage_uri=get_settings().REDIS_URL)


import math
import time
from fastapi import Depends, HTTPException
from limits import parse

from app.api.deps import authenticate_api_key
from app.db.models import ApiKey


def _per_key_limit():
    return parse(f"{get_settings().RATE_LIMIT_PER_MINUTE}/minute")


async def rate_limited_api_key(api_key: ApiKey = Depends(authenticate_api_key)) -> ApiKey:
    """Authenticate the API key, then enforce RATE_LIMIT_PER_MINUTE per key using the
    shared (Redis) limiter storage. Over the limit -> 429 with Retry-After (seconds)."""
    if get_settings().RATE_LIMIT_PER_MINUTE <= 0:
        return api_key
    item = _per_key_limit()
    strategy = limiter.limiter
    key = str(api_key.id)
    if not strategy.hit(item, "v1-apikey", key):
        reset_at, _remaining = strategy.get_window_stats(item, "v1-apikey", key)
        retry_after = max(1, math.ceil(reset_at - time.time()))
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for this API key",
            headers={"Retry-After": str(retry_after), "X-RateLimit-Limit": str(item.amount)},
        )
    return api_key
