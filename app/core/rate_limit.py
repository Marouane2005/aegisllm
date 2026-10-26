from slowapi import Limiter
from slowapi.util import get_remote_address
from app.core.config import get_settings

# Single shared limiter so all routes use the configured (Redis) storage and
# limits are shared across workers/restarts.
limiter = Limiter(key_func=get_remote_address, storage_uri=get_settings().REDIS_URL)
