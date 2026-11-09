from datetime import datetime, timezone


def utcnow_naive() -> datetime:
    """Current UTC time without tzinfo.

    The DateTime columns are TIMESTAMP WITHOUT TIME ZONE holding UTC, and
    asyncpg rejects tz-aware values for them, so writes and comparisons use
    naive UTC. API responses attach the zone again (see app/schemas/admin.py).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)
