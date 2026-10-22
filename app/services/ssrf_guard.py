from urllib.parse import urlparse
from app.core.config import get_settings


class SSRFError(Exception):
    pass


def validate_upstream_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise SSRFError(f"Invalid scheme: {parsed.scheme}")
    host = parsed.hostname
    if not host:
        raise SSRFError("Missing hostname")

    settings = get_settings()
    allowed = {h.strip().lower() for h in settings.ALLOWED_UPSTREAM_HOSTS.split(",") if h.strip()}
    if host.lower() not in allowed:
        raise SSRFError(f"Host not in allowlist: {host}")

    if host.lower() in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"):
        raise SSRFError(f"Blocked internal host: {host}")

    return url
