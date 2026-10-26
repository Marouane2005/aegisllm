import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable, List, Optional
from urllib.parse import urlparse, urlunparse
from app.core.config import get_settings


class SSRFError(Exception):
    pass


_EXTRA_BLOCKED = [
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT
    ipaddress.ip_network("169.254.0.0/16"),     # link-local incl. 169.254.169.254 metadata
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IPv6 metadata
]


@dataclass
class ValidatedUpstream:
    url: str            # original URL
    host: str           # original hostname (for Host header / SNI)
    pinned_ip: str      # the vetted IP we will connect to
    pinned_url: str     # URL with hostname replaced by pinned_ip


def _private_overrides() -> List[ipaddress._BaseNetwork]:
    raw = get_settings().UPSTREAM_PRIVATE_IP_ALLOWLIST
    return [ipaddress.ip_network(c.strip(), strict=False) for c in raw.split(",") if c.strip()]


def is_blocked_ip(ip_str: str, overrides: Optional[Iterable] = None) -> bool:
    ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    for net in overrides if overrides is not None else _private_overrides():
        if ip.version == net.version and ip in net:
            return False
    if (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast
            or ip.is_unspecified or ip.is_reserved or not ip.is_global):
        return True
    return any(ip.version == n.version and ip in n for n in _EXTRA_BLOCKED)


def _check_scheme_and_allowlist(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise SSRFError(f"Invalid scheme: {parsed.scheme}")
    host = parsed.hostname
    if not host:
        raise SSRFError("Missing hostname")
    allowed = {h.strip().lower() for h in get_settings().ALLOWED_UPSTREAM_HOSTS.split(",") if h.strip()}
    if host.lower() not in allowed:
        raise SSRFError(f"Host not in allowlist: {host}")
    return parsed, host


def validate_upstream_url(url: str) -> str:
    """Static checks only (scheme + hostname allowlist). Kept for callers that don't connect."""
    _check_scheme_and_allowlist(url)
    return url


async def _resolve(host: str, port: int) -> List[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


async def resolve_and_validate(url: str) -> ValidatedUpstream:
    """Resolve the upstream host once, reject if ANY resolved IP is internal, and pin the
    first address so a later re-resolution (DNS rebinding) cannot redirect the connection."""
    parsed, host = _check_scheme_and_allowlist(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        ips = await _resolve(host, port)
    except OSError as e:
        raise SSRFError(f"DNS resolution failed for {host}: {e}")
    if not ips:
        raise SSRFError(f"No addresses for {host}")
    overrides = _private_overrides()
    for ip in ips:
        if is_blocked_ip(ip, overrides):
            raise SSRFError(f"Blocked internal address for {host}: {ip}")
    pinned = ips[0]
    netloc_host = f"[{pinned}]" if ":" in pinned else pinned
    netloc = f"{netloc_host}:{parsed.port}" if parsed.port else netloc_host
    return ValidatedUpstream(url, host, pinned, urlunparse(parsed._replace(netloc=netloc)))
