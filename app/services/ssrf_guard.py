import asyncio
import ipaddress
import re
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


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    """Pull an IPv4 address out of the common transition encodings."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    raw = int(ip)
    if ip in ipaddress.ip_network("64:ff9b::/96") or ip in ipaddress.ip_network("64:ff9b:1::/48"):
        return ipaddress.IPv4Address(raw & 0xFFFFFFFF)
    if ip in ipaddress.ip_network("2002::/16"):
        return ipaddress.IPv4Address((raw >> 80) & 0xFFFFFFFF)
    if ip in ipaddress.ip_network("2001::/32"):
        # Teredo obfuscates the client address with a bitwise NOT.
        return ipaddress.IPv4Address((raw & 0xFFFFFFFF) ^ 0xFFFFFFFF)
    return None


def _nonpublic(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast
            or ip.is_unspecified or ip.is_reserved or not ip.is_global):
        return True
    return any(ip.version == net.version and ip in net for net in _EXTRA_BLOCKED)


def is_blocked_ip(ip_str: str, overrides: Optional[Iterable] = None) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        return True
    candidates = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            candidates.append(embedded)
    nets = list(overrides if overrides is not None else _private_overrides())
    for candidate in candidates:
        allowed = any(candidate.version == net.version and candidate in net for net in nets)
        if allowed:
            continue
        if _nonpublic(candidate):
            return True
    return False


def _aton_part(part: str) -> int:
    if re.fullmatch(r"0x[0-9a-fA-F]+", part):
        return int(part, 16)
    if len(part) > 1 and part.startswith("0") and part.isdigit():
        return int(part, 8)
    if part.isdigit():
        return int(part, 10)
    raise ValueError(part)


def parse_ip_literal(host: str) -> Optional[str]:
    """Canonicalize a hostname that is an IP, including the legacy inet_aton forms
    (decimal, hex, octal, and shortened dotted quads). Returns None for DNS names.
    """
    host = host.strip().strip("[]")
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if re.fullmatch(r"0x[0-9a-fA-F]+", host):
        value = int(host, 16)
        if 0 <= value <= 0xFFFFFFFF:
            return str(ipaddress.IPv4Address(value))
        return None
    if re.fullmatch(r"\d+", host):
        value = int(host, 10)
        if 0 <= value <= 0xFFFFFFFF:
            return str(ipaddress.IPv4Address(value))
        return None
    parts = host.split(".")
    if not 2 <= len(parts) <= 4:
        return None
    try:
        nums = [_aton_part(part) for part in parts]
    except ValueError:
        return None
    try:
        if len(nums) == 4:
            if any(n > 255 for n in nums):
                return None
            value = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
        elif len(nums) == 3:
            if nums[0] > 255 or nums[1] > 255 or nums[2] > 0xFFFF:
                return None
            value = (nums[0] << 24) | (nums[1] << 16) | nums[2]
        else:
            if nums[0] > 255 or nums[1] > 0xFFFFFF:
                return None
            value = (nums[0] << 24) | nums[1]
    except ValueError:
        return None
    return str(ipaddress.IPv4Address(value))


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
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


async def resolve_and_validate(url: str) -> ValidatedUpstream:
    """Resolve the upstream host once, reject if ANY resolved IP is internal, and pin the
    first address so a later re-resolution (DNS rebinding) cannot redirect the connection."""
    parsed, host = _check_scheme_and_allowlist(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    overrides = _private_overrides()
    # Resolve IP literals ourselves. glibc's getaddrinfo accepts decimal, hex,
    # octal and shortened quads, and not every platform agrees on them.
    literal = parse_ip_literal(host)
    if literal is not None:
        ips = [literal]
    else:
        try:
            ips = await _resolve(host, port)
        except OSError as e:
            raise SSRFError(f"DNS resolution failed for {host}: {e}")
    if not ips:
        raise SSRFError(f"No addresses for {host}")
    for ip in ips:
        if is_blocked_ip(ip, overrides):
            raise SSRFError(f"Blocked internal address for {host}: {ip}")
    pinned = ips[0]
    netloc_host = f"[{pinned}]" if ":" in pinned else pinned
    netloc = f"{netloc_host}:{parsed.port}" if parsed.port else netloc_host
    return ValidatedUpstream(url, host, pinned, urlunparse(parsed._replace(netloc=netloc)))
