import pytest
from unittest.mock import patch
from app.services import ssrf_guard
from app.services.ssrf_guard import SSRFError, is_blocked_ip, resolve_and_validate

PUBLIC = "104.18.6.192"


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
    "0.0.0.0", "224.0.0.1", "::1", "::", "fe80::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1",
    "fd00:ec2::254",
])
def test_blocked_ips(ip):
    assert is_blocked_ip(ip, overrides=[])


@pytest.mark.parametrize("ip", [PUBLIC, "2606:4700::6812:6c0"])
def test_public_ips_allowed(ip):
    assert not is_blocked_ip(ip, overrides=[])


def _fake_resolver(*answers):
    seq = list(answers)

    async def _resolve(host, port):
        return seq.pop(0) if len(seq) > 1 else seq[0]
    return _resolve


@pytest.mark.asyncio
async def test_allowlisted_name_resolving_to_loopback_is_blocked():
    with patch.object(ssrf_guard, "_resolve", _fake_resolver(["127.0.0.1"])):
        with pytest.raises(SSRFError, match="Blocked internal address"):
            await resolve_and_validate("https://api.openai.com/v1/chat/completions")


@pytest.mark.asyncio
async def test_any_internal_answer_blocks():
    with patch.object(ssrf_guard, "_resolve", _fake_resolver([PUBLIC, "10.0.0.5"])):
        with pytest.raises(SSRFError):
            await resolve_and_validate("https://api.openai.com/v1/x")


@pytest.mark.asyncio
async def test_rebinding_connection_is_pinned_to_vetted_ip():
    # First resolution is public, a later one would be loopback: the request must
    # still target the pinned public IP with the original Host header and SNI.
    from app.services.proxy_service import _build_pinned_request
    from app.db.models import ProviderConfig
    from app.core.security import encrypt_secret
    cfg = ProviderConfig(provider="openai", encrypted_api_key=encrypt_secret("sk-x"), base_url=None)
    with patch.object(ssrf_guard, "_resolve", _fake_resolver([PUBLIC], ["127.0.0.1"])):
        req = await _build_pinned_request({"messages": []}, cfg, "v1/chat/completions")
    assert req.url.host == PUBLIC
    assert req.headers["host"] == "api.openai.com"
    assert req.extensions["sni_hostname"] == "api.openai.com"


@pytest.mark.asyncio
async def test_ipv6_pinned_url_bracketed():
    with patch.object(ssrf_guard, "_resolve", _fake_resolver(["2606:4700::6812:6c0"])):
        t = await resolve_and_validate("https://api.openai.com/v1/x")
    assert t.pinned_url == "https://[2606:4700::6812:6c0]/v1/x"


@pytest.mark.asyncio
async def test_not_allowlisted_and_bad_scheme():
    with pytest.raises(SSRFError, match="allowlist"):
        await resolve_and_validate("https://evil.example.com/")
    with pytest.raises(SSRFError, match="scheme"):
        await resolve_and_validate("file:///etc/passwd")


@pytest.mark.asyncio
async def test_private_override_cidr():
    with patch.object(ssrf_guard, "_private_overrides", lambda: [__import__("ipaddress").ip_network("127.0.0.1/32")]), \
         patch.object(ssrf_guard, "_resolve", _fake_resolver(["127.0.0.1"])):
        t = await resolve_and_validate("http://api.openai.com/v1/x")
    assert t.pinned_ip == "127.0.0.1"


def test_redirects_not_followed():
    from app.services.proxy_service import _get_client
    assert _get_client().follow_redirects is False
