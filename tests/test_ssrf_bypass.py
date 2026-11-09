import pytest
import httpx
from unittest.mock import patch

from app.core.config import get_settings
from app.core.security import encrypt_secret
from app.db.models import ProviderConfig
from app.services.proxy_service import _build_pinned_request, forward_request
from app.services.ssrf_guard import SSRFError, is_blocked_ip, parse_ip_literal, resolve_and_validate


def _cfg(base_url=None):
    return ProviderConfig(provider="openai", encrypted_api_key=encrypt_secret("sk-test"), base_url=base_url)


def _allow(*hosts):
    return patch.object(get_settings(), "ALLOWED_UPSTREAM_HOSTS", ",".join(hosts))


@pytest.mark.parametrize("host,canonical", [
    ("2130706433", "127.0.0.1"),
    ("0x7f000001", "127.0.0.1"),
    ("0177.0.0.1", "127.0.0.1"),
    ("127.1", "127.0.0.1"),
    ("0x7f.0.0.1", "127.0.0.1"),
    ("8.8.8.8", "8.8.8.8"),
    ("::1", "::1"),
])
def test_parse_obfuscated_ip_literals(host, canonical):
    assert parse_ip_literal(host) == canonical


def test_dns_names_are_not_ip_literals():
    assert parse_ip_literal("api.openai.com") is None
    assert parse_ip_literal("metadata.google.internal") is None


@pytest.mark.parametrize("url", [
    "https://2130706433/v1/x",
    "https://0x7f000001/v1/x",
    "https://0177.0.0.1/v1/x",
    "https://127.1/v1/x",
    "https://0x7f.0.0.1/v1/x",
    "http://[::1]/v1/x",
    "http://[::ffff:127.0.0.1]/v1/x",
    "http://[fd00::1]/v1/x",
    "http://169.254.169.254/latest/meta-data",
    "http://[fd00:ec2::254]/",
])
@pytest.mark.asyncio
async def test_obfuscated_literals_blocked_without_dns(url):
    from urllib.parse import urlparse
    host = urlparse(url).hostname

    async def _no_dns(h, p):
        raise AssertionError(f"DNS should not be consulted for {h}")

    with _allow(host), patch("app.services.ssrf_guard._resolve", _no_dns):
        with pytest.raises(SSRFError, match="Blocked internal address"):
            await resolve_and_validate(url)


@pytest.mark.asyncio
async def test_public_literal_is_pinned_without_dns():
    async def _no_dns(h, p):
        raise AssertionError("unexpected dns")

    with _allow("8.8.8.8"), patch("app.services.ssrf_guard._resolve", _no_dns):
        target = await resolve_and_validate("https://8.8.8.8/v1/x")
    assert target.pinned_ip == "8.8.8.8"
    assert target.pinned_url.startswith("https://8.8.8.8/")


@pytest.mark.parametrize("ip", [
    "64:ff9b::127.0.0.1",
    "64:ff9b::169.254.169.254",
    "2002:7f00:1::",
    "2001:0:1234:5678::80ff:fffe",
    "::ffff:10.1.2.3",
    "::ffff:169.254.169.254",
])
def test_transition_encodings_of_internal_addresses_are_blocked(ip):
    assert is_blocked_ip(ip, overrides=[])


@pytest.mark.asyncio
async def test_redirect_is_not_followed():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)

    async def _public(host, port):
        return ["104.18.6.192"]

    with patch("app.services.proxy_service._get_client", lambda: client), \
         patch("app.services.ssrf_guard._resolve", _public):
        with pytest.raises(SSRFError, match="redirect"):
            await forward_request({"messages": []}, _cfg())
    assert seen == ["https://104.18.6.192/v1/chat/completions"]
    assert "169.254.169.254" not in seen[0]
    await client.aclose()


@pytest.mark.asyncio
async def test_host_header_drops_userinfo():
    async def _public(host, port):
        return ["104.18.6.192"]

    with patch("app.services.ssrf_guard._resolve", _public):
        req = await _build_pinned_request(
            {"messages": []},
            _cfg("https://user:pass@api.openai.com"),
            "v1/chat/completions",
        )
    assert req.headers["host"] == "api.openai.com"
    assert "pass" not in req.headers["host"]
    assert req.url.host == "104.18.6.192"
    assert req.extensions["sni_hostname"] == "api.openai.com"


@pytest.mark.asyncio
async def test_rebinding_second_lookup_is_ignored():
    calls = {"n": 0}

    async def _flap(host, port):
        calls["n"] += 1
        return ["104.18.6.192"] if calls["n"] == 1 else ["127.0.0.1"]

    with patch("app.services.ssrf_guard._resolve", _flap):
        req = await _build_pinned_request({"messages": []}, _cfg(), "v1/chat/completions")
        # A second resolution, as a rebinding attacker would hope for, is not used.
        assert (await _flap("api.openai.com", 443)) == ["127.0.0.1"]
    assert calls["n"] == 2
    assert req.url.host == "104.18.6.192"
    assert req.headers["host"] == "api.openai.com"


@pytest.mark.asyncio
async def test_metadata_name_is_not_allowlisted_by_default():
    with pytest.raises(SSRFError, match="allowlist"):
        await resolve_and_validate("http://metadata.google.internal/")
