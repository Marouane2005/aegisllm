import json
import logging
from typing import AsyncIterator, Optional, Tuple
import httpx
from urllib.parse import urlparse
from app.core.config import get_settings
from app.core.security import decrypt_secret
from app.db.models import ProviderConfig
from app.services.pii_detector import detect_pii, mask_text, summarize_findings
from app.services.injection_guard import evaluate_injection_risk
from app.services.ssrf_guard import resolve_and_validate

logger = logging.getLogger(__name__)
settings = get_settings()

_http_client: Optional[httpx.AsyncClient] = None


def _get_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            http2=True,
            timeout=httpx.Timeout(settings.PROXY_REQUEST_TIMEOUT_SEC, connect=10.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            follow_redirects=False,
        )
    return _http_client


async def close_client() -> None:
    global _http_client
    if _http_client is not None and not _http_client.is_closed:
        await _http_client.aclose()
        _http_client = None


def _build_upstream_url(provider_config: ProviderConfig, path: str) -> str:
    base = provider_config.base_url
    if not base:
        defaults = {"openai": "https://api.openai.com", "anthropic": "https://api.anthropic.com"}
        base = defaults.get(provider_config.provider, "https://api.openai.com")
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def _build_upstream_headers(provider_config: ProviderConfig) -> dict:
    api_key = decrypt_secret(provider_config.encrypted_api_key)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if provider_config.provider == "anthropic":
        headers["x-api-key"] = api_key
        headers["anthropic-version"] = "2023-06-01"
        del headers["Authorization"]
    return headers


async def _build_pinned_request(body: dict, provider_config: ProviderConfig, path: str) -> httpx.Request:
    """Validate the upstream (DNS + IP blocklist) and build a request that connects to the
    vetted IP while keeping the original Host header and TLS SNI/cert hostname.
    Redirects are never followed (client has follow_redirects=False); 3xx is returned as-is."""
    target = await resolve_and_validate(_build_upstream_url(provider_config, path))
    headers = _build_upstream_headers(provider_config)
    headers["Host"] = urlparse(target.url).netloc
    return _get_client().build_request(
        "POST", target.pinned_url, json=body, headers=headers,
        extensions={"sni_hostname": target.host},
    )


def _extract_text_from_messages(messages: list) -> str:
    parts = []
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append(item.get("text", ""))
    return "\n".join(parts)


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


async def process_request(body: dict, provider_config: ProviderConfig, request_id: str, client_ip: Optional[str]):
    messages = body.get("messages", [])
    text = _extract_text_from_messages(messages)

    threat_summary = {}
    action_taken = "allowed"

    is_blocked, signals, score = evaluate_injection_risk(text)
    if is_blocked:
        threat_summary["injection"] = {
            "blocked": True,
            "score": round(score, 3),
            "signals": [{"name": s.name, "evidence": s.evidence} for s in signals[:5]],
        }
        raise ValueError("Prompt injection detected")

    if signals:
        threat_summary["injection"] = {
            "blocked": False,
            "score": round(score, 3),
            "signals": [{"name": s.name, "evidence": s.evidence} for s in signals[:3]],
        }

    findings = detect_pii(text)
    if findings:
        threat_summary["pii"] = summarize_findings(findings)
        new_messages = []
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                msg_findings = detect_pii(content)
                new_msg = dict(msg)
                new_msg["content"] = mask_text(content, msg_findings) if msg_findings else content
                new_messages.append(new_msg)
            elif isinstance(content, list):
                new_content = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        item_findings = detect_pii(item.get("text", ""))
                        new_item = dict(item)
                        new_item["text"] = mask_text(item.get("text", ""), item_findings) if item_findings else item.get("text", "")
                        new_content.append(new_item)
                    else:
                        new_content.append(item)
                new_msg = dict(msg)
                new_msg["content"] = new_content
                new_messages.append(new_msg)
            else:
                new_messages.append(msg)

        body = dict(body)
        body["messages"] = new_messages
        action_taken = "masked"

    return body, threat_summary, action_taken


async def forward_request(body: dict, provider_config: ProviderConfig, path: str = "v1/chat/completions"):
    req = await _build_pinned_request(body, provider_config, path)
    return await _get_client().send(req)


async def stream_request(body: dict, provider_config: ProviderConfig, path: str = "v1/chat/completions"):
    req = await _build_pinned_request(body, provider_config, path)
    response = await _get_client().send(req, stream=True)
    return response, response.aiter_bytes()


def parse_sse_chunk(chunk: bytes) -> Optional[dict]:
    text = chunk.decode("utf-8", errors="replace").strip()
    if not text.startswith("data:"):
        return None
    data = text[5:].strip()
    if data == "[DONE]":
        return None
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return None


def accumulate_stream_text(accumulated: str, parsed: dict) -> str:
    choices = parsed.get("choices", [])
    if not choices:
        return accumulated
    delta = choices[0].get("delta", {})
    content = delta.get("content", "")
    return accumulated + content


def extract_token_usage(response_json: dict):
    usage = response_json.get("usage", {})
    return usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)
