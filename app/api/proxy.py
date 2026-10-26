import json
import logging
import time
import uuid
from typing import Optional
import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Path as PathParam
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import authenticate_api_key
from app.core.config import get_settings
from app.db.models import ApiKey, ProviderConfig
from app.db.session import AsyncSessionLocal
from app.services.proxy_service import (
    process_request, forward_request, stream_request,
    parse_sse_chunk, accumulate_stream_text, extract_token_usage,
    _estimate_tokens, close_client,
)
from app.services.ssrf_guard import SSRFError
from app.services.audit_service import write_audit_record

logger = logging.getLogger(__name__)
SUPPORTED_CHAT_COMPLETIONS_PROVIDERS = {"openai"}

router = APIRouter()
settings = get_settings()


async def _resolve_provider_config(db: AsyncSession, project_id: uuid.UUID, provider_hint: Optional[str]) -> ProviderConfig:
    if provider_hint:
        result = await db.execute(
            select(ProviderConfig).where(
                ProviderConfig.project_id == project_id,
                ProviderConfig.provider == provider_hint.lower(),
                ProviderConfig.is_active == True,
            )
        )
        config = result.scalar_one_or_none()
        if config is None:
            raise HTTPException(404, f"Provider '{provider_hint}' not configured")
        return config
    result = await db.execute(
        select(ProviderConfig).where(ProviderConfig.project_id == project_id, ProviderConfig.is_active == True)
    )
    config = result.scalars().first()
    if config is None:
        raise HTTPException(403, "No upstream provider configured")
    return config


async def _audit_background(**kwargs):
    async with AsyncSessionLocal() as session:
        await write_audit_record(db=session, **kwargs)


@router.post("/chat/completions")
async def chat_completions(
    request: Request,
    background_tasks: BackgroundTasks,
    api_key: ApiKey = Depends(authenticate_api_key),
):
    start_time = time.perf_counter()
    request_id = str(uuid.uuid4())
    provider_hint = request.headers.get("X-Aegis-Provider")

    body_bytes = await request.body()
    if len(body_bytes) > settings.MAX_REQUEST_BODY_BYTES:
        raise HTTPException(413, "Request body too large")
    try:
        body = json.loads(body_bytes)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON")
    if not isinstance(body, dict) or "messages" not in body:
        raise HTTPException(400, "Missing 'messages' field")

    async with AsyncSessionLocal() as db:
        provider_config = await _resolve_provider_config(db, api_key.project_id, provider_hint)

    if provider_config.provider not in SUPPORTED_CHAT_COMPLETIONS_PROVIDERS:
        # Anthropic uses a different API shape (/v1/messages); forwarding OpenAI-format
        # bodies to it fails with confusing upstream errors, so refuse clearly instead.
        return JSONResponse(status_code=501, content={"error": {
            "message": f"Provider '{provider_config.provider}' is not supported yet on /v1/chat/completions",
            "type": "provider_not_supported",
        }})

    client_ip = request.client.host if request.client else None
    model = body.get("model", "unknown")
    is_stream = body.get("stream", False)
    raw_request = json.dumps(body)

    try:
        modified_body, threat_summary, action_taken = await process_request(body, provider_config, request_id, client_ip)
    except ValueError as e:
        latency_ms = int((time.perf_counter() - start_time) * 1000)
        threat_summary["blocked"] = True
        threat_summary["reason"] = str(e)
        background_tasks.add_task(
            _audit_background,
            project_id=api_key.project_id, request_id=request_id,
            provider=provider_config.provider, model=model,
            latency_ms=latency_ms, input_tokens=_estimate_tokens(raw_request), output_tokens=0,
            action_taken="blocked", threat_summary=threat_summary, status_code=403,
            client_ip=client_ip, raw_request=raw_request,
        )
        return JSONResponse(status_code=403, content={"error": {"message": "Request blocked by security policy", "type": "security_policy_violation"}})

    masked_request = json.dumps(modified_body) if modified_body is not body else None

    try:
        if is_stream:
            return await _handle_streaming(
                modified_body, provider_config, background_tasks, api_key, request_id, model,
                start_time, raw_request, masked_request, threat_summary, action_taken, client_ip,
            )
        else:
            return await _handle_non_streaming(
                modified_body, provider_config, background_tasks, api_key, request_id, model,
                start_time, raw_request, masked_request, threat_summary, action_taken, client_ip,
            )
    except SSRFError as e:
        raise HTTPException(502, f"Upstream request blocked: {e}")
    except httpx.TimeoutException:
        raise HTTPException(504, "Upstream request timed out")
    except httpx.HTTPError as e:
        logger.exception(f"Upstream HTTP error: {e}")
        raise HTTPException(502, "Upstream request failed")


async def _handle_non_streaming(body, provider_config, background_tasks, api_key, request_id, model, start_time, raw_request, masked_request, threat_summary, action_taken, client_ip):
    response = await forward_request(body, provider_config)
    latency_ms = int((time.perf_counter() - start_time) * 1000)
    response_json = response.json()
    input_tokens, output_tokens = extract_token_usage(response_json)
    background_tasks.add_task(
        _audit_background,
        project_id=api_key.project_id, request_id=request_id,
        provider=provider_config.provider, model=model,
        latency_ms=latency_ms, input_tokens=input_tokens, output_tokens=output_tokens,
        action_taken=action_taken, threat_summary=threat_summary, status_code=response.status_code,
        client_ip=client_ip, raw_request=raw_request, masked_request=masked_request,
        raw_response=response.text,
    )
    return JSONResponse(content=response_json, status_code=response.status_code)


async def _handle_streaming(body, provider_config, background_tasks, api_key, request_id, model, start_time, raw_request, masked_request, threat_summary, action_taken, client_ip):
    upstream_response, byte_iterator = await stream_request(body, provider_config)
    if upstream_response.status_code >= 400:
        error_body = await upstream_response.aread()
        latency_ms = int((time.perf_counter() - start_time) * 1000)
        background_tasks.add_task(
            _audit_background,
            project_id=api_key.project_id, request_id=request_id,
            provider=provider_config.provider, model=model,
            latency_ms=latency_ms, input_tokens=_estimate_tokens(raw_request), output_tokens=0,
            action_taken=action_taken, threat_summary=threat_summary,
            status_code=upstream_response.status_code, client_ip=client_ip,
            raw_request=raw_request, masked_request=masked_request,
            raw_response=error_body.decode("utf-8", errors="replace"),
        )
        return StreamingResponse(iter([error_body]), status_code=upstream_response.status_code, media_type="application/json")

    accumulated_text = ""
    buffer_size = 0
    max_buffer = 4 * 1024 * 1024

    async def stream_with_audit():
        nonlocal accumulated_text, buffer_size
        try:
            async for chunk in byte_iterator:
                buffer_size += len(chunk)
                if buffer_size > max_buffer:
                    logger.warning(f"Stream exceeded max buffer for {request_id}")
                    break
                parsed = parse_sse_chunk(chunk)
                if parsed:
                    accumulated_text = accumulate_stream_text(accumulated_text, parsed)
                yield chunk
        finally:
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            await _audit_background(
                project_id=api_key.project_id, request_id=request_id,
                provider=provider_config.provider, model=model,
                latency_ms=latency_ms, input_tokens=_estimate_tokens(raw_request),
                output_tokens=_estimate_tokens(accumulated_text),
                action_taken=action_taken, threat_summary=threat_summary,
                status_code=200, client_ip=client_ip,
                raw_request=raw_request, masked_request=masked_request,
                raw_response=accumulated_text,
            )

    return StreamingResponse(
        stream_with_audit(), status_code=200, media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Aegis-Request-ID": request_id},
    )
