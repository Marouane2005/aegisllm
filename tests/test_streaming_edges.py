import asyncio
import json

import pytest
from sqlalchemy import select

from app.api.proxy import _audit_shielded, feed_sse_buffer
from app.db.models import AuditLog, AuditPayload
from app.db.session import AsyncSessionLocal
from app.services.proxy_service import accumulate_stream_text, parse_sse_chunk


def _upstream(chunks, status=200):
    closed = {"n": 0}

    async def body():
        for chunk in chunks:
            if isinstance(chunk, tuple):
                await asyncio.sleep(chunk[0])
                yield chunk[1]
            else:
                yield chunk

    class Response:
        status_code = status

        async def aread(self):
            return b'{"error":"nope"}'

        async def aclose(self):
            closed["n"] += 1

    return Response(), body(), closed


@pytest.fixture
def patched_stream(monkeypatch):
    holder = {}

    async def fake_stream(body, provider_config, path="v1/chat/completions"):
        response, iterator, closed = holder["built"]()
        holder["closed"] = closed
        return response, iterator

    monkeypatch.setattr("app.api.proxy.stream_request", fake_stream)
    return holder


def test_sse_buffer_reassembles_split_chunks():
    pending = b""
    pending, events = feed_sse_buffer(pending, b'data: {"choices":[{"delta":{"content":"He')
    assert events == []
    pending, events = feed_sse_buffer(pending, b'llo"}}]}\n\n')
    assert len(events) == 1
    assert accumulate_stream_text("", events[0]) == "Hello"
    pending, events = feed_sse_buffer(pending, b"data: [DONE]\n\n")
    assert events == []
    assert parse_sse_chunk(b"not an event") is None


@pytest.mark.asyncio
async def test_split_stream_is_audited_in_full(client, project_with_key, patched_stream):
    _, api_key, project_id = project_with_key
    patched_stream["built"] = lambda: _upstream([
        b'data: {"choices":[{"delta":{"content":"He',
        b'llo"}}]}\n\n',
        b'data: {"choices":[{"delta":{"content":"!"}}]}\n',
        b"\n",
        b"data: [DONE]\n\n",
    ])
    resp = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"model": "gpt-4o-mini", "stream": True, "messages": [{"role": "user", "content": "hi"}]},
    )
    assert resp.status_code == 200
    assert 'content":"Hello"' in resp.text
    assert 'content":"!"' in resp.text
    request_id = resp.headers["x-aegis-request-id"]
    async with AsyncSessionLocal() as session:
        log = (await session.execute(select(AuditLog).where(AuditLog.request_id == request_id))).scalar_one()
        payload = (await session.execute(select(AuditPayload).where(AuditPayload.audit_log_id == log.id))).scalar_one()
    assert log.status_code == 200
    assert log.project_id.hex == project_id.replace("-", "") or str(log.project_id) == project_id
    assert "Hello!" in (payload.masked_response or "")
    assert patched_stream["closed"]["n"] == 1


@pytest.mark.asyncio
async def test_stream_disconnect_still_writes_audit(client, project_with_key, patched_stream):
    """Cancel the ASGI task after the first SSE chunk, the way a dropped client does.

    httpx's ASGI transport drains a stream on close, so it cannot stand in for
    a disconnect. Driving the app and cancelling the task can.
    """
    from app.main import app
    _, api_key, _ = project_with_key
    release = asyncio.Event()

    async def chunks():
        yield b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'
        await release.wait()
        yield b'data: {"choices":[{"delta":{"content":" late"}}]}\n\n'

    class Response:
        status_code = 200

        async def aclose(self):
            return None

    def built():
        return Response(), chunks(), {"n": 0}

    patched_stream["built"] = built
    body = json.dumps({"model": "gpt-4o-mini", "stream": True, "messages": [{"role": "user", "content": "hi"}]}).encode()
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "POST", "scheme": "http", "path": "/v1/chat/completions",
        "raw_path": b"/v1/chat/completions", "query_string": b"",
        "headers": [
            (b"authorization", f"Bearer {api_key}".encode()),
            (b"content-type", b"application/json"),
        ],
        "client": ("127.0.0.1", 1234), "server": ("test", 80),
    }
    sent = []
    first_body = asyncio.Event()

    delivered = False

    async def receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        # Starlette polls for http.disconnect. Another http.request would spin.
        await asyncio.Future()

    async def send(message):
        sent.append(message)
        if message["type"] == "http.response.body" and message.get("body"):
            first_body.set()

    task = asyncio.create_task(app(scope, receive, send))
    await asyncio.wait_for(first_body.wait(), timeout=2)
    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=2)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass
    if not task.done():
        raise AssertionError("request task ignored cancellation")

    request_id = None
    for message in sent:
        if message["type"] == "http.response.start":
            headers = {k.decode().lower(): v.decode() for k, v in message["headers"]}
            request_id = headers.get("x-aegis-request-id")
    assert request_id
    for _ in range(50):
        async with AsyncSessionLocal() as session:
            log = (await session.execute(select(AuditLog).where(AuditLog.request_id == request_id))).scalar_one_or_none()
        if log is not None:
            break
        await asyncio.sleep(0.05)
    assert log is not None
    async with AsyncSessionLocal() as session:
        payload = (await session.execute(select(AuditPayload).where(AuditPayload.audit_log_id == log.id))).scalar_one()
    assert "partial" in (payload.masked_response or "")
    assert "late" not in (payload.masked_response or "")


@pytest.mark.asyncio
async def test_upstream_error_stream_is_audited(client, project_with_key, patched_stream):
    _, api_key, _ = project_with_key
    patched_stream["built"] = lambda: _upstream([], status=500)
    resp = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"model": "gpt-4o-mini", "stream": True, "messages": [{"role": "user", "content": "hi"}]},
    )
    assert resp.status_code == 500
    request_id = resp.headers.get("x-aegis-request-id")
    # The error path audits in the background, keyed by a request id we can look up
    # via the single row this test created.
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(select(AuditLog).where(AuditLog.status_code == 500))).scalars().all()
    assert len(rows) == 1
    assert rows[0].output_tokens == 0
    if request_id:
        assert rows[0].request_id == request_id


@pytest.mark.asyncio
async def test_audit_shield_survives_caller_cancellation(monkeypatch):
    started = asyncio.Event()
    finished = asyncio.Event()

    async def slow(**kwargs):
        started.set()
        await asyncio.sleep(0.05)
        finished.set()

    monkeypatch.setattr("app.api.proxy._audit_background", slow)

    async def caller():
        await _audit_shielded(request_id="x")

    task = asyncio.create_task(caller())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(finished.wait(), timeout=1)


def test_malformed_sse_does_not_raise():
    pending, events = feed_sse_buffer(b"", b"data: {not json}\n\n: keep-alive\n\n")
    assert events == []
    assert pending == b""
