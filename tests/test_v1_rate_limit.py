import uuid
import json
from unittest.mock import MagicMock

import pytest
from app.core.config import get_settings

BODY = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}


@pytest.fixture
def quiet_upstream(monkeypatch):
    """The limiter tests must not open a socket to the real provider."""
    calls = {"n": 0}

    async def fake_forward(body, provider_config, path="v1/chat/completions"):
        calls["n"] += 1
        resp = MagicMock()
        resp.status_code = 200
        resp.text = json.dumps({"choices": [{"message": {"content": "ok"}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}})
        resp.json.return_value = json.loads(resp.text)
        return resp

    monkeypatch.setattr("app.api.proxy.forward_request", fake_forward)
    return calls


@pytest.mark.asyncio
async def test_v1_rate_limit_per_api_key(client, project_with_key, monkeypatch, quiet_upstream):
    monkeypatch.setattr(get_settings(), "RATE_LIMIT_PER_MINUTE", 2)
    token, key1, project_id = project_with_key
    h1 = {"Authorization": f"Bearer {key1}"}
    codes = [(await client.post("/v1/chat/completions", json=BODY, headers=h1)).status_code for _ in range(2)]
    assert 429 not in codes
    r = await client.post("/v1/chat/completions", json=BODY, headers=h1)
    assert r.status_code == 429
    assert r.headers["X-RateLimit-Limit"] == "2"
    assert 1 <= int(r.headers["Retry-After"]) <= 60
    assert quiet_upstream["n"] == 2

    # A second key in the same project has its own budget.
    resp = await client.post(f"/api/admin/projects/{project_id}/api-keys", json={"name": "k2"},
                             headers={"Authorization": f"Bearer {token}"})
    h2 = {"Authorization": f"Bearer {resp.json()['key']}"}
    assert (await client.post("/v1/chat/completions", json=BODY, headers=h2)).status_code != 429


@pytest.mark.asyncio
async def test_v1_rate_limit_disabled_with_zero(client, project_with_key, monkeypatch, quiet_upstream):
    monkeypatch.setattr(get_settings(), "RATE_LIMIT_PER_MINUTE", 0)
    h = {"Authorization": f"Bearer {project_with_key[1]}"}
    for _ in range(4):
        assert (await client.post("/v1/chat/completions", json=BODY, headers=h)).status_code != 429


@pytest.mark.asyncio
async def test_invalid_key_is_401_not_counted(client, setup_db, monkeypatch):
    monkeypatch.setattr(get_settings(), "RATE_LIMIT_PER_MINUTE", 1)
    for _ in range(3):
        r = await client.post("/v1/chat/completions", json=BODY, headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401


async def _audit_rows(project_id):
    from sqlalchemy import select
    from app.db.models import AuditLog
    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as s:
        rows = (await s.execute(
            select(AuditLog).where(AuditLog.project_id == uuid.UUID(project_id)).order_by(AuditLog.timestamp)
        )).scalars().all()
    return rows


@pytest.mark.asyncio
async def test_rate_limited_call_writes_audit_row(client, project_with_key, monkeypatch, quiet_upstream):
    monkeypatch.setattr(get_settings(), "RATE_LIMIT_PER_MINUTE", 1)
    token, key, project_id = project_with_key
    h = {"Authorization": f"Bearer {key}", "X-Aegis-Provider": "openai"}
    assert (await client.post("/v1/chat/completions", json=BODY, headers=h)).status_code == 200
    assert (await client.post("/v1/chat/completions", json=BODY, headers=h)).status_code == 429

    rows = await _audit_rows(project_id)
    limited = [r for r in rows if r.action_taken == "rate_limited"]
    assert len(limited) == 1
    row = limited[0]
    assert row.status_code == 429
    assert row.model == "gpt-4o-mini"
    assert row.provider == "openai"
    assert row.threat_summary["rate_limit"]["limit_per_minute"] == 1
    assert quiet_upstream["n"] == 1

    admin = {"Authorization": f"Bearer {token}"}
    listed = await client.get(f"/api/admin/projects/{project_id}/audit-logs",
                              params={"action_taken": "rate_limited"}, headers=admin)
    assert listed.json()["total_count"] == 1
    assert listed.json()["items"][0]["status_code"] == 429

    m = (await client.get(f"/api/admin/projects/{project_id}/metrics", headers=admin)).json()
    assert m["total_requests"] == 2
    assert m["rate_limited_requests"] == 1
    assert m["allowed_requests"] == 1
    assert m["requests_by_action"] == {"allowed": 1, "rate_limited": 1}


@pytest.mark.asyncio
async def test_rate_limited_audit_does_not_store_body(client, project_with_key, monkeypatch, quiet_upstream):
    from sqlalchemy import select, func
    from app.db.models import AuditPayload
    from app.db.session import AsyncSessionLocal
    monkeypatch.setattr(get_settings(), "RATE_LIMIT_PER_MINUTE", 1)
    _, key, project_id = project_with_key
    h = {"Authorization": f"Bearer {key}"}
    await client.post("/v1/chat/completions", json=BODY, headers=h)
    secret = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "mail jane@example.com"}]}
    assert (await client.post("/v1/chat/completions", json=secret, headers=h)).status_code == 429
    row = [r for r in await _audit_rows(project_id) if r.action_taken == "rate_limited"][0]
    assert row.provider == "unknown"
    async with AsyncSessionLocal() as s:
        n = await s.scalar(select(func.count()).select_from(AuditPayload).where(AuditPayload.audit_log_id == row.id))
    assert n == 0


@pytest.mark.asyncio
async def test_rate_limited_still_429_when_audit_write_fails(client, project_with_key, monkeypatch, quiet_upstream):
    monkeypatch.setattr(get_settings(), "RATE_LIMIT_PER_MINUTE", 1)

    async def broken(**kwargs):
        raise RuntimeError("db down")

    monkeypatch.setattr("app.core.rate_limit.write_audit_record", broken)
    h = {"Authorization": f"Bearer {project_with_key[1]}"}
    await client.post("/v1/chat/completions", json=BODY, headers=h)
    assert (await client.post("/v1/chat/completions", json=BODY, headers=h)).status_code == 429


@pytest.mark.asyncio
async def test_invalid_key_writes_no_audit_row(client, project_with_key):
    _, _, project_id = project_with_key
    r = await client.post("/v1/chat/completions", json=BODY, headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401
    assert await _audit_rows(project_id) == []
