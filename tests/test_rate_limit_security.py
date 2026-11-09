import json
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def quiet_upstream(monkeypatch):
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
async def test_register_limit_is_per_process_storage(client, setup_db):
    codes = []
    for i in range(6):
        resp = await client.post("/api/auth/register", json={"email": f"user{i}@example.com", "password": "strongpassword123"})
        codes.append(resp.status_code)
    assert codes[:5] == [201, 201, 201, 201, 201]
    assert codes[5] == 429


@pytest.mark.asyncio
async def test_login_limit_returns_429(client, setup_db):
    await client.post("/api/auth/register", json={"email": "login-limit@example.com", "password": "strongpassword123"})
    codes = []
    for _ in range(11):
        resp = await client.post("/api/auth/login", json={"email": "login-limit@example.com", "password": "wrongpassword1"})
        codes.append(resp.status_code)
    assert codes[:10] == [401] * 10
    assert codes[10] == 429


@pytest.mark.asyncio
async def test_rate_limit_zero_does_not_consume_a_budget(client, project_with_key, monkeypatch, quiet_upstream):
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "RATE_LIMIT_PER_MINUTE", 0)
    _, api_key, _ = project_with_key
    for _ in range(3):
        resp = await client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert resp.status_code == 200
    assert quiet_upstream["n"] == 3
