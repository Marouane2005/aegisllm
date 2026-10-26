import pytest
from app.core.config import get_settings

BODY = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}


@pytest.mark.asyncio
async def test_v1_rate_limit_per_api_key(client, project_with_key, monkeypatch):
    monkeypatch.setattr(get_settings(), "RATE_LIMIT_PER_MINUTE", 2)
    token, key1, project_id = project_with_key
    h1 = {"Authorization": f"Bearer {key1}"}
    codes = [(await client.post("/v1/chat/completions", json=BODY, headers=h1)).status_code for _ in range(2)]
    assert 429 not in codes
    r = await client.post("/v1/chat/completions", json=BODY, headers=h1)
    assert r.status_code == 429
    assert 1 <= int(r.headers["Retry-After"]) <= 60

    # A second key in the same project has its own budget.
    resp = await client.post(f"/api/admin/projects/{project_id}/api-keys", json={"name": "k2"},
                             headers={"Authorization": f"Bearer {token}"})
    h2 = {"Authorization": f"Bearer {resp.json()['key']}"}
    assert (await client.post("/v1/chat/completions", json=BODY, headers=h2)).status_code != 429


@pytest.mark.asyncio
async def test_v1_rate_limit_disabled_with_zero(client, project_with_key, monkeypatch):
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
