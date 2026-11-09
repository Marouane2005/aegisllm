import pytest
from unittest.mock import MagicMock
import json


@pytest.mark.asyncio
async def test_default_provider_is_the_earliest_active_one(client, project_with_key, monkeypatch):
    token, api_key, project_id = project_with_key
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.post(
        f"/api/admin/projects/{project_id}/providers",
        json={"provider": "anthropic", "api_key": "sk-ant-fake"},
        headers=headers,
    )
    assert resp.status_code == 201

    seen = {}

    async def fake_forward(body, provider_config, path="v1/chat/completions"):
        seen["provider"] = provider_config.provider
        resp = MagicMock()
        resp.status_code = 200
        resp.text = json.dumps({"choices": [{"message": {"content": "ok"}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}})
        resp.json.return_value = json.loads(resp.text)
        return resp

    monkeypatch.setattr("app.api.proxy.forward_request", fake_forward)
    resp = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert resp.status_code == 200
    # The project fixture inserts OpenAI first. Anthropic must not win the tie.
    assert seen["provider"] == "openai"
