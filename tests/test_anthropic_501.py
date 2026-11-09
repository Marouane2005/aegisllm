import pytest
from unittest.mock import patch

BODY = {"model": "claude-3-5-sonnet", "messages": [{"role": "user", "content": "hi"}]}


@pytest.mark.asyncio
async def test_anthropic_provider_returns_501(client, project_with_key):
    token, key, project_id = project_with_key
    r = await client.post(f"/api/admin/projects/{project_id}/providers",
                          json={"provider": "anthropic", "api_key": "sk-ant-fake"},
                          headers={"Authorization": f"Bearer {token}"})
    assert r.status_code in (200, 201)
    with patch("app.services.proxy_service._get_client") as gc:
        for stream in (False, True):
            r = await client.post("/v1/chat/completions", json={**BODY, "stream": stream},
                                  headers={"Authorization": f"Bearer {key}", "X-Aegis-Provider": "anthropic"})
            assert r.status_code == 501
            assert r.json()["error"]["type"] == "provider_not_supported"
            assert "not supported yet" in r.json()["error"]["message"]
        gc.assert_not_called()
