import pytest


@pytest.mark.asyncio
async def test_register_and_login(client):
    resp = await client.post("/api/auth/register", json={"email": "new@test.com", "password": "strongpassword123"})
    assert resp.status_code == 201
    assert resp.json()["email"] == "new@test.com"

    resp = await client.post("/api/auth/login", json={"email": "new@test.com", "password": "strongpassword123"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    await client.post("/api/auth/register", json={"email": "x@test.com", "password": "strongpassword123"})
    resp = await client.post("/api/auth/login", json={"email": "x@test.com", "password": "wrongpassword"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_requires_auth(client):
    resp = await client.get("/api/admin/projects")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_projects_with_auth(client, admin_user):
    token, _ = admin_user
    resp = await client.get("/api/admin/projects", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
