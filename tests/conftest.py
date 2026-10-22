import os
import asyncio
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from cryptography.fernet import Fernet

os.environ.setdefault("POSTGRES_USER", "test")
os.environ.setdefault("POSTGRES_PASSWORD", "test")
os.environ.setdefault("POSTGRES_DB", "test")
os.environ.setdefault("POSTGRES_HOST", "localhost")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-testing-only-1234567890")
os.environ.setdefault("FERNET_MASTER_KEY", Fernet.generate_key().decode())
os.environ.setdefault("ALLOWED_ORIGINS", "http://localhost")

from app.main import app
from app.db.session import engine
from app.db.base_class import Base


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client(setup_db):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def admin_user(client):
    email = "admin@test.com"
    password = "strongpassword123"
    await client.post("/api/auth/register", json={"email": email, "password": password})
    resp = await client.post("/api/auth/login", json={"email": email, "password": password})
    token = resp.json()["access_token"]
    return token, email


@pytest_asyncio.fixture
async def project_with_key(client, admin_user):
    token, _ = admin_user
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.post("/api/admin/projects", json={"name": "Test", "retention_days": 7}, headers=headers)
    project_id = resp.json()["id"]
    resp = await client.post(f"/api/admin/projects/{project_id}/api-keys", json={"name": "test-key"}, headers=headers)
    api_key_raw = resp.json()["key"]
    resp = await client.post(
        f"/api/admin/projects/{project_id}/providers",
        json={"provider": "openai", "api_key": "sk-test-fake-key-12345"},
        headers=headers,
    )
    assert resp.status_code == 201
    return token, api_key_raw, project_id
