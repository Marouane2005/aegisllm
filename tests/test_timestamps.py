import uuid
from datetime import datetime, timedelta
from app.core.clock import utcnow_naive
import pytest
from sqlalchemy import select, func
from app.db.session import AsyncSessionLocal
from app.db.models import AuditLog, AuditPayload


async def _insert_log(project_id, age: timedelta):
    async with AsyncSessionLocal() as s:
        log = AuditLog(
            project_id=uuid.UUID(project_id), request_id=str(uuid.uuid4()), provider="openai", model="m",
            latency_ms=5, input_tokens=1, output_tokens=1, action_taken="allowed", threat_summary={},
            status_code=200, timestamp=utcnow_naive() - age,
        )
        s.add(log)
        await s.flush()
        s.add(AuditPayload(audit_log_id=log.id, raw_request="{}"))
        await s.commit()
        return log.id


@pytest.mark.asyncio
async def test_metrics_endpoint(client, project_with_key):
    token, _, project_id = project_with_key
    await _insert_log(project_id, timedelta(minutes=5))
    resp = await client.get(f"/api/admin/projects/{project_id}/metrics", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["total_requests"] == 1


@pytest.mark.asyncio
async def test_audit_log_time_filter_with_tz(client, project_with_key):
    token, _, project_id = project_with_key
    await _insert_log(project_id, timedelta(minutes=5))
    start = (utcnow_naive() - timedelta(hours=1)).isoformat() + "+00:00"
    resp = await client.get(
        f"/api/admin/projects/{project_id}/audit-logs", params={"start_time": start},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["total_count"] == 1


@pytest.mark.asyncio
async def test_retention_cleanup_deletes_only_old_payloads(client, project_with_key):
    from app.core.scheduler import cleanup_old_payloads
    _, _, project_id = project_with_key  # retention_days=7
    old_id = await _insert_log(project_id, timedelta(days=30))
    new_id = await _insert_log(project_id, timedelta(days=1))
    await cleanup_old_payloads()
    async with AsyncSessionLocal() as s:
        async def count(log_id):
            return await s.scalar(select(func.count()).select_from(AuditPayload).where(AuditPayload.audit_log_id == log_id))
        assert await count(old_id) == 0
        assert await count(new_id) == 1


@pytest.mark.asyncio
async def test_retention_deletes_old_audit_logs_in_batches(client, project_with_key, monkeypatch):
    from app.core.config import get_settings
    from app.core.scheduler import cleanup_old_payloads
    monkeypatch.setattr(get_settings(), "AUDIT_LOG_RETENTION_DAYS", 60)
    monkeypatch.setattr(get_settings(), "CLEANUP_BATCH_SIZE", 2)
    _, _, project_id = project_with_key  # retention_days=7
    for _ in range(5):
        await _insert_log(project_id, timedelta(days=100))
    mid = await _insert_log(project_id, timedelta(days=30))
    fresh = await _insert_log(project_id, timedelta(days=1))
    stats = await cleanup_old_payloads()
    assert stats == {"payloads": 6, "audit_logs": 5}
    async with AsyncSessionLocal() as s:
        ids = set((await s.execute(select(AuditLog.id))).scalars().all())
        assert ids == {mid, fresh}
        payloads = set((await s.execute(select(AuditPayload.audit_log_id))).scalars().all())
        assert payloads == {fresh}


@pytest.mark.asyncio
async def test_audit_log_retention_disabled(client, project_with_key, monkeypatch):
    from app.core.config import get_settings
    from app.core.scheduler import cleanup_old_payloads
    monkeypatch.setattr(get_settings(), "AUDIT_LOG_RETENTION_DAYS", 0)
    _, _, project_id = project_with_key
    old = await _insert_log(project_id, timedelta(days=400))
    await cleanup_old_payloads()
    async with AsyncSessionLocal() as s:
        assert await s.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.id == old)) == 1


def _assert_utc(value: str):
    assert value.endswith("Z") or value.endswith("+00:00"), value
    assert datetime.fromisoformat(value.replace("Z", "+00:00")).utcoffset() == timedelta(0)


@pytest.mark.asyncio
async def test_audit_log_timestamps_are_utc_aware(client, project_with_key):
    token, _, project_id = project_with_key
    await _insert_log(project_id, timedelta(minutes=5))
    resp = await client.get(
        f"/api/admin/projects/{project_id}/audit-logs", headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    item = resp.json()["items"][0]
    _assert_utc(item["timestamp"])
    # Same instant as the naive UTC value in the DB, not shifted.
    parsed = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")).replace(tzinfo=None)
    assert abs(utcnow_naive() - timedelta(minutes=5) - parsed) < timedelta(minutes=1)


@pytest.mark.asyncio
async def test_created_at_and_last_used_are_utc_aware(client, project_with_key):
    token, api_key, project_id = project_with_key
    headers = {"Authorization": f"Bearer {token}"}
    # Any authenticated /v1 call stamps last_used_at, whatever the upstream does.
    await client.post("/v1/chat/completions", json={}, headers={"Authorization": f"Bearer {api_key}"})
    projects = (await client.get("/api/admin/projects", headers=headers)).json()
    _assert_utc(projects[0]["created_at"])
    keys = (await client.get(f"/api/admin/projects/{project_id}/api-keys", headers=headers)).json()
    _assert_utc(keys[0]["created_at"])
    _assert_utc(keys[0]["last_used_at"])
    providers = (await client.get(f"/api/admin/projects/{project_id}/providers", headers=headers)).json()
    _assert_utc(providers[0]["created_at"])


def test_utc_schema_normalizes_offsets():
    from datetime import timezone
    from app.schemas.admin import _as_utc
    naive = datetime(2026, 11, 9, 21, 47, 32)
    assert _as_utc(naive) == naive.replace(tzinfo=timezone.utc)
    plus_one = datetime(2026, 11, 9, 22, 47, 32, tzinfo=timezone(timedelta(hours=1)))
    assert _as_utc(plus_one).tzinfo == timezone.utc
    assert _as_utc(plus_one).hour == 21
