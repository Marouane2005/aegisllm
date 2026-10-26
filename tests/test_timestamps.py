import uuid
from datetime import datetime, timedelta
import pytest
from sqlalchemy import select, func
from app.db.session import AsyncSessionLocal
from app.db.models import AuditLog, AuditPayload


async def _insert_log(project_id, age: timedelta):
    async with AsyncSessionLocal() as s:
        log = AuditLog(
            project_id=uuid.UUID(project_id), request_id=str(uuid.uuid4()), provider="openai", model="m",
            latency_ms=5, input_tokens=1, output_tokens=1, action_taken="allowed", threat_summary={},
            status_code=200, timestamp=datetime.utcnow() - age,
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
    start = (datetime.utcnow() - timedelta(hours=1)).isoformat() + "+00:00"
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
        count = lambda i: s.scalar(select(func.count()).select_from(AuditPayload).where(AuditPayload.audit_log_id == i))
        assert await count(old_id) == 0
        assert await count(new_id) == 1


@pytest.mark.asyncio
async def test_retention_deletes_old_audit_logs_in_batches(client, project_with_key, monkeypatch):
    from app.core.config import get_settings
    from app.core.scheduler import cleanup_old_payloads
    monkeypatch.setattr(get_settings(), "AUDIT_LOG_RETENTION_DAYS", 60)
    monkeypatch.setattr(get_settings(), "CLEANUP_BATCH_SIZE", 2)
    _, _, project_id = project_with_key  # retention_days=7
    ancient = [await _insert_log(project_id, timedelta(days=100)) for _ in range(5)]
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
