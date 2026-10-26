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
