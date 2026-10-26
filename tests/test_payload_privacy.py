import uuid
import pytest
from sqlalchemy import select
from app.core.config import get_settings
from app.db.session import AsyncSessionLocal
from app.db.models import AuditLog, AuditPayload, PayloadAccessLog
from app.services.audit_service import write_audit_record

RAW_REQ = '{"messages":[{"role":"user","content":"mail me at alice@example.com"}]}'
RAW_RESP = '{"choices":[{"message":{"content":"sure, bob@example.org"}}]}'


async def _write(project_id):
    rid = f"req-{uuid.uuid4()}"
    async with AsyncSessionLocal() as db:
        await write_audit_record(
            db=db, project_id=uuid.UUID(project_id), request_id=rid, provider="openai", model="m",
            latency_ms=1, input_tokens=1, output_tokens=1, action_taken="allowed", threat_summary={},
            status_code=200, client_ip=None, raw_request=RAW_REQ, raw_response=RAW_RESP,
        )
    async with AsyncSessionLocal() as db:
        log = (await db.execute(select(AuditLog).where(AuditLog.request_id == rid))).scalar_one()
        payload = (await db.execute(select(AuditPayload).where(AuditPayload.audit_log_id == log.id))).scalar_one()
    return log, payload


@pytest.mark.asyncio
async def test_raw_not_stored_by_default_and_masked_at_write(project_with_key):
    assert get_settings().STORE_RAW_PAYLOADS is False
    _, _, project_id = project_with_key
    _, p = await _write(project_id)
    assert p.raw_request is None and p.raw_response is None
    assert "alice@example.com" not in p.masked_request
    assert "bob@example.org" not in p.masked_response



@pytest.mark.asyncio
async def test_raw_stored_when_opted_in(project_with_key, monkeypatch):
    monkeypatch.setattr(get_settings(), "STORE_RAW_PAYLOADS", True)
    _, _, project_id = project_with_key
    _, p = await _write(project_id)
    assert p.raw_request == RAW_REQ
    assert "alice@example.com" not in p.masked_request


@pytest.mark.asyncio
async def test_include_raw_admin_only_and_audited(client, project_with_key, admin_user, monkeypatch):
    token, project_id = project_with_key[0], project_with_key[2]
    email = admin_user[1]
    h = {"Authorization": f"Bearer {token}"}
    log, _ = await _write(project_id)
    url = f"/api/admin/projects/{project_id}/audit-logs/{log.id}"

    monkeypatch.setattr(get_settings(), "ADMIN_EMAILS", "")
    r = await client.get(url, params={"include_raw": "true"}, headers=h)
    assert r.status_code == 403
    r = await client.get(url, headers=h)
    assert r.status_code == 200 and "raw_request" not in r.json()

    monkeypatch.setattr(get_settings(), "ADMIN_EMAILS", email.upper())
    r = await client.get(url, params={"include_raw": "true"}, headers=h)
    assert r.status_code == 200 and "raw_request" in r.json()
    await client.get(url, params={"include_raw": "true"}, headers=h)
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(select(PayloadAccessLog).where(PayloadAccessLog.audit_log_id == log.id))).scalars().all()
    assert len(rows) == 2 and rows[0].user_email == email
