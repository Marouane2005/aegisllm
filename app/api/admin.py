import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
import logging
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, is_admin
from app.core.security import generate_api_key, encrypt_secret
from app.db.session import get_db
from app.db.models import User, Project, ApiKey, ProviderConfig, AuditLog, AuditPayload, PayloadAccessLog
from app.schemas.admin import (
    ProjectCreate, ProjectUpdate, ProjectResponse,
    ApiKeyCreate, ApiKeyCreatedResponse, ApiKeyResponse,
    ProviderConfigCreate, ProviderConfigUpdate, ProviderConfigResponse,
    AuditLogResponse, AuditListResponse, MetricsResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter()


def encode_cursor(timestamp: datetime, log_id: uuid.UUID) -> str:
    data = {"t": timestamp.isoformat(), "i": str(log_id)}
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()


def decode_cursor(cursor: str):
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        return datetime.fromisoformat(data["t"]), uuid.UUID(data["i"])
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid cursor")


# ---------- Projects ----------

@router.post("/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(data: ProjectCreate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = Project(owner_id=current_user.id, name=data.name, retention_days=data.retention_days)
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


@router.get("/projects", response_model=list[ProjectResponse])
async def list_projects(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.owner_id == current_user.id).order_by(Project.created_at.desc()))
    return result.scalars().all()


@router.get("/projects/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: uuid.UUID, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.patch("/projects/{project_id}", response_model=ProjectResponse)
async def update_project(project_id: uuid.UUID, data: ProjectUpdate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if data.name is not None:
        project.name = data.name
    if data.retention_days is not None:
        project.retention_days = data.retention_days
    await db.commit()
    await db.refresh(project)
    return project


@router.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(project_id: uuid.UUID, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    await db.delete(project)
    await db.commit()


# ---------- API Keys ----------

@router.post("/projects/{project_id}/api-keys", response_model=ApiKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(project_id: uuid.UUID, data: ApiKeyCreate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")
    raw_key, prefix, key_hash = generate_api_key()
    api_key = ApiKey(project_id=project_id, name=data.name, key_hash=key_hash, key_prefix=prefix)
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    return ApiKeyCreatedResponse(id=api_key.id, name=api_key.name, key=raw_key, key_prefix=api_key.key_prefix, created_at=api_key.created_at)


@router.get("/projects/{project_id}/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(project_id: uuid.UUID, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")
    result = await db.execute(select(ApiKey).where(ApiKey.project_id == project_id).order_by(ApiKey.created_at.desc()))
    return result.scalars().all()


@router.delete("/projects/{project_id}/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(project_id: uuid.UUID, key_id: uuid.UUID, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")
    result = await db.execute(select(ApiKey).where(ApiKey.id == key_id, ApiKey.project_id == project_id))
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    api_key.is_active = False
    await db.commit()


# ---------- Provider Configs ----------

@router.post("/projects/{project_id}/providers", response_model=ProviderConfigResponse, status_code=status.HTTP_201_CREATED)
async def create_provider_config(project_id: uuid.UUID, data: ProviderConfigCreate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")
    result = await db.execute(select(ProviderConfig).where(ProviderConfig.project_id == project_id, ProviderConfig.provider == data.provider))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f"Provider '{data.provider}' already configured")
    encrypted_key = encrypt_secret(data.api_key.get_secret_value())
    config = ProviderConfig(project_id=project_id, provider=data.provider, encrypted_api_key=encrypted_key, base_url=data.base_url)
    db.add(config)
    await db.commit()
    await db.refresh(config)
    return config


@router.get("/projects/{project_id}/providers", response_model=list[ProviderConfigResponse])
async def list_provider_configs(project_id: uuid.UUID, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")
    result = await db.execute(select(ProviderConfig).where(ProviderConfig.project_id == project_id))
    return result.scalars().all()


@router.patch("/projects/{project_id}/providers/{config_id}", response_model=ProviderConfigResponse)
async def update_provider_config(project_id: uuid.UUID, config_id: uuid.UUID, data: ProviderConfigUpdate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")
    result = await db.execute(select(ProviderConfig).where(ProviderConfig.id == config_id, ProviderConfig.project_id == project_id))
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail="Provider config not found")
    if data.api_key is not None:
        config.encrypted_api_key = encrypt_secret(data.api_key.get_secret_value())
    if data.base_url is not None:
        config.base_url = data.base_url
    if data.is_active is not None:
        config.is_active = data.is_active
    await db.commit()
    await db.refresh(config)
    return config


# ---------- Audit Logs ----------

@router.get("/projects/{project_id}/audit-logs", response_model=AuditListResponse)
async def list_audit_logs(
    project_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    action_taken: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    request_id: Optional[str] = Query(None),
):
    result = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    start_dt = end_dt = None
    if start_time:
        try:
            start_dt = datetime.fromisoformat(start_time)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start_time format")
    if end_time:
        try:
            end_dt = datetime.fromisoformat(end_time)
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end_time format")

    conditions = [AuditLog.project_id == project_id]
    if action_taken:
        conditions.append(AuditLog.action_taken == action_taken)
    if provider:
        conditions.append(AuditLog.provider == provider)
    if start_dt:
        conditions.append(AuditLog.timestamp >= start_dt)
    if end_dt:
        conditions.append(AuditLog.timestamp <= end_dt)
    if request_id:
        conditions.append(AuditLog.request_id == request_id)

    count_conditions = list(conditions)
    total_result = await db.execute(select(func.count(AuditLog.id)).where(*count_conditions))
    total_count = total_result.scalar() or 0

    if cursor:
        cursor_ts, cursor_id = decode_cursor(cursor)
        conditions.append(
            (AuditLog.timestamp < cursor_ts) |
            ((AuditLog.timestamp == cursor_ts) & (AuditLog.id < cursor_id))
        )

    query = select(AuditLog).where(*conditions).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).limit(limit)
    result = await db.execute(query)
    items = result.scalars().all()

    next_cursor = encode_cursor(items[-1].timestamp, items[-1].id) if len(items) == limit else None
    return AuditListResponse(
        items=[AuditLogResponse.model_validate(item) for item in items],
        next_cursor=next_cursor,
        total_count=total_count,
    )


@router.get("/projects/{project_id}/audit-logs/{log_id}")
async def get_audit_payload(
    request: Request,
    project_id: uuid.UUID,
    log_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    include_raw: bool = Query(False),
):
    if include_raw and not is_admin(current_user):
        raise HTTPException(status_code=403, detail="include_raw requires an admin account")
    result = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")
    result = await db.execute(
        select(AuditPayload).join(AuditLog).where(AuditLog.id == log_id, AuditLog.project_id == project_id)
    )
    payload = result.scalar_one_or_none()
    if not payload:
        raise HTTPException(status_code=404, detail="Audit payload not found")
    response_data = {
        "id": payload.id,
        "audit_log_id": payload.audit_log_id,
        "masked_request": payload.masked_request,
        "masked_response": payload.masked_response,
    }
    if include_raw:
        db.add(PayloadAccessLog(
            user_id=current_user.id, user_email=current_user.email, project_id=project_id,
            audit_log_id=log_id, client_ip=request.client.host if request.client else None,
        ))
        await db.commit()
        logger.warning("raw payload access user=%s log=%s", current_user.email, log_id)
        response_data["raw_request"] = payload.raw_request
        response_data["raw_response"] = payload.raw_response
    return response_data


# ---------- Metrics ----------

@router.get("/projects/{project_id}/metrics", response_model=MetricsResponse)
async def get_metrics(
    project_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    hours: int = Query(24, ge=1, le=720),
):
    result = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    base_where = [AuditLog.project_id == project_id, AuditLog.timestamp >= cutoff]

    total_result = await db.execute(select(func.count(AuditLog.id)).where(*base_where))
    total_requests = total_result.scalar() or 0

    blocked_result = await db.execute(select(func.count(AuditLog.id)).where(*base_where, AuditLog.action_taken == "blocked"))
    blocked_requests = blocked_result.scalar() or 0

    masked_result = await db.execute(select(func.count(AuditLog.id)).where(*base_where, AuditLog.action_taken == "masked"))
    masked_requests = masked_result.scalar() or 0

    allowed_requests = total_requests - blocked_requests - masked_requests

    latency_result = await db.execute(
        select(func.avg(AuditLog.latency_ms), func.percentile_cont(0.95).within_group(AuditLog.latency_ms)).where(*base_where)
    )
    avg_latency, p95_latency = latency_result.one()

    token_result = await db.execute(
        select(func.coalesce(func.sum(AuditLog.input_tokens), 0), func.coalesce(func.sum(AuditLog.output_tokens), 0)).where(*base_where)
    )
    total_input_tokens, total_output_tokens = token_result.one()

    provider_result = await db.execute(
        select(AuditLog.provider, func.count(AuditLog.id)).where(*base_where).group_by(AuditLog.provider)
    )
    requests_by_provider = dict(provider_result.all())

    action_result = await db.execute(
        select(AuditLog.action_taken, func.count(AuditLog.id)).where(*base_where).group_by(AuditLog.action_taken)
    )
    requests_by_action = dict(action_result.all())

    return MetricsResponse(
        total_requests=total_requests,
        blocked_requests=blocked_requests,
        masked_requests=masked_requests,
        allowed_requests=allowed_requests,
        avg_latency_ms=round(float(avg_latency or 0), 2),
        p95_latency_ms=round(float(p95_latency or 0), 2),
        total_input_tokens=total_input_tokens,
        total_output_tokens=total_output_tokens,
        requests_by_provider=requests_by_provider,
        requests_by_action=requests_by_action,
    )
