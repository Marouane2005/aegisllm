from datetime import datetime, timezone
from typing import Annotated, Optional, List
from uuid import UUID
from pydantic import AfterValidator, BaseModel, EmailStr, Field, SecretStr


def _as_utc(value: datetime) -> datetime:
    # DB columns are TIMESTAMP WITHOUT TIME ZONE holding UTC. Attach the zone so
    # the JSON says so ("...Z") and browsers don't read it as local time.
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


UTCDateTime = Annotated[datetime, AfterValidator(_as_utc)]


class UserRegister(BaseModel):
    email: EmailStr
    password: SecretStr = Field(..., min_length=8)


class UserLogin(BaseModel):
    email: EmailStr
    password: SecretStr


class UserResponse(BaseModel):
    id: UUID
    email: str
    is_active: bool
    created_at: UTCDateTime
    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    retention_days: int = Field(default=30, ge=1, le=365)


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    retention_days: Optional[int] = Field(None, ge=1, le=365)


class ProjectResponse(BaseModel):
    id: UUID
    name: str
    retention_days: int
    created_at: UTCDateTime
    model_config = {"from_attributes": True}


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


class ApiKeyCreatedResponse(BaseModel):
    id: UUID
    name: str
    key: str
    key_prefix: str
    created_at: UTCDateTime


class ApiKeyResponse(BaseModel):
    id: UUID
    name: str
    key_prefix: str
    is_active: bool
    created_at: UTCDateTime
    last_used_at: Optional[UTCDateTime]
    model_config = {"from_attributes": True}


class ProviderConfigCreate(BaseModel):
    provider: str = Field(..., pattern="^(openai|anthropic)$")
    api_key: SecretStr
    base_url: Optional[str] = Field(None, max_length=255)


class ProviderConfigUpdate(BaseModel):
    api_key: Optional[SecretStr] = None
    base_url: Optional[str] = Field(None, max_length=255)
    is_active: Optional[bool] = None


class ProviderConfigResponse(BaseModel):
    id: UUID
    provider: str
    base_url: Optional[str]
    is_active: bool
    created_at: UTCDateTime
    model_config = {"from_attributes": True}


class AuditLogResponse(BaseModel):
    id: UUID
    request_id: str
    provider: str
    model: str
    timestamp: UTCDateTime
    latency_ms: int
    input_tokens: int
    output_tokens: int
    action_taken: str
    threat_summary: dict
    status_code: int
    client_ip: Optional[str]
    model_config = {"from_attributes": True}


class AuditListResponse(BaseModel):
    items: List[AuditLogResponse]
    next_cursor: Optional[str] = None
    total_count: int


class MetricsResponse(BaseModel):
    total_requests: int
    blocked_requests: int
    masked_requests: int
    allowed_requests: int
    rate_limited_requests: int = 0
    avg_latency_ms: float
    p95_latency_ms: float
    total_input_tokens: int
    total_output_tokens: int
    requests_by_provider: dict
    requests_by_action: dict
