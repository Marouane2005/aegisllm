import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, DateTime, Boolean, Integer, ForeignKey, Text, Index,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.db.base_class import Base


class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Project(Base):
    __tablename__ = "projects"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(100), nullable=False)
    retention_days = Column(Integer, default=30, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ProviderConfig(Base):
    __tablename__ = "provider_configs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(50), nullable=False)
    encrypted_api_key = Column(Text, nullable=False)
    base_url = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_provider_project_name", "project_id", "provider", unique=True),
    )


class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    key_prefix = Column(String(20), nullable=False)
    name = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    request_id = Column(String(64), unique=True, nullable=False, index=True)
    provider = Column(String(50), nullable=False)
    model = Column(String(100), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    latency_ms = Column(Integer, nullable=False)
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    action_taken = Column(String(20), nullable=False, index=True)
    threat_summary = Column(JSONB, default=dict, nullable=False)
    status_code = Column(Integer, nullable=False)
    client_ip = Column(String(45), nullable=True)

    __table_args__ = (
        Index("ix_audit_project_time", "project_id", "timestamp"),
    )


class AuditPayload(Base):
    __tablename__ = "audit_payloads"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_log_id = Column(
        UUID(as_uuid=True),
        ForeignKey("audit_logs.id", ondelete="CASCADE"),
        unique=True, nullable=False, index=True,
    )
    raw_request = Column(Text, nullable=True)
    masked_request = Column(Text, nullable=True)
    raw_response = Column(Text, nullable=True)
    masked_response = Column(Text, nullable=True)


class PayloadAccessLog(Base):
    """One row per read of raw (unmasked) audit payloads."""
    __tablename__ = "payload_access_logs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    user_email = Column(String(255), nullable=False)
    project_id = Column(UUID(as_uuid=True), nullable=False)
    audit_log_id = Column(UUID(as_uuid=True), nullable=False)
    client_ip = Column(String(64), nullable=True)
    accessed_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
