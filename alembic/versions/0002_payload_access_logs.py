"""payload access audit log

Revision ID: 0002_payload_access_logs
Revises: 0001_initial
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_payload_access_logs"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "payload_access_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("user_email", sa.String(255), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("audit_log_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("client_ip", sa.String(64), nullable=True),
        sa.Column("accessed_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_payload_access_logs_accessed_at", "payload_access_logs", ["accessed_at"])


def downgrade() -> None:
    op.drop_index("ix_payload_access_logs_accessed_at", table_name="payload_access_logs")
    op.drop_table("payload_access_logs")
