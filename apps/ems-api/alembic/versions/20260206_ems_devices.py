"""create devices table

Revision ID: 20260206_ems_devices
Revises:
Create Date: 2026-02-06
"""

from alembic import op
import sqlalchemy as sa


revision = "20260206_ems_devices"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("devices")
