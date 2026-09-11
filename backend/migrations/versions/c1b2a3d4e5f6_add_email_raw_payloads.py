"""Add email_raw_payloads table for pristine evidence preservation

Revision ID: c1b2a3d4e5f6
Revises: 9557d637c8b2
Create Date: 2026-09-06 18:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c1b2a3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '9557d637c8b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'email_raw_payloads',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('email_id', sa.Integer(), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('raw_bytes', sa.LargeBinary(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.UniqueConstraint('email_id', name='uq_email_raw_payloads_email_id'),
    )
    op.create_index('idx_raw_payloads_email_id', 'email_raw_payloads', ['email_id'])
    op.create_index('idx_raw_payloads_sha256', 'email_raw_payloads', ['sha256'])


def downgrade() -> None:
    op.drop_index('idx_raw_payloads_sha256', table_name='email_raw_payloads')
    op.drop_index('idx_raw_payloads_email_id', table_name='email_raw_payloads')
    op.drop_table('email_raw_payloads')
