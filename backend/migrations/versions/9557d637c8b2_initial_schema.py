"""Initial schema

Revision ID: 9557d637c8b2
Revises: 
Create Date: 2026-09-05 19:20:56.121957

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9557d637c8b2'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # cases
    op.create_table(
        'cases',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
    )

    # emails
    op.create_table(
        'emails',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('case_id', sa.Integer(), sa.ForeignKey('cases.id', ondelete='SET NULL'), nullable=True),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('filename', sa.String(length=512), nullable=True),
        sa.Column('size', sa.BigInteger(), nullable=False),
        sa.Column('subject', sa.Text(), nullable=True),
        sa.Column('sender', sa.String(length=512), nullable=True),
        sa.Column('sender_name', sa.String(length=512), nullable=True),
        sa.Column('reply_to', sa.String(length=512), nullable=True),
        sa.Column('to', sa.JSON(), nullable=True),
        sa.Column('cc', sa.JSON(), nullable=True),
        sa.Column('message_id', sa.String(length=512), nullable=True),
        sa.Column('date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('body_text', sa.Text(), nullable=True),
        sa.Column('body_html', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
    )
    op.create_index('idx_emails_sha256', 'emails', ['sha256'])
    op.create_index('idx_emails_case_id', 'emails', ['case_id'])

    # email_headers
    op.create_table(
        'email_headers',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('email_id', sa.Integer(), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('position', sa.Integer(), nullable=False),
    )
    op.create_index('idx_email_headers_email_id', 'email_headers', ['email_id'])

    # attachments
    op.create_table(
        'attachments',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('email_id', sa.Integer(), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('filename', sa.String(length=512), nullable=True),
        sa.Column('content_type', sa.String(length=256), nullable=False),
        sa.Column('size', sa.BigInteger(), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('content', sa.LargeBinary(), nullable=True),
    )
    op.create_index('idx_attachments_email_id', 'attachments', ['email_id'])

    # email_authentication_results
    op.create_table(
        'email_authentication_results',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('email_id', sa.Integer(), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('mechanism', sa.String(length=32), nullable=False),
        sa.Column('result', sa.String(length=32), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=True),
        sa.Column('selector', sa.String(length=255), nullable=True),
        sa.Column('aligned', sa.Boolean(), nullable=True),
        sa.Column('source', sa.String(length=32), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('checked_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
    )
    op.create_index('idx_auth_results_email_id', 'email_authentication_results', ['email_id'])

    # audit_log
    op.create_table(
        'audit_log',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('entity_type', sa.String(length=32), nullable=False),
        sa.Column('entity_id', sa.Integer(), nullable=True),
        sa.Column('actor', sa.String(length=128), nullable=False, server_default='system'),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('previous_hash', sa.String(length=64), nullable=True),
        sa.Column('entry_hash', sa.String(length=64), nullable=False),
    )
    op.create_index('idx_audit_log_timestamp', 'audit_log', ['timestamp'])

    # evidence_chain
    op.create_table(
        'evidence_chain',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('email_id', sa.Integer(), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('evidence_id', sa.String(length=64), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('content_hash', sa.String(length=64), nullable=False),
        sa.Column('previous_hash', sa.String(length=64), nullable=True),
        sa.Column('chain_hash', sa.String(length=64), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('details', sa.Text(), nullable=True),
    )
    op.create_index('idx_evidence_chain_email_id', 'evidence_chain', ['email_id'])
    op.create_index('idx_evidence_chain_evidence_id', 'evidence_chain', ['evidence_id'])


def downgrade() -> None:
    op.drop_table('evidence_chain')
    op.drop_table('audit_log')
    op.drop_table('email_authentication_results')
    op.drop_table('attachments')
    op.drop_table('email_headers')
    op.drop_table('emails')
    op.drop_table('cases')
