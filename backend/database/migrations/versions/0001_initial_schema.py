"""initial schema

Revision ID: 0001
Revises: 
Create Date: 2026-11-05 22:07:40.093458
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
import backend.database


revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('endpoints',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=False),
    sa.Column('operating_system', sa.String(length=128), nullable=False),
    sa.Column('agent_version', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('last_seen', backend.database.UTCDateTime(), nullable=True),
    sa.Column('started_at', backend.database.UTCDateTime(), nullable=True),
    sa.Column('current_risk_score', sa.Float(), nullable=False),
    sa.Column('current_risk_level', sa.String(length=16), nullable=False),
    sa.Column('risk_details', sa.JSON(), nullable=True),
    sa.Column('health', sa.JSON(), nullable=True),
    sa.Column('capabilities', sa.JSON(), nullable=True),
    sa.Column('policy_version', sa.Integer(), nullable=True),
    sa.Column('created_at', backend.database.UTCDateTime(), nullable=False),
    sa.CheckConstraint("status IN ('online','offline','degraded','starting','stopped')", name=op.f('ck_endpoints_status_valid')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_endpoints')),
    sa.UniqueConstraint('hostname', name=op.f('uq_endpoints_hostname'))
    )
    with op.batch_alter_table('endpoints', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_endpoints_last_seen'), ['last_seen'], unique=False)

    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('failed_login_count', sa.Integer(), nullable=False),
    sa.Column('locked_until', backend.database.UTCDateTime(), nullable=True),
    sa.Column('last_login', backend.database.UTCDateTime(), nullable=True),
    sa.Column('created_at', backend.database.UTCDateTime(), nullable=False),
    sa.CheckConstraint("role IN ('admin','analyst','viewer')", name=op.f('ck_users_role_valid')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users')),
    sa.UniqueConstraint('email', name=op.f('uq_users_email')),
    sa.UniqueConstraint('username', name=op.f('uq_users_username'))
    )
    op.create_table('agent_commands',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=False),
    sa.Column('command', sa.String(length=64), nullable=False),
    sa.Column('params', sa.JSON(), nullable=True),
    sa.Column('signature', sa.String(length=128), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('created_by', sa.Integer(), nullable=True),
    sa.Column('created_at', backend.database.UTCDateTime(), nullable=False),
    sa.Column('started_at', backend.database.UTCDateTime(), nullable=True),
    sa.Column('completed_at', backend.database.UTCDateTime(), nullable=True),
    sa.Column('result', sa.JSON(), nullable=True),
    sa.CheckConstraint("status IN ('pending','running','completed','failed','rejected','expired')", name=op.f('ck_agent_commands_status_valid')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_agent_commands_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], name=op.f('fk_agent_commands_endpoint_id_endpoints'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_agent_commands'))
    )
    with op.batch_alter_table('agent_commands', schema=None) as batch_op:
        batch_op.create_index('ix_agent_commands_pending', ['endpoint_id', 'status'], unique=False)

    op.create_table('audit_logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('username', sa.String(length=64), nullable=True),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('resource', sa.String(length=255), nullable=False),
    sa.Column('timestamp', backend.database.UTCDateTime(), nullable=False),
    sa.Column('result', sa.String(length=16), nullable=False),
    sa.Column('ip_address', sa.String(length=64), nullable=True),
    sa.Column('details', sa.JSON(), nullable=True),
    sa.Column('prev_hash', sa.String(length=64), nullable=False),
    sa.Column('entry_hash', sa.String(length=64), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_audit_logs_user_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_logs')),
    sa.UniqueConstraint('entry_hash', name=op.f('uq_audit_logs_entry_hash'))
    )
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_logs_timestamp'), ['timestamp'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_logs_user_id'), ['user_id'], unique=False)

    op.create_table('canary_files',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=False),
    sa.Column('file_path', sa.String(length=2048), nullable=False),
    sa.Column('directory', sa.String(length=2048), nullable=False),
    sa.Column('canary_type', sa.String(length=16), nullable=False),
    sa.Column('original_hash', sa.String(length=64), nullable=False),
    sa.Column('file_size', sa.BigInteger(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('last_verified', backend.database.UTCDateTime(), nullable=True),
    sa.Column('last_interaction', backend.database.UTCDateTime(), nullable=True),
    sa.Column('last_interaction_type', sa.String(length=32), nullable=True),
    sa.Column('trigger_count', sa.Integer(), nullable=False),
    sa.Column('generation', sa.Integer(), nullable=False),
    sa.Column('created_at', backend.database.UTCDateTime(), nullable=False),
    sa.CheckConstraint("status IN ('active','triggered','missing','regenerating','retired','error')", name=op.f('ck_canary_files_status_valid')),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], name=op.f('fk_canary_files_endpoint_id_endpoints'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_canary_files')),
    sa.UniqueConstraint('endpoint_id', 'file_path', name='uq_canary_endpoint_path')
    )
    with op.batch_alter_table('canary_files', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_canary_files_endpoint_id'), ['endpoint_id'], unique=False)

    op.create_table('entropy_history',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=True),
    sa.Column('file_path', sa.String(length=2048), nullable=False),
    sa.Column('file_category', sa.String(length=32), nullable=True),
    sa.Column('previous_entropy', sa.Float(), nullable=True),
    sa.Column('current_entropy', sa.Float(), nullable=False),
    sa.Column('entropy_delta', sa.Float(), nullable=True),
    sa.Column('max_chunk_entropy', sa.Float(), nullable=True),
    sa.Column('magic_ok', sa.Boolean(), nullable=True),
    sa.Column('suspicious', sa.Boolean(), nullable=False),
    sa.Column('reason', sa.String(length=255), nullable=True),
    sa.Column('timestamp', backend.database.UTCDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], name=op.f('fk_entropy_history_endpoint_id_endpoints'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_entropy_history'))
    )
    with op.batch_alter_table('entropy_history', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_entropy_history_endpoint_id'), ['endpoint_id'], unique=False)
        batch_op.create_index('ix_entropy_history_path_ts', ['file_path', 'timestamp'], unique=False)
        batch_op.create_index(batch_op.f('ix_entropy_history_timestamp'), ['timestamp'], unique=False)

    op.create_table('file_events',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=False),
    sa.Column('file_path', sa.String(length=2048), nullable=False),
    sa.Column('dest_path', sa.String(length=2048), nullable=True),
    sa.Column('event_type', sa.String(length=32), nullable=False),
    sa.Column('is_directory', sa.Boolean(), nullable=False),
    sa.Column('process_id', sa.Integer(), nullable=True),
    sa.Column('process_name', sa.String(length=255), nullable=True),
    sa.Column('attribution', sa.String(length=32), nullable=True),
    sa.Column('file_size', sa.BigInteger(), nullable=True),
    sa.Column('timestamp', backend.database.UTCDateTime(), nullable=False),
    sa.Column('metadata', sa.JSON(), nullable=True),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], name=op.f('fk_file_events_endpoint_id_endpoints'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_file_events'))
    )
    with op.batch_alter_table('file_events', schema=None) as batch_op:
        batch_op.create_index('ix_file_events_endpoint_ts', ['endpoint_id', 'timestamp'], unique=False)
        batch_op.create_index('ix_file_events_path', ['file_path'], unique=False)
        batch_op.create_index(batch_op.f('ix_file_events_process_id'), ['process_id'], unique=False)
        batch_op.create_index('ix_file_events_type_ts', ['event_type', 'timestamp'], unique=False)

    op.create_table('file_inventory',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=False),
    sa.Column('file_path', sa.String(length=2048), nullable=False),
    sa.Column('extension', sa.String(length=32), nullable=True),
    sa.Column('category', sa.String(length=32), nullable=True),
    sa.Column('size', sa.BigInteger(), nullable=True),
    sa.Column('mtime', sa.Float(), nullable=True),
    sa.Column('entropy', sa.Float(), nullable=True),
    sa.Column('magic_ok', sa.Boolean(), nullable=True),
    sa.Column('last_scanned', backend.database.UTCDateTime(), nullable=True),
    sa.Column('last_modified_event', backend.database.UTCDateTime(), nullable=True),
    sa.Column('deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], name=op.f('fk_file_inventory_endpoint_id_endpoints'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_file_inventory')),
    sa.UniqueConstraint('endpoint_id', 'file_path', name='uq_file_inventory_endpoint_path')
    )
    with op.batch_alter_table('file_inventory', schema=None) as batch_op:
        batch_op.create_index('ix_file_inventory_category', ['category'], unique=False)

    op.create_table('incidents',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('risk_score', sa.Float(), nullable=False),
    sa.Column('summary', sa.Text(), nullable=True),
    sa.Column('affected_files', sa.JSON(), nullable=True),
    sa.Column('affected_directories', sa.JSON(), nullable=True),
    sa.Column('affected_processes', sa.JSON(), nullable=True),
    sa.Column('signals', sa.JSON(), nullable=True),
    sa.Column('response_status', sa.String(length=32), nullable=False),
    sa.Column('response_level', sa.String(length=16), nullable=True),
    sa.Column('created_at', backend.database.UTCDateTime(), nullable=False),
    sa.Column('updated_at', backend.database.UTCDateTime(), nullable=False),
    sa.Column('acknowledged_by', sa.Integer(), nullable=True),
    sa.Column('acknowledged_at', backend.database.UTCDateTime(), nullable=True),
    sa.Column('resolved_by', sa.Integer(), nullable=True),
    sa.Column('resolved_at', backend.database.UTCDateTime(), nullable=True),
    sa.Column('resolution_note', sa.Text(), nullable=True),
    sa.CheckConstraint("response_status IN ('open','acknowledged','containing','contained','resolved','false_positive')", name=op.f('ck_incidents_response_status_valid')),
    sa.ForeignKeyConstraint(['acknowledged_by'], ['users.id'], name=op.f('fk_incidents_acknowledged_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], name=op.f('fk_incidents_endpoint_id_endpoints'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], name=op.f('fk_incidents_resolved_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_incidents'))
    )
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_incidents_created_at'), ['created_at'], unique=False)
        batch_op.create_index('ix_incidents_endpoint_status', ['endpoint_id', 'response_status'], unique=False)

    op.create_table('monitored_directories',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=False),
    sa.Column('directory_path', sa.String(length=1024), nullable=False),
    sa.Column('recursive', sa.Boolean(), nullable=False),
    sa.Column('monitoring_enabled', sa.Boolean(), nullable=False),
    sa.Column('signature', sa.String(length=128), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('status_detail', sa.String(length=512), nullable=True),
    sa.Column('protected', sa.Boolean(), nullable=False),
    sa.Column('created_by', sa.Integer(), nullable=True),
    sa.Column('created_at', backend.database.UTCDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_monitored_directories_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], name=op.f('fk_monitored_directories_endpoint_id_endpoints'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_monitored_directories')),
    sa.UniqueConstraint('endpoint_id', 'directory_path', name='uq_monitored_dir_endpoint_path')
    )
    with op.batch_alter_table('monitored_directories', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_monitored_directories_endpoint_id'), ['endpoint_id'], unique=False)

    op.create_table('processes',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=False),
    sa.Column('process_id', sa.Integer(), nullable=False),
    sa.Column('process_name', sa.String(length=255), nullable=False),
    sa.Column('executable_path', sa.String(length=2048), nullable=True),
    sa.Column('command_line', sa.Text(), nullable=True),
    sa.Column('parent_process_id', sa.Integer(), nullable=True),
    sa.Column('username', sa.String(length=255), nullable=True),
    sa.Column('create_time', sa.Float(), nullable=False),
    sa.Column('first_seen', backend.database.UTCDateTime(), nullable=False),
    sa.Column('last_seen', backend.database.UTCDateTime(), nullable=False),
    sa.Column('is_running', sa.Boolean(), nullable=False),
    sa.Column('state', sa.String(length=16), nullable=False),
    sa.Column('cpu_percent', sa.Float(), nullable=True),
    sa.Column('memory_rss', sa.BigInteger(), nullable=True),
    sa.Column('write_bytes_rate', sa.Float(), nullable=True),
    sa.Column('total_write_bytes', sa.BigInteger(), nullable=True),
    sa.Column('files_modified', sa.Integer(), nullable=False),
    sa.Column('suspicious', sa.Boolean(), nullable=False),
    sa.Column('risk_score', sa.Float(), nullable=False),
    sa.Column('suspicion_reasons', sa.JSON(), nullable=True),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], name=op.f('fk_processes_endpoint_id_endpoints'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_processes')),
    sa.UniqueConstraint('endpoint_id', 'process_id', 'create_time', name='uq_process_identity')
    )
    with op.batch_alter_table('processes', schema=None) as batch_op:
        batch_op.create_index('ix_processes_running', ['endpoint_id', 'is_running'], unique=False)

    op.create_table('refresh_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('family_id', sa.String(length=36), nullable=False),
    sa.Column('expires_at', backend.database.UTCDateTime(), nullable=False),
    sa.Column('revoked_at', backend.database.UTCDateTime(), nullable=True),
    sa.Column('replaced_by', sa.Integer(), nullable=True),
    sa.Column('created_at', backend.database.UTCDateTime(), nullable=False),
    sa.Column('ip_address', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_refresh_tokens_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_refresh_tokens')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_refresh_tokens_token_hash'))
    )
    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_refresh_tokens_family_id'), ['family_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_refresh_tokens_user_id'), ['user_id'], unique=False)

    op.create_table('snapshots',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=False),
    sa.Column('source_directory', sa.String(length=2048), nullable=False),
    sa.Column('snapshot_path', sa.String(length=2048), nullable=False),
    sa.Column('file_count', sa.Integer(), nullable=False),
    sa.Column('total_bytes', sa.BigInteger(), nullable=False),
    sa.Column('manifest_hash', sa.String(length=64), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('created_at', backend.database.UTCDateTime(), nullable=False),
    sa.Column('verified_at', backend.database.UTCDateTime(), nullable=True),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], name=op.f('fk_snapshots_endpoint_id_endpoints'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_snapshots'))
    )
    op.create_table('system_configuration',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('policy', sa.JSON(), nullable=False),
    sa.Column('signature', sa.String(length=128), nullable=False),
    sa.Column('created_by', sa.Integer(), nullable=True),
    sa.Column('comment', sa.String(length=512), nullable=True),
    sa.Column('created_at', backend.database.UTCDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_system_configuration_created_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_system_configuration')),
    sa.UniqueConstraint('version', name=op.f('uq_system_configuration_version'))
    )
    op.create_table('evidence_items',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=False),
    sa.Column('incident_id', sa.Integer(), nullable=True),
    sa.Column('item_type', sa.String(length=32), nullable=False),
    sa.Column('original_path', sa.String(length=2048), nullable=True),
    sa.Column('stored_path', sa.String(length=2048), nullable=True),
    sa.Column('sha256', sa.String(length=64), nullable=True),
    sa.Column('size', sa.BigInteger(), nullable=True),
    sa.Column('details', sa.JSON(), nullable=True),
    sa.Column('created_at', backend.database.UTCDateTime(), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], name=op.f('fk_evidence_items_endpoint_id_endpoints'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_evidence_items_incident_id_incidents'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_evidence_items'))
    )
    with op.batch_alter_table('evidence_items', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_evidence_items_incident_id'), ['incident_id'], unique=False)

    op.create_table('response_actions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=False),
    sa.Column('incident_id', sa.Integer(), nullable=True),
    sa.Column('response_level', sa.String(length=16), nullable=False),
    sa.Column('action_type', sa.String(length=48), nullable=False),
    sa.Column('target', sa.JSON(), nullable=True),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('requires_approval', sa.Boolean(), nullable=False),
    sa.Column('requested_by', sa.String(length=64), nullable=False),
    sa.Column('approved_by', sa.Integer(), nullable=True),
    sa.Column('reason', sa.Text(), nullable=True),
    sa.Column('result', sa.JSON(), nullable=True),
    sa.Column('rollback_data', sa.JSON(), nullable=True),
    sa.Column('created_at', backend.database.UTCDateTime(), nullable=False),
    sa.Column('decided_at', backend.database.UTCDateTime(), nullable=True),
    sa.Column('executed_at', backend.database.UTCDateTime(), nullable=True),
    sa.Column('expires_at', backend.database.UTCDateTime(), nullable=True),
    sa.CheckConstraint("status IN ('pending_approval','approved','executing','completed','failed','rejected','expired','rolled_back','skipped')", name=op.f('ck_response_actions_status_valid')),
    sa.ForeignKeyConstraint(['approved_by'], ['users.id'], name=op.f('fk_response_actions_approved_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], name=op.f('fk_response_actions_endpoint_id_endpoints'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_response_actions_incident_id_incidents'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_response_actions'))
    )
    with op.batch_alter_table('response_actions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_response_actions_incident_id'), ['incident_id'], unique=False)
        batch_op.create_index('ix_response_actions_status', ['status'], unique=False)

    op.create_table('security_alerts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=False),
    sa.Column('incident_id', sa.Integer(), nullable=True),
    sa.Column('alert_type', sa.String(length=64), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('risk_score', sa.Float(), nullable=False),
    sa.Column('risk_level', sa.String(length=16), nullable=True),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('signals', sa.JSON(), nullable=True),
    sa.Column('file_paths', sa.JSON(), nullable=True),
    sa.Column('process_info', sa.JSON(), nullable=True),
    sa.Column('timestamp', backend.database.UTCDateTime(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('feedback', sa.String(length=32), nullable=True),
    sa.Column('feedback_note', sa.Text(), nullable=True),
    sa.Column('feedback_by', sa.Integer(), nullable=True),
    sa.CheckConstraint("severity IN ('info','low','medium','high','critical')", name=op.f('ck_security_alerts_severity_valid')),
    sa.CheckConstraint("status IN ('new','acknowledged','investigating','resolved','false_positive')", name=op.f('ck_security_alerts_status_valid')),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], name=op.f('fk_security_alerts_endpoint_id_endpoints'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['feedback_by'], ['users.id'], name=op.f('fk_security_alerts_feedback_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_security_alerts_incident_id_incidents'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_security_alerts'))
    )
    with op.batch_alter_table('security_alerts', schema=None) as batch_op:
        batch_op.create_index('ix_security_alerts_endpoint_ts', ['endpoint_id', 'timestamp'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_alerts_incident_id'), ['incident_id'], unique=False)
        batch_op.create_index('ix_security_alerts_status_ts', ['status', 'timestamp'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('security_alerts', schema=None) as batch_op:
        batch_op.drop_index('ix_security_alerts_status_ts')
        batch_op.drop_index(batch_op.f('ix_security_alerts_incident_id'))
        batch_op.drop_index('ix_security_alerts_endpoint_ts')

    op.drop_table('security_alerts')
    with op.batch_alter_table('response_actions', schema=None) as batch_op:
        batch_op.drop_index('ix_response_actions_status')
        batch_op.drop_index(batch_op.f('ix_response_actions_incident_id'))

    op.drop_table('response_actions')
    with op.batch_alter_table('evidence_items', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_evidence_items_incident_id'))

    op.drop_table('evidence_items')
    op.drop_table('system_configuration')
    op.drop_table('snapshots')
    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_refresh_tokens_user_id'))
        batch_op.drop_index(batch_op.f('ix_refresh_tokens_family_id'))

    op.drop_table('refresh_tokens')
    with op.batch_alter_table('processes', schema=None) as batch_op:
        batch_op.drop_index('ix_processes_running')

    op.drop_table('processes')
    with op.batch_alter_table('monitored_directories', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_monitored_directories_endpoint_id'))

    op.drop_table('monitored_directories')
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.drop_index('ix_incidents_endpoint_status')
        batch_op.drop_index(batch_op.f('ix_incidents_created_at'))

    op.drop_table('incidents')
    with op.batch_alter_table('file_inventory', schema=None) as batch_op:
        batch_op.drop_index('ix_file_inventory_category')

    op.drop_table('file_inventory')
    with op.batch_alter_table('file_events', schema=None) as batch_op:
        batch_op.drop_index('ix_file_events_type_ts')
        batch_op.drop_index(batch_op.f('ix_file_events_process_id'))
        batch_op.drop_index('ix_file_events_path')
        batch_op.drop_index('ix_file_events_endpoint_ts')

    op.drop_table('file_events')
    with op.batch_alter_table('entropy_history', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_entropy_history_timestamp'))
        batch_op.drop_index('ix_entropy_history_path_ts')
        batch_op.drop_index(batch_op.f('ix_entropy_history_endpoint_id'))

    op.drop_table('entropy_history')
    with op.batch_alter_table('canary_files', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_canary_files_endpoint_id'))

    op.drop_table('canary_files')
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_audit_logs_user_id'))
        batch_op.drop_index(batch_op.f('ix_audit_logs_timestamp'))

    op.drop_table('audit_logs')
    with op.batch_alter_table('agent_commands', schema=None) as batch_op:
        batch_op.drop_index('ix_agent_commands_pending')

    op.drop_table('agent_commands')
    op.drop_table('users')
    with op.batch_alter_table('endpoints', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_endpoints_last_seen'))

    op.drop_table('endpoints')
