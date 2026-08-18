"""initial schema

Revision ID: 001
Revises: 
Create Date: 2025-05-23

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def _create_enum(name: str, values: list[str]) -> None:
    """Create an enum type only if it does not already exist."""
    labels = ", ".join(f"'{value}'" for value in values)
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = '{name}') THEN
                CREATE TYPE {name} AS ENUM ({labels});
            END IF;
        END
        $$;
        """
    )


def upgrade() -> None:
    # --- ENUM TYPES ---
    # PostgreSQL has no `CREATE TYPE ... IF NOT EXISTS`; the previous version
    # used it and every migration run failed with a syntax error, which is why
    # startup silently fell back to metadata.create_all.
    _create_enum("userrole", ["viewer", "analyst", "admin"])
    _create_enum("honeypotmode", ["active", "passive"])
    _create_enum("sessionstatus", ["active", "completed", "terminated"])
    _create_enum("attackseverity", ["low", "medium", "high", "critical"])
    _create_enum(
        "attackcategory",
        ["benign", "reconnaissance", "exploitation", "exfiltration"],
    )
    _create_enum(
        "attackerprofile",
        ["script_kiddie", "automated_bot", "skilled_attacker", "apt", "unknown"],
    )
    _create_enum(
        "alertstatus", ["new", "acknowledged", "resolved", "false_positive"]
    )

    # --- users ---
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('name', sa.String(255), nullable=True),
        sa.Column('role', sa.Enum('viewer', 'analyst', 'admin', name='userrole'), nullable=False, server_default='analyst'),
        sa.Column('is_active', sa.Boolean(), nullable=True, server_default='true'),
        sa.Column('is_verified', sa.Boolean(), nullable=True, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    # --- honeypot_nodes ---
    op.create_table(
        'honeypot_nodes',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('protocol', sa.String(50), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('mode', sa.Enum('active', 'passive', name='honeypotmode'), nullable=False, server_default='active'),
        sa.Column('is_active', sa.Boolean(), nullable=True, server_default='true'),
        sa.Column('location_lat', sa.Float(), nullable=True),
        sa.Column('location_lon', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_heartbeat', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_honeypot_nodes_ip_address', 'honeypot_nodes', ['ip_address'])

    # --- honeypot_sessions ---
    op.create_table(
        'honeypot_sessions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('session_uuid', sa.String(36), nullable=True),
        sa.Column('node_id', sa.Integer(), nullable=False),
        sa.Column('attacker_ip', sa.String(45), nullable=False),
        sa.Column('attacker_port', sa.Integer(), nullable=True),
        sa.Column('geo_country', sa.String(3), nullable=True),
        sa.Column('geo_country_name', sa.String(100), nullable=True),
        sa.Column('geo_city', sa.String(100), nullable=True),
        sa.Column('geo_lat', sa.Float(), nullable=True),
        sa.Column('geo_lon', sa.Float(), nullable=True),
        sa.Column('status', sa.Enum('active', 'completed', 'terminated', name='sessionstatus'), nullable=False, server_default='active'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('attack_category', sa.Enum('benign', 'reconnaissance', 'exploitation', 'exfiltration', name='attackcategory'), nullable=True),
        sa.Column('attack_confidence', sa.Float(), nullable=True),
        sa.Column('attacker_profile', sa.Enum('script_kiddie', 'automated_bot', 'skilled_attacker', 'apt', 'unknown', name='attackerprofile'), nullable=True),
        sa.Column('anomaly_score', sa.Float(), nullable=True),
        sa.Column('is_anomalous', sa.Boolean(), nullable=True, server_default='false'),
        sa.Column('detected_tools', sa.JSON(), nullable=True),
        sa.Column('detected_intents', sa.JSON(), nullable=True),
        sa.Column('command_summary', sa.Text(), nullable=True),
        sa.Column('mitre_tactics', sa.JSON(), nullable=True),
        sa.Column('mitre_techniques', sa.JSON(), nullable=True),
        sa.Column('raw_commands_encrypted', sa.Text(), nullable=True),
        sa.Column('raw_payloads_encrypted', sa.Text(), nullable=True),
        sa.Column('network_packets_summary', sa.JSON(), nullable=True),
        sa.Column('uploaded_files', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['node_id'], ['honeypot_nodes.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_honeypot_sessions_session_uuid', 'honeypot_sessions', ['session_uuid'], unique=True)
    op.create_index('ix_honeypot_sessions_attacker_ip', 'honeypot_sessions', ['attacker_ip'])

    # --- indicators_of_compromise ---
    op.create_table(
        'indicators_of_compromise',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('session_id', sa.Integer(), nullable=False),
        sa.Column('ioc_type', sa.String(50), nullable=False),
        sa.Column('value', sa.String(500), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['session_id'], ['honeypot_sessions.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_indicators_of_compromise_value', 'indicators_of_compromise', ['value'])

    # --- alerts ---
    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('session_id', sa.Integer(), nullable=False),
        sa.Column('severity', sa.Enum('low', 'medium', 'high', 'critical', name='attackseverity'), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.Enum('new', 'acknowledged', 'resolved', 'false_positive', name='alertstatus'), nullable=False, server_default='new'),
        sa.Column('assigned_to_id', sa.Integer(), nullable=True),
        sa.Column('auto_generated', sa.Boolean(), nullable=True, server_default='true'),
        sa.Column('mitre_tactics', sa.JSON(), nullable=True),
        sa.Column('mitre_techniques', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['assigned_to_id'], ['users.id']),
        sa.ForeignKeyConstraint(['session_id'], ['honeypot_sessions.id']),
        sa.PrimaryKeyConstraint('id'),
    )

    # --- audit_logs ---
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(50), nullable=True),
        sa.Column('resource_id', sa.Integer(), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )

    # --- alert_thresholds ---
    op.create_table(
        'alert_thresholds',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('min_severity', sa.Enum('low', 'medium', 'high', 'critical', name='attackseverity'), nullable=True, server_default='medium'),
        sa.Column('anomaly_score_threshold', sa.Float(), nullable=True, server_default='0.7'),
        sa.Column('email_enabled', sa.Boolean(), nullable=True, server_default='true'),
        sa.Column('webhook_enabled', sa.Boolean(), nullable=True, server_default='false'),
        sa.Column('is_active', sa.Boolean(), nullable=True, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )

    # --- otp_verifications ---
    op.create_table(
        'otp_verifications',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('otp_code', sa.String(6), nullable=False),
        sa.Column('purpose', sa.String(50), nullable=False, server_default='email_verification'),
        sa.Column('is_used', sa.Boolean(), nullable=True, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_otp_verifications_email', 'otp_verifications', ['email'])


def downgrade() -> None:
    op.drop_table('otp_verifications')
    op.drop_table('alert_thresholds')
    op.drop_table('audit_logs')
    op.drop_table('alerts')
    op.drop_table('indicators_of_compromise')
    op.drop_table('honeypot_sessions')
    op.drop_table('honeypot_nodes')
    op.drop_table('users')
    op.execute("DROP TYPE IF EXISTS alertstatus")
    op.execute("DROP TYPE IF EXISTS attackerprofile")
    op.execute("DROP TYPE IF EXISTS attackcategory")
    op.execute("DROP TYPE IF EXISTS attackseverity")
    op.execute("DROP TYPE IF EXISTS sessionstatus")
    op.execute("DROP TYPE IF EXISTS honeypotmode")
    op.execute("DROP TYPE IF EXISTS userrole")
