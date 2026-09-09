"""Record session protocol/command counts and harden OTP storage.

Revision ID: 002
Revises: 001
"""

import sqlalchemy as sa
from alembic import op

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The engine reports the protocol a session was captured on, but it was
    # discarded and every export claimed "ssh".
    op.add_column(
        "honeypot_sessions", sa.Column("protocol", sa.String(20), nullable=True)
    )
    op.add_column(
        "honeypot_sessions",
        sa.Column(
            "command_count", sa.Integer(), nullable=False, server_default="0"
        ),
    )

    # OTPs are now stored as an HMAC-SHA256 hex digest, which needs 64 chars.
    op.alter_column(
        "otp_verifications",
        "otp_code",
        existing_type=sa.String(6),
        type_=sa.String(64),
        existing_nullable=False,
    )
    op.add_column(
        "otp_verifications",
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
    )

    # Any pre-existing codes are plaintext and unusable against the new
    # verification path; retire them so users request a fresh code.
    op.execute("UPDATE otp_verifications SET is_used = true WHERE is_used = false")

    # Dashboard and session-list queries filter and sort on these constantly.
    op.create_index(
        "ix_sessions_started_at", "honeypot_sessions", ["started_at"]
    )
    op.create_index(
        "ix_sessions_attack_category",
        "honeypot_sessions",
        ["attack_category"],
    )
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_alerts_created_at", table_name="alerts")
    op.drop_index("ix_alerts_status", table_name="alerts")
    op.drop_index("ix_sessions_attack_category", table_name="honeypot_sessions")
    op.drop_index("ix_sessions_started_at", table_name="honeypot_sessions")
    op.drop_column("otp_verifications", "attempts")
    op.alter_column(
        "otp_verifications",
        "otp_code",
        existing_type=sa.String(64),
        type_=sa.String(6),
        existing_nullable=False,
    )
    op.drop_column("honeypot_sessions", "command_count")
    op.drop_column("honeypot_sessions", "protocol")
