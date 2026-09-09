"""Add TOTP multi-factor authentication to users.

The report lists MFA among implemented Protect controls (Tables III, VI, VIII)
while login checked only an email address and a password. TOTP rather than
emailed codes because SMTP is not configured on the deployment: an emailed
second factor would lock every account out the moment it was enforced.

The secret is stored encrypted, not in plaintext. A readable TOTP secret in
the database is equivalent to no second factor against anyone who reaches it.

Revision ID: 004
Revises: 003
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_secret_encrypted", sa.Text(), nullable=True))
    op.add_column(
        "users",
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    # Hashed, never stored in the clear — they are password-equivalent.
    op.add_column(
        "users", sa.Column("totp_recovery_hashes", postgresql.JSONB(), nullable=True)
    )
    op.add_column(
        "users", sa.Column("totp_enrolled_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    for column in (
        "totp_enrolled_at",
        "totp_recovery_hashes",
        "totp_enabled",
        "totp_secret_encrypted",
    ):
        op.drop_column("users", column)
