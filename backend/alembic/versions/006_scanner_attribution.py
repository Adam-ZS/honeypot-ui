"""Attribute research scanners, and stop discarding three measurements.

A honeypot on a public address is scanned continuously by Censys, Shodan,
Rapid7 and Shadowserver, none of which are attacking it. All of that was
classified as reconnaissance, which is technically correct and makes every
figure the project reports — sessions observed, attacks by country, category
distribution — dominated by traffic that was never adversarial. Sessions are
now attributed rather than dropped, so the counts can exclude them and the
scans themselves stay auditable.

Three things the pipeline computed and threw away:

* the full class distribution, not just the winning label — 0.34/0.33/0.33 and
  0.98/0.01/0.01 are different findings and were stored identically;
* analysis wall-clock time, logged when it exceeded the 200 ms NFR-2 budget
  and then discarded, so the requirement could never be evidenced over real
  traffic rather than asserted from a single run;
* the packet summary, whose column has been indexed since migration 001 and
  never written to.

Revision ID: 006
Revises: 005
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "honeypot_sessions", sa.Column("scanner_operator", sa.String(50), nullable=True)
    )
    op.add_column(
        "honeypot_sessions",
        sa.Column(
            "class_probabilities",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    op.add_column(
        "honeypot_sessions", sa.Column("analysis_ms", sa.Float(), nullable=True)
    )
    # Excluding scanners is a filter on almost every dashboard query, so it is
    # worth an index; the column is null for the majority of rows, which makes
    # a partial index the cheaper shape.
    op.create_index(
        "ix_honeypot_sessions_scanner_operator",
        "honeypot_sessions",
        ["scanner_operator"],
        postgresql_where=sa.text("scanner_operator IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_honeypot_sessions_scanner_operator", table_name="honeypot_sessions"
    )
    for column in ("analysis_ms", "class_probabilities", "scanner_operator"):
        op.drop_column("honeypot_sessions", column)
