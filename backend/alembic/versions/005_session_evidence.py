"""Store the evidence the pipeline already collects but threw away.

Four things were captured and then discarded at a boundary:

* the command *outputs* — the transcript was stored as commands only, so an
  analyst could see what was typed but not what the machine appeared to reply;
* the credentials tried against the honeypot — recorded per session on the
  node and reduced to a failure count before transmission;
* the classifier's ``model_source`` — computed on every classification and
  dropped with the ingest response, so the UI could never say whether a
  confidence figure came from a trained model or from synthetic bootstrap
  data, despite the interface being built to say exactly that;
* the behavioural cluster assignment — computed on every session with nowhere
  to put it.

Also carried now: the retrieval and execution events the SSH emulator
observes, which is where a dropper's C2 URL appears.

Revision ID: 005
Revises: 004
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "honeypot_sessions", sa.Column("model_source", sa.String(32), nullable=True)
    )
    op.add_column(
        "honeypot_sessions", sa.Column("cluster_id", sa.Integer(), nullable=True)
    )
    op.add_column(
        "honeypot_sessions", sa.Column("cluster_distance", sa.Float(), nullable=True)
    )
    op.add_column(
        "honeypot_sessions", sa.Column("cluster_is_outlier", sa.Boolean(), nullable=True)
    )
    op.add_column(
        "honeypot_sessions", sa.Column("transcript_encrypted", sa.Text(), nullable=True)
    )
    op.add_column(
        "honeypot_sessions", sa.Column("credentials_encrypted", sa.Text(), nullable=True)
    )
    op.add_column(
        "honeypot_sessions",
        sa.Column("network_events", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "honeypot_sessions",
        sa.Column(
            "keystroke_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )

    # Cluster is the axis analysts filter on ("show me everything that behaves
    # like this campaign"), so it gets an index; the rest are read per session.
    op.create_index(
        "ix_honeypot_sessions_cluster_id", "honeypot_sessions", ["cluster_id"]
    )
    # Containment queries over retrieval events — "which sessions reached for
    # this host" — need GIN, matching how the other JSONB columns are indexed.
    op.create_index(
        "ix_honeypot_sessions_network_events",
        "honeypot_sessions",
        ["network_events"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("ix_honeypot_sessions_network_events", table_name="honeypot_sessions")
    op.drop_index("ix_honeypot_sessions_cluster_id", table_name="honeypot_sessions")
    for column in (
        "keystroke_count",
        "network_events",
        "credentials_encrypted",
        "transcript_encrypted",
        "cluster_is_outlier",
        "cluster_distance",
        "cluster_id",
        "model_source",
    ):
        op.drop_column("honeypot_sessions", column)
