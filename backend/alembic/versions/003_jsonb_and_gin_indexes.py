"""Convert JSON columns to JSONB and index the ones that get queried.

The report's engine-selection argument (Table IV) rests on PostgreSQL's
"native JSONB" support and the "flexible, high-performance indexing" it
enables. Every column was created as ``json``, which Postgres stores as text
and reparses on every access, and which cannot carry a GIN index at all — so
the stated rationale did not apply to the schema that was actually deployed.

``json -> jsonb`` is a rewriting change but these tables are small at the point
of migration, and the cast is lossless apart from key-order and duplicate-key
normalisation, neither of which anything here depends on.

Revision ID: 003
Revises: 002
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None

#: (table, column) pairs holding semi-structured payloads.
JSON_COLUMNS = [
    ("honeypot_sessions", "detected_tools"),
    ("honeypot_sessions", "detected_intents"),
    ("honeypot_sessions", "mitre_tactics"),
    ("honeypot_sessions", "mitre_techniques"),
    ("honeypot_sessions", "network_packets_summary"),
    ("honeypot_sessions", "uploaded_files"),
    ("indicators_of_compromise", "tags"),
    ("alerts", "mitre_tactics"),
    ("alerts", "mitre_techniques"),
    ("audit_logs", "details"),
]

#: Columns the dashboard actually filters and aggregates on. A GIN index is
#: only worth its write cost where containment queries really happen — the
#: "top tools detected" panel scans detected_tools on every dashboard load.
GIN_INDEXES = [
    ("ix_sessions_detected_tools_gin", "honeypot_sessions", "detected_tools"),
    ("ix_sessions_detected_intents_gin", "honeypot_sessions", "detected_intents"),
    ("ix_sessions_mitre_techniques_gin", "honeypot_sessions", "mitre_techniques"),
]


def upgrade() -> None:
    for table, column in JSON_COLUMNS:
        op.execute(
            f'ALTER TABLE {table} '
            f'ALTER COLUMN {column} TYPE jsonb USING {column}::text::jsonb'
        )

    for name, table, column in GIN_INDEXES:
        op.execute(f'CREATE INDEX IF NOT EXISTS {name} ON {table} USING gin ({column})')


def downgrade() -> None:
    for name, _table, _column in GIN_INDEXES:
        op.execute(f'DROP INDEX IF EXISTS {name}')

    for table, column in JSON_COLUMNS:
        op.execute(
            f'ALTER TABLE {table} '
            f'ALTER COLUMN {column} TYPE json USING {column}::text::json'
        )
