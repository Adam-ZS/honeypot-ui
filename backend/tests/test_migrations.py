"""Migration tests.

The rest of the suite runs against SQLite via ``Base.metadata.create_all``,
which never executes the Alembic scripts and has no concept of a PostgreSQL
ENUM type. That combination hid a migration that could not apply to a real
PostgreSQL database at all, so these tests render the migration to PostgreSQL
DDL offline (no server required) and assert on the emitted SQL.
"""

import importlib.util
import io
import os

import pytest
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

MIGRATION_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "alembic",
    "versions",
    "001_initial_schema.py",
)

#: Every enum type the initial migration is responsible for creating.
ENUM_TYPES = [
    "userrole",
    "honeypotmode",
    "sessionstatus",
    "attackseverity",
    "attackcategory",
    "attackerprofile",
    "alertstatus",
]


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_001", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _render(direction: str) -> str:
    """Render the migration to PostgreSQL DDL without connecting anywhere."""
    module = _load_migration()
    buffer = io.StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": buffer},
    )
    with Operations.context(context):
        getattr(module, direction)()
    return buffer.getvalue()


@pytest.fixture(scope="module")
def upgrade_sql() -> str:
    return _render("upgrade")


@pytest.mark.parametrize("enum_name", ENUM_TYPES)
def test_enum_type_is_created_exactly_once(upgrade_sql, enum_name):
    """Each ENUM must be created once, by the guarded _create_enum block.

    ``sa.Enum(..., name='userrole')`` emits its own ``CREATE TYPE`` when the
    owning table is built — ``op.create_table`` does not pass ``checkfirst``,
    unlike ``metadata.create_all``. With the type already created by
    ``_create_enum``, PostgreSQL raised::

        (psycopg.errors.DuplicateObject) type "userrole" already exists

    and because DDL is transactional the entire migration rolled back, leaving
    an empty database and a backend that exited during startup. The columns
    therefore use ``postgresql.ENUM(..., create_type=False)``.
    """
    assert upgrade_sql.count(f"CREATE TYPE {enum_name} ") == 1


def test_every_enum_creation_is_guarded(upgrade_sql):
    """Re-running against a database that already has the types must be safe."""
    for enum_name in ENUM_TYPES:
        guard = f"SELECT 1 FROM pg_type WHERE typname = '{enum_name}'"
        assert guard in upgrade_sql, f"{enum_name} is created without a guard"


def test_expected_tables_are_created(upgrade_sql):
    for table in (
        "users",
        "honeypot_nodes",
        "honeypot_sessions",
        "alerts",
        "indicators_of_compromise",
        "audit_logs",
        "otp_verifications",
        "alert_thresholds",
    ):
        assert f"CREATE TABLE {table} " in upgrade_sql


def test_downgrade_renders(upgrade_sql):
    """A downgrade that cannot even render is a downgrade nobody can run."""
    sql = _render("downgrade")
    assert "DROP TABLE users" in sql
    for enum_name in ENUM_TYPES:
        assert f"DROP TYPE {enum_name}" in sql or f"DROP TYPE IF EXISTS {enum_name}" in sql
