"""Schema-shape tests: registration, composite PKs, partition options, natural keys."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import Table, UniqueConstraint
from sqlalchemy.ext.asyncio import AsyncEngine

from app.models import Base

EXPECTED_TABLES = {
    "roles",
    "users",
    "audit_log",
    "devices",
    "device_credentials",
    "discovery_runs",
    "raw_artifacts",
    "normalized_interfaces",
    "normalized_routes",
    "normalized_neighbors",
    "agent_sessions",
    "reasoning_traces",
    "reasoning_trace_steps",
    "config_snapshots",
    "compliance_policies",
    "documents",
    "embeddings",
    "change_requests",
    "approvals",
    "pcap_metadata",
}

PARTITIONED_TABLES = (
    "audit_log",
    "raw_artifacts",
    "reasoning_traces",
    "reasoning_trace_steps",
)

NORMALIZED_NATURAL_KEYS = {
    "normalized_interfaces": ("device_id", "name"),
    "normalized_routes": ("device_id", "vrf", "prefix", "protocol", "next_hop", "interface"),
    "normalized_neighbors": (
        "device_id",
        "protocol",
        "local_interface",
        "neighbor_name",
        "neighbor_interface",
    ),
}


def _table(name: str) -> Table:
    return Base.metadata.tables[name]


def test_all_m1_tables_registered() -> None:
    """Importing app.models registers every M1 table on Base.metadata."""
    assert set(Base.metadata.tables) >= EXPECTED_TABLES


async def test_metadata_creates_cleanly_on_sqlite(engine: AsyncEngine) -> None:
    """create_all succeeds on aiosqlite and produces every expected table."""
    async with engine.connect() as conn:
        names = await conn.run_sync(lambda sync: sa.inspect(sync).get_table_names())
    assert set(names) >= EXPECTED_TABLES


def test_partitioned_tables_declare_range_partitioning() -> None:
    """audit_log and raw_artifacts carry the Postgres partition option."""
    for name in PARTITIONED_TABLES:
        table = _table(name)
        assert table.dialect_options["postgresql"]["partition_by"] == "RANGE (created_at)"


def test_partitioned_tables_have_composite_pk() -> None:
    """Partition key must be part of the PK: (id, created_at)."""
    for name in PARTITIONED_TABLES:
        pk_columns = [column.name for column in _table(name).primary_key.columns]
        assert pk_columns == ["id", "created_at"]


def test_normalized_tables_have_natural_key_unique_constraints() -> None:
    """Each normalized table declares its idempotent-upsert natural key."""
    for name, expected in NORMALIZED_NATURAL_KEYS.items():
        uniques = [
            tuple(column.name for column in constraint.columns)
            for constraint in _table(name).constraints
            if isinstance(constraint, UniqueConstraint)
        ]
        assert expected in uniques


def test_natural_key_columns_are_not_nullable() -> None:
    """Every natural-key column is NOT NULL ('' sentinel for absent values).

    A nullable key column would silently disable the unique constraint under
    default NULLS DISTINCT semantics (SQLite and PostgreSQL alike), breaking
    idempotent upserts and ON CONFLICT arbiter matching.
    """
    for name, expected in NORMALIZED_NATURAL_KEYS.items():
        for column_name in expected:
            assert not _table(name).columns[column_name].nullable, f"{name}.{column_name}"


def test_raw_artifact_id_is_plain_indexed_uuid_without_fk() -> None:
    """Linkage to the partitioned raw_artifacts table is a bare indexed UUID.

    Postgres FKs to partitioned tables must include the partition key, so the
    design decision is NO db-level FK; linkage is enforced by tests instead.
    """
    for name in NORMALIZED_NATURAL_KEYS:
        table = _table(name)
        column = table.columns["raw_artifact_id"]
        assert not column.foreign_keys
        assert not column.nullable
        indexed_columns = {c.name for index in table.indexes for c in index.columns}
        assert "raw_artifact_id" in indexed_columns


def test_device_credential_has_no_plaintext_secret_column() -> None:
    """The credential table stores ciphertext only — exact column allowlist."""
    expected = {
        "id",
        "created_at",
        "updated_at",
        "name",
        "kind",
        "username",
        "ciphertext",
        "nonce",
        "wrapped_dek",
        "dek_nonce",
        "kek_version",
        "params",
    }
    assert set(_table("device_credentials").columns.keys()) == expected
