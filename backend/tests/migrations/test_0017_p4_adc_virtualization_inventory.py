"""Migration 0017 (P4 W1-T3, ADR-0050 §4 / ADR-0051 §5): ADC + virtualization
inventory tables + single head.

Unit tests drive ``alembic upgrade --sql`` in-process against the PostgreSQL
dialect (no DB/Docker/network) and assert the emitted DDL creates all six
read-only inventory tables (``adc_virtual_servers``, ``adc_pools``,
``virt_machines``, ``virt_hosts``, ``virt_clusters``, ``virt_port_groups``)
with their key columns. This is an **expand-only** migration (six new tables,
no edits to existing ones). ``alembic heads`` is asserted to be the SINGLE
head ``0017`` chaining after ``0016`` — 0017 is now the LATEST migration and
owns the single-head invariant.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from app.core.config import get_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]


def _alembic_config(output_buffer: io.StringIO | None = None) -> Config:
    cfg = Config(output_buffer=output_buffer) if output_buffer is not None else Config()
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    return cfg


def _offline_sql_0017(direction: str) -> str:
    """Render ``alembic <direction> --sql`` for revision 0017 in isolation."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0016:0017", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0017:0016", sql=True)
    return buffer.getvalue()


@pytest.fixture()
def _postgres_dialect_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "NETOPS_DATABASE_URL", "postgresql+asyncpg://netops:netops@127.0.0.1:5432/netops"
    )
    get_settings.cache_clear()
    yield  # type: ignore[misc]
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Single head + revision wiring
# ---------------------------------------------------------------------------


def test_single_head_is_0017() -> None:
    """`alembic heads` resolves to exactly one head, revision 0017 (no branch)."""
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert heads == ["0017"], f"expected single head 0017, got {heads}"


def test_0017_revises_0016() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    rev = script.get_revision("0017")
    assert rev.down_revision == "0016"


# ---------------------------------------------------------------------------
# Offline SQL (no database required)
# ---------------------------------------------------------------------------

_EXPECTED_TABLES_AND_COLUMNS: dict[str, tuple[str, ...]] = {
    "ADC_VIRTUAL_SERVERS": ("VIP_ADDRESS", "PORT", "PROTOCOL", "AVAILABILITY", "POOL_NAME"),
    "ADC_POOLS": ("MONITORS", "AVAILABILITY", "MEMBERS"),
    "VIRT_MACHINES": ("MOREF", "POWER_STATE", "GUEST_IP_ADDRESSES", "HOST_NAME", "NICS"),
    "VIRT_HOSTS": ("MOREF", "CONNECTION_STATE", "IN_MAINTENANCE_MODE", "PNICS"),
    "VIRT_CLUSTERS": ("MOREF", "DRS_ENABLED", "HA_ENABLED"),
    "VIRT_PORT_GROUPS": ("SWITCH_TYPE", "VLAN_ID", "UPLINK_PNIC_NAMES"),
}


def _table_ddl_segment(sql: str, table: str) -> str:
    """The ``CREATE TABLE {table}`` statement's own DDL span.

    Column tokens repeat across tables (e.g. ``PORT`` in VIRT_PORT_GROUPS,
    ``AVAILABILITY`` in ADC_POOLS), so a whole-SQL ``column in sql`` check would
    pass even if the column were dropped from *this* table. Narrow to the segment
    running from this table's ``CREATE TABLE`` to the next one (or end of SQL).
    """
    marker = f"CREATE TABLE {table}"
    start = sql.index(marker)
    nxt = sql.find("CREATE TABLE ", start + len(marker))
    return sql[start:] if nxt == -1 else sql[start:nxt]


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_all_six_inventory_tables() -> None:
    sql = _offline_sql_0017("upgrade").upper()
    for table, columns in _EXPECTED_TABLES_AND_COLUMNS.items():
        assert f"CREATE TABLE {table}" in sql, f"missing CREATE TABLE {table}"
        segment = _table_ddl_segment(sql, table)
        for column in columns:
            assert column in segment, f"missing column {column} on {table}"
    # Every table carries the shared provenance triple + raw-artifact link.
    for provenance_column in ("DEVICE_ID", "RAW_ARTIFACT_ID", "COLLECTED_AT", "SOURCE_VENDOR"):
        assert provenance_column in sql, f"missing provenance column {provenance_column}"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_downgrade_drops_all_six_inventory_tables() -> None:
    sql = _offline_sql_0017("downgrade").upper()
    for table in _EXPECTED_TABLES_AND_COLUMNS:
        assert f"DROP TABLE {table}" in sql, f"downgrade DDL must DROP TABLE {table}"
