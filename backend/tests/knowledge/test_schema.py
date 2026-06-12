"""Unit tests for app.knowledge.schema — constants and constraint bootstrap.

All tests run without a live Neo4j instance.  A ``FakeClient`` captures every
Cypher statement executed and supports being called twice to verify idempotency
(CREATE CONSTRAINT IF NOT EXISTS is safe, but we also check that the helper is
callable more than once without raising).
"""

from __future__ import annotations

from typing import Any

from app.knowledge.schema import (
    # Label constants
    LABEL_DEVICE,
    LABEL_INTERFACE,
    LABEL_IPADDRESS,
    LABEL_SITE,
    LABEL_SUBNET,
    LABEL_VLAN,
    LABEL_VRF,
    # Key-property mapping
    NODE_KEY_PROPERTY,
    # Relationship type constants
    REL_CONNECTED_TO,
    REL_HAS_INTERFACE,
    REL_IN_SUBNET,
    REL_L3_ADJACENT,
    REL_ROUTES_TO,
    # Bootstrap helper
    ensure_constraints,
)

# ---------------------------------------------------------------------------
# Constant value assertions
# ---------------------------------------------------------------------------


def test_node_label_constants_have_expected_values() -> None:
    assert LABEL_DEVICE == "Device"
    assert LABEL_INTERFACE == "Interface"
    assert LABEL_IPADDRESS == "IPAddress"
    assert LABEL_VLAN == "Vlan"
    assert LABEL_SUBNET == "Subnet"
    assert LABEL_VRF == "VRF"
    assert LABEL_SITE == "Site"


def test_relationship_type_constants_have_expected_values() -> None:
    assert REL_CONNECTED_TO == "CONNECTED_TO"
    assert REL_HAS_INTERFACE == "HAS_INTERFACE"
    assert REL_IN_SUBNET == "IN_SUBNET"
    assert REL_L3_ADJACENT == "L3_ADJACENT"
    assert REL_ROUTES_TO == "ROUTES_TO"


def test_node_key_property_maps_all_seven_labels() -> None:
    """Every label constant must have a key-property entry."""
    for label in (
        LABEL_DEVICE,
        LABEL_INTERFACE,
        LABEL_IPADDRESS,
        LABEL_VLAN,
        LABEL_SUBNET,
        LABEL_VRF,
        LABEL_SITE,
    ):
        assert label in NODE_KEY_PROPERTY, f"Missing key property for label: {label!r}"


def test_pg_id_labels_use_pg_id_key() -> None:
    """Device, Interface, and IPAddress are projected from Postgres rows."""
    for label in (LABEL_DEVICE, LABEL_INTERFACE, LABEL_IPADDRESS):
        assert NODE_KEY_PROPERTY[label] == "pg_id", (
            f"{label} should use 'pg_id' as its key property"
        )


def test_derived_labels_use_natural_keys() -> None:
    """Derived nodes carry domain-natural keys, never pg_id."""
    assert NODE_KEY_PROPERTY[LABEL_VLAN] == "vlan_id"
    assert NODE_KEY_PROPERTY[LABEL_SUBNET] == "cidr"
    assert NODE_KEY_PROPERTY[LABEL_VRF] == "name"
    assert NODE_KEY_PROPERTY[LABEL_SITE] == "name"


# ---------------------------------------------------------------------------
# Fake client for ensure_constraints tests
# ---------------------------------------------------------------------------


class FakeSession:
    """Records every Cypher string passed via run()."""

    def __init__(self) -> None:
        self.executed: list[str] = []

    async def run(self, cypher: str, **_params: Any) -> None:  # noqa: ARG002
        self.executed.append(cypher)

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


class FakeClient:
    """Minimal stand-in for Neo4jClient; captures every statement issued."""

    def __init__(self) -> None:
        self.sessions: list[FakeSession] = []

    def session(self) -> FakeSession:  # called as async context manager
        sess = FakeSession()
        self.sessions.append(sess)
        return sess

    @property
    def all_executed(self) -> list[str]:
        return [stmt for s in self.sessions for stmt in s.executed]


# ---------------------------------------------------------------------------
# ensure_constraints — Cypher correctness
# ---------------------------------------------------------------------------


async def test_ensure_constraints_issues_one_statement_per_label() -> None:
    """Exactly 7 CREATE CONSTRAINT statements — one per node label."""
    client = FakeClient()
    await ensure_constraints(client)
    assert len(client.all_executed) == 7


async def test_ensure_constraints_uses_create_constraint_if_not_exists() -> None:
    """Every statement must be idempotent: CREATE CONSTRAINT IF NOT EXISTS."""
    client = FakeClient()
    await ensure_constraints(client)
    for stmt in client.all_executed:
        upper = stmt.upper()
        assert "CREATE CONSTRAINT" in upper, f"Not a CREATE CONSTRAINT: {stmt!r}"
        assert "IF NOT EXISTS" in upper, f"Missing IF NOT EXISTS: {stmt!r}"


async def test_ensure_constraints_covers_uniqueness_for_all_labels() -> None:
    """Each label appears in exactly one constraint, keyed by its key property."""
    client = FakeClient()
    await ensure_constraints(client)

    expected_pairs = [
        ("Device", "pg_id"),
        ("Interface", "pg_id"),
        ("IPAddress", "pg_id"),
        ("Vlan", "vlan_id"),
        ("Subnet", "cidr"),
        ("VRF", "name"),
        ("Site", "name"),
    ]
    stmts = client.all_executed
    for label, prop in expected_pairs:
        matched = [s for s in stmts if label in s and prop in s]
        assert matched, (
            f"No constraint statement found for label={label!r}, prop={prop!r}. "
            f"Statements issued: {stmts}"
        )


async def test_ensure_constraints_statements_are_uniqueness_constraints() -> None:
    """Each statement must declare a UNIQUENESS constraint."""
    client = FakeClient()
    await ensure_constraints(client)
    for stmt in client.all_executed:
        assert "UNIQUENESS" in stmt.upper() or "IS UNIQUE" in stmt.upper(), (
            f"Statement does not declare uniqueness: {stmt!r}"
        )


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


async def test_ensure_constraints_is_idempotent_called_twice() -> None:
    """Calling ensure_constraints twice must not raise and must issue the same
    7 statements on each call."""
    client = FakeClient()
    await ensure_constraints(client)
    first_pass = list(client.all_executed)

    await ensure_constraints(client)
    second_pass = client.all_executed[len(first_pass) :]

    assert len(first_pass) == 7
    assert len(second_pass) == 7
    # same set of statements in both passes
    assert sorted(first_pass) == sorted(second_pass)
