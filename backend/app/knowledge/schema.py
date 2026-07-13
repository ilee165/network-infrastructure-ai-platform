"""Graph schema constants and constraint bootstrap for the Neo4j projection.

Implements ADR-0005 fixed design (M2 subset):

Node labels
-----------
- Device, Interface, IPAddress  — projected directly from Postgres rows;
  key property is ``pg_id`` (UUID string of the source row).
- Vlan, Subnet, VRF, Site       — derived nodes; key properties are the
  natural domain keys ``vlan_id``, ``cidr``, ``name``, ``name`` respectively.

Relationship types
------------------
CONNECTED_TO, HAS_INTERFACE, IN_SUBNET, L3_ADJACENT, ROUTES_TO.

Every node also carries ``last_projected_at`` (tz-aware UTC ISO-8601 string),
but that column does not require a uniqueness constraint.

Bootstrap
---------
:func:`ensure_constraints` creates ``UNIQUENESS`` constraints idempotently via
``CREATE CONSTRAINT IF NOT EXISTS``.  It is safe to call on every projection
pass; Neo4j 5 silently skips already-existing constraints.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Node label constants
# ---------------------------------------------------------------------------

LABEL_DEVICE: str = "Device"
LABEL_INTERFACE: str = "Interface"
LABEL_IPADDRESS: str = "IPAddress"
LABEL_VLAN: str = "Vlan"
LABEL_SUBNET: str = "Subnet"
LABEL_VRF: str = "VRF"
LABEL_SITE: str = "Site"
#: DNS-dependency layer (M5 task #13, ADR-0022): zones + records projected from
#: Infoblox DDI data.  ``DnsZone`` is keyed by its FQDN; ``DnsRecord`` by a
#: composite ``key`` (``name|type|value``) so same-name records of different
#: type/value stay distinct.
LABEL_DNS_ZONE: str = "DnsZone"
LABEL_DNS_RECORD: str = "DnsRecord"
#: Application-dependency layer (P4 W2, ADR-0052 §5): ``Application`` projects
#: directly from the ``applications`` Postgres row, keyed by ``pg_id`` exactly
#: like Device/Interface/IPAddress.
LABEL_APPLICATION: str = "Application"

# ---------------------------------------------------------------------------
# Relationship type constants
# ---------------------------------------------------------------------------

REL_CONNECTED_TO: str = "CONNECTED_TO"
REL_HAS_INTERFACE: str = "HAS_INTERFACE"
REL_IN_SUBNET: str = "IN_SUBNET"
REL_L3_ADJACENT: str = "L3_ADJACENT"
REL_ROUTES_TO: str = "ROUTES_TO"
#: DNS-dependency layer relationships (M5 task #13).  ``IN_ZONE`` links a
#: ``DnsZone`` to each record it contains; ``RESOLVES_TO`` links a ``DnsRecord``
#: to the projected node its value resolves to (a reconciled ``IPAddress`` /
#: ``Device``), or carries only the literal value when unreconciled.
REL_IN_ZONE: str = "IN_ZONE"
REL_RESOLVES_TO: str = "RESOLVES_TO"
#: Application-dependency layer (P4 W2, ADR-0052 §3.2/§5): one union
#: ``DEPENDS_ON`` edge per (application, target) pair, targets restricted to
#: the rebuild-safe ``Device``/``IPAddress`` kinds (§2.3).
REL_DEPENDS_ON: str = "DEPENDS_ON"

# ---------------------------------------------------------------------------
# Key property per label
# ---------------------------------------------------------------------------

#: Maps each node label to its uniqueness key property.
#:
#: - ``pg_id``   — UUID of the originating Postgres row (Device / Interface /
#:                 IPAddress); stored as a string.
#: - ``vlan_id`` — integer VLAN tag stored as string key (Vlan).
#: - ``cidr``    — CIDR notation string, e.g. ``"10.0.0.0/24"`` (Subnet).
#: - ``name``    — human-readable name string (VRF, Site).
#: - ``fqdn``       — fully-qualified zone name, e.g. ``"corp.example.com"`` (DnsZone).
#: - ``record_key`` — composite ``name|type|value`` string (DnsRecord); ``name``
#:                    alone is not unique (a host may have several records).
NODE_KEY_PROPERTY: dict[str, str] = {
    LABEL_DEVICE: "pg_id",
    LABEL_INTERFACE: "pg_id",
    LABEL_IPADDRESS: "pg_id",
    LABEL_VLAN: "vlan_id",
    LABEL_SUBNET: "cidr",
    LABEL_VRF: "name",
    LABEL_SITE: "name",
    LABEL_DNS_ZONE: "fqdn",
    LABEL_DNS_RECORD: "record_key",
    LABEL_APPLICATION: "pg_id",
}

# ---------------------------------------------------------------------------
# Constraint name prefix (stable, human-readable)
# ---------------------------------------------------------------------------

_CONSTRAINT_PREFIX = "netops_unique"


def _constraint_name(label: str, prop: str) -> str:
    """Deterministic constraint name: ``netops_unique_<label>_<prop>``."""
    return f"{_CONSTRAINT_PREFIX}_{label.lower()}_{prop.lower()}"


def _create_constraint_cypher(label: str, prop: str) -> str:
    """Return the idempotent Cypher for a uniqueness constraint."""
    name = _constraint_name(label, prop)
    return f"CREATE CONSTRAINT {name} IF NOT EXISTS FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"


# ---------------------------------------------------------------------------
# Public bootstrap
# ---------------------------------------------------------------------------

_CONSTRAINT_STATEMENTS: tuple[str, ...] = tuple(
    _create_constraint_cypher(label, prop) for label, prop in NODE_KEY_PROPERTY.items()
)

#: Wave 5 / perf #18: site-scoped graph reads seed from ``(:Device {site})``.
_SITE_INDEX_STATEMENTS: tuple[str, ...] = (
    "CREATE INDEX netops_device_site IF NOT EXISTS FOR (n:Device) ON (n.site)",
)


async def ensure_constraints(client: Any) -> None:
    """Create all node uniqueness constraints idempotently.

    Uses ``CREATE CONSTRAINT … IF NOT EXISTS`` so it is safe to call on every
    projection pass — Neo4j 5 skips constraints that already exist. Also
    ensures the Device.site index for scoped topology reads (Wave 5).

    Parameters
    ----------
    client:
        Any object that exposes a ``.session()`` async context manager whose
        body yields an object with an async ``.run(cypher)`` method.  In
        production this will be :class:`app.knowledge.neo4j_client.Neo4jClient`;
        in unit tests it is a lightweight fake.
    """
    async with client.session() as session:
        for cypher in _CONSTRAINT_STATEMENTS:
            await session.run(cypher)
        for cypher in _SITE_INDEX_STATEMENTS:
            await session.run(cypher)
