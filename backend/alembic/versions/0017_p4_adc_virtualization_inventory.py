"""P4-W1-T3 (ADR-0050 §4 / ADR-0051 §5): ADC + virtualization inventory tables.

**Expand-only** migration adding the six read-only inventory tables that back
the new ADC (F5 BIG-IP) and virtualization (VMware) inventory surfacing:

- ``adc_virtual_servers`` / ``adc_pools`` — relational projections of
  ``NormalizedVirtualServer`` / ``NormalizedPool`` (ADR-0050 §4.3). Pool
  members nest as a JSON list on the pool row (F5's own subcollection shape,
  ADR-0050 §4.5) rather than a child table.
- ``virt_machines`` / ``virt_hosts`` / ``virt_clusters`` / ``virt_port_groups``
  — relational projections of ``NormalizedVirtualMachine`` /
  ``NormalizedHypervisorHost`` / ``NormalizedComputeCluster`` /
  ``NormalizedPortGroup`` (ADR-0051 §5.3); vNICs/pNICs nest as JSON on their
  parent VM/host row for the same reason.

No existing table is altered. Portable DDL: plain ``JSON`` (``JSONB`` on
PostgreSQL via the app-side ``JSON_VARIANT`` variant, mirrored here per the
existing ``_JSON`` migration convention — D4: migrations never import models).

Revision ID: 0017
Revises: 0016
Create Date: 2026-07-06
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Portable JSON column: plain JSON everywhere, JSONB on PostgreSQL. Mirrors
#: app.models.mixins.JSON_VARIANT (migrations never import models — D4).
_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

#: Shared provenance-triple + raw-artifact-linkage columns (mirrors
#: app.models.inventory._ProvenanceMixin) common to every row below.
_PROVENANCE_COLUMNS: tuple[sa.Column, ...] = (
    sa.Column("device_id", sa.Uuid(), nullable=False),
    sa.Column("raw_artifact_id", sa.Uuid(), nullable=False),
    sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("source_vendor", sa.String(length=64), nullable=False),
)

_TIMESTAMP_COLUMNS: tuple[sa.Column, ...] = (
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)


def upgrade() -> None:
    op.create_table(
        "adc_virtual_servers",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_PROVENANCE_COLUMNS,
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("vip_address", sa.String(length=64), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("vrf", sa.String(length=64), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("availability", sa.String(length=32), nullable=False),
        sa.Column("pool_name", sa.String(length=255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        *_TIMESTAMP_COLUMNS,
        sa.PrimaryKeyConstraint("id", name=op.f("pk_adc_virtual_servers")),
        sa.UniqueConstraint("device_id", "name", name=op.f("uq_adc_virtual_servers_device_id")),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name=op.f("fk_adc_virtual_servers_device_id")
        ),
    )
    op.create_index(op.f("ix_adc_virtual_servers_device_id"), "adc_virtual_servers", ["device_id"])
    op.create_index(
        op.f("ix_adc_virtual_servers_raw_artifact_id"),
        "adc_virtual_servers",
        ["raw_artifact_id"],
    )

    op.create_table(
        "adc_pools",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_PROVENANCE_COLUMNS,
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("monitors", _JSON, nullable=False),
        sa.Column("availability", sa.String(length=32), nullable=False),
        sa.Column("members", _JSON, nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        *_TIMESTAMP_COLUMNS,
        sa.PrimaryKeyConstraint("id", name=op.f("pk_adc_pools")),
        sa.UniqueConstraint("device_id", "name", name=op.f("uq_adc_pools_device_id")),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], name=op.f("fk_adc_pools_device_id")),
    )
    op.create_index(op.f("ix_adc_pools_device_id"), "adc_pools", ["device_id"])
    op.create_index(op.f("ix_adc_pools_raw_artifact_id"), "adc_pools", ["raw_artifact_id"])

    op.create_table(
        "virt_machines",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_PROVENANCE_COLUMNS,
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("moref", sa.String(length=64), nullable=False),
        sa.Column("instance_uuid", sa.String(length=64), nullable=True),
        sa.Column("is_template", sa.Boolean(), nullable=False),
        sa.Column("power_state", sa.String(length=32), nullable=False),
        sa.Column("guest_hostname", sa.String(length=255), nullable=True),
        sa.Column("guest_ip_addresses", _JSON, nullable=False),
        sa.Column("host_name", sa.String(length=255), nullable=True),
        sa.Column("cluster_name", sa.String(length=255), nullable=True),
        sa.Column("datacenter", sa.String(length=255), nullable=True),
        sa.Column("nics", _JSON, nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=True),
        *_TIMESTAMP_COLUMNS,
        sa.PrimaryKeyConstraint("id", name=op.f("pk_virt_machines")),
        sa.UniqueConstraint("device_id", "moref", name=op.f("uq_virt_machines_device_id")),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name=op.f("fk_virt_machines_device_id")
        ),
    )
    op.create_index(op.f("ix_virt_machines_device_id"), "virt_machines", ["device_id"])
    op.create_index(op.f("ix_virt_machines_raw_artifact_id"), "virt_machines", ["raw_artifact_id"])

    op.create_table(
        "virt_hosts",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_PROVENANCE_COLUMNS,
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("moref", sa.String(length=64), nullable=False),
        sa.Column("cluster_name", sa.String(length=255), nullable=True),
        sa.Column("datacenter", sa.String(length=255), nullable=True),
        sa.Column("vendor", sa.String(length=128), nullable=True),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("hypervisor_version", sa.String(length=255), nullable=True),
        sa.Column("connection_state", sa.String(length=32), nullable=False),
        sa.Column("in_maintenance_mode", sa.Boolean(), nullable=False),
        sa.Column("management_ip", sa.String(length=64), nullable=True),
        sa.Column("pnics", _JSON, nullable=False),
        *_TIMESTAMP_COLUMNS,
        sa.PrimaryKeyConstraint("id", name=op.f("pk_virt_hosts")),
        sa.UniqueConstraint("device_id", "moref", name=op.f("uq_virt_hosts_device_id")),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name=op.f("fk_virt_hosts_device_id")
        ),
    )
    op.create_index(op.f("ix_virt_hosts_device_id"), "virt_hosts", ["device_id"])
    op.create_index(op.f("ix_virt_hosts_raw_artifact_id"), "virt_hosts", ["raw_artifact_id"])

    op.create_table(
        "virt_clusters",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_PROVENANCE_COLUMNS,
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("moref", sa.String(length=64), nullable=False),
        sa.Column("datacenter", sa.String(length=255), nullable=True),
        sa.Column("drs_enabled", sa.Boolean(), nullable=True),
        sa.Column("ha_enabled", sa.Boolean(), nullable=True),
        *_TIMESTAMP_COLUMNS,
        sa.PrimaryKeyConstraint("id", name=op.f("pk_virt_clusters")),
        sa.UniqueConstraint("device_id", "moref", name=op.f("uq_virt_clusters_device_id")),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name=op.f("fk_virt_clusters_device_id")
        ),
    )
    op.create_index(op.f("ix_virt_clusters_device_id"), "virt_clusters", ["device_id"])
    op.create_index(op.f("ix_virt_clusters_raw_artifact_id"), "virt_clusters", ["raw_artifact_id"])

    op.create_table(
        "virt_port_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_PROVENANCE_COLUMNS,
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("switch_name", sa.String(length=255), nullable=False),
        sa.Column("switch_type", sa.String(length=32), nullable=False),
        sa.Column("datacenter", sa.String(length=255), nullable=False),
        sa.Column("host_name", sa.String(length=255), nullable=False),
        sa.Column("vlan_id", sa.Integer(), nullable=True),
        sa.Column("moref", sa.String(length=64), nullable=False),
        sa.Column("uplink_pnic_names", _JSON, nullable=False),
        *_TIMESTAMP_COLUMNS,
        sa.PrimaryKeyConstraint("id", name=op.f("pk_virt_port_groups")),
        sa.UniqueConstraint(
            "device_id",
            "moref",
            "datacenter",
            "host_name",
            "name",
            name=op.f("uq_virt_port_groups_device_id"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name=op.f("fk_virt_port_groups_device_id")
        ),
    )
    op.create_index(op.f("ix_virt_port_groups_device_id"), "virt_port_groups", ["device_id"])
    op.create_index(
        op.f("ix_virt_port_groups_raw_artifact_id"), "virt_port_groups", ["raw_artifact_id"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_virt_port_groups_raw_artifact_id"), table_name="virt_port_groups")
    op.drop_index(op.f("ix_virt_port_groups_device_id"), table_name="virt_port_groups")
    op.drop_table("virt_port_groups")

    op.drop_index(op.f("ix_virt_clusters_raw_artifact_id"), table_name="virt_clusters")
    op.drop_index(op.f("ix_virt_clusters_device_id"), table_name="virt_clusters")
    op.drop_table("virt_clusters")

    op.drop_index(op.f("ix_virt_hosts_raw_artifact_id"), table_name="virt_hosts")
    op.drop_index(op.f("ix_virt_hosts_device_id"), table_name="virt_hosts")
    op.drop_table("virt_hosts")

    op.drop_index(op.f("ix_virt_machines_raw_artifact_id"), table_name="virt_machines")
    op.drop_index(op.f("ix_virt_machines_device_id"), table_name="virt_machines")
    op.drop_table("virt_machines")

    op.drop_index(op.f("ix_adc_pools_raw_artifact_id"), table_name="adc_pools")
    op.drop_index(op.f("ix_adc_pools_device_id"), table_name="adc_pools")
    op.drop_table("adc_pools")

    op.drop_index(op.f("ix_adc_virtual_servers_raw_artifact_id"), table_name="adc_virtual_servers")
    op.drop_index(op.f("ix_adc_virtual_servers_device_id"), table_name="adc_virtual_servers")
    op.drop_table("adc_virtual_servers")
