"""DNS-dependency derivation (M5 task #13, ADR-0022): zones, records, RESOLVES_TO.

Fixtures build the normalized DDI currency (:class:`NormalizedDnsRecord`) and
in-memory inventory rows directly (no session) — :func:`derive_dns` is a pure
function, deterministic and insensitive to input ordering, exactly like the M2
``derive_nodes`` / edge builders it mirrors.

The reconciliation contract under test: an A/AAAA record whose value is a known
device interface address or a device ``mgmt_ip`` produces a ``RESOLVES_TO`` edge
onto that *projected* node (IPAddress / Device); an unreconciled record points at
no phantom node and carries its literal value on the edge instead.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.engines.topology import (
    DnsRecordNode,
    DnsZoneNode,
    InZoneEdge,
    ResolvesToEdge,
    derive_dns,
)
from app.knowledge.schema import (
    LABEL_DEVICE,
    LABEL_DNS_RECORD,
    LABEL_DNS_ZONE,
    LABEL_IPADDRESS,
)
from app.models.inventory import Device, NormalizedInterfaceRow
from app.schemas.normalized import (
    DnsRecordType,
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NormalizedDnsRecord,
)

COLLECTED_AT = datetime(2026, 6, 18, 12, 0, tzinfo=UTC)

DEV1 = UUID("00000000-0000-0000-0000-0000000000d1")
IF1 = UUID("00000000-0000-0000-0000-0000000000f1")


def make_device(hostname: str, mgmt_ip: str, *, device_id: UUID | None = None) -> Device:
    return Device(
        id=device_id or uuid4(),
        hostname=hostname,
        mgmt_ip=mgmt_ip,
        vendor_id="cisco_ios",
        model="C9300",
        site="hq",
    )


def make_interface(
    device_id: UUID, name: str, ip_address: str | None, *, row_id: UUID | None = None
) -> NormalizedInterfaceRow:
    return NormalizedInterfaceRow(
        id=row_id or uuid4(),
        device_id=device_id,
        raw_artifact_id=uuid4(),
        collected_at=COLLECTED_AT,
        source_vendor="cisco_ios",
        name=name,
        admin_status=InterfaceAdminStatus.UP,
        oper_status=InterfaceOperStatus.UP,
        ip_address=ip_address,
    )


def make_record(
    name: str,
    record_type: DnsRecordType,
    value: str,
    *,
    zone: str | None,
    device_id: UUID | None = None,
) -> NormalizedDnsRecord:
    return NormalizedDnsRecord(
        device_id=device_id or DEV1,
        collected_at=COLLECTED_AT,
        source_vendor="infoblox",
        name=name,
        record_type=record_type,
        value=value,
        zone=zone,
        object_ref=f"record:{record_type.value}/ref-{name}",
    )


# ---------------------------------------------------------------------------
# Zone + record nodes
# ---------------------------------------------------------------------------


def test_zones_become_dns_zone_nodes_sorted_and_deduped() -> None:
    result = derive_dns(
        records=[],
        zones=["corp.example.com", "lab.example.com", "corp.example.com"],
        devices=[],
        interfaces=[],
    )
    assert [z.fqdn for z in result.zones] == ["corp.example.com", "lab.example.com"]
    assert all(isinstance(z, DnsZoneNode) for z in result.zones)
    assert result.zones[0].label == LABEL_DNS_ZONE


def test_record_zone_not_in_zone_list_is_still_projected_as_zone_node() -> None:
    """A record referencing a zone never listed by get_zones() still anchors one."""
    rec = make_record("a.corp.example.com", DnsRecordType.A, "10.0.0.9", zone="corp.example.com")
    result = derive_dns(records=[rec], zones=[], devices=[], interfaces=[])
    assert [z.fqdn for z in result.zones] == ["corp.example.com"]


def test_records_become_dns_record_nodes_keyed_by_name_type_value() -> None:
    rec = make_record("www.corp.example.com", DnsRecordType.A, "10.0.0.9", zone="corp.example.com")
    result = derive_dns(records=[rec], zones=["corp.example.com"], devices=[], interfaces=[])
    assert len(result.records) == 1
    node = result.records[0]
    assert isinstance(node, DnsRecordNode)
    assert node.label == LABEL_DNS_RECORD
    assert node.name == "www.corp.example.com"
    assert node.record_type == DnsRecordType.A
    assert node.value == "10.0.0.9"
    assert node.zone == "corp.example.com"
    # The key is a stable composite so same name across record types stays distinct.
    assert node.key == "www.corp.example.com|a|10.0.0.9"


def test_same_name_different_type_are_distinct_records() -> None:
    a = make_record("dual.corp.example.com", DnsRecordType.A, "10.0.0.9", zone="corp.example.com")
    aaaa = make_record(
        "dual.corp.example.com", DnsRecordType.AAAA, "2001:db8::9", zone="corp.example.com"
    )
    result = derive_dns(records=[aaaa, a], zones=[], devices=[], interfaces=[])
    keys = {r.key for r in result.records}
    assert keys == {
        "dual.corp.example.com|a|10.0.0.9",
        "dual.corp.example.com|aaaa|2001:db8::9",
    }


def test_duplicate_records_collapse_to_one_node() -> None:
    rec = make_record("a.corp.example.com", DnsRecordType.A, "10.0.0.9", zone="corp.example.com")
    dup = make_record("a.corp.example.com", DnsRecordType.A, "10.0.0.9", zone="corp.example.com")
    result = derive_dns(records=[rec, dup], zones=[], devices=[], interfaces=[])
    assert len(result.records) == 1


# ---------------------------------------------------------------------------
# IN_ZONE structural edges (zone -> record)
# ---------------------------------------------------------------------------


def test_in_zone_edges_link_zone_to_each_of_its_records() -> None:
    rec = make_record("a.corp.example.com", DnsRecordType.A, "10.0.0.9", zone="corp.example.com")
    result = derive_dns(records=[rec], zones=["corp.example.com"], devices=[], interfaces=[])
    assert result.in_zone == (
        InZoneEdge(zone_fqdn="corp.example.com", record_key="a.corp.example.com|a|10.0.0.9"),
    )


def test_record_without_zone_produces_no_in_zone_edge() -> None:
    rec = make_record("orphan.example.com", DnsRecordType.A, "10.0.0.9", zone=None)
    result = derive_dns(records=[rec], zones=[], devices=[], interfaces=[])
    assert result.in_zone == ()
    assert result.zones == ()
    assert len(result.records) == 1


# ---------------------------------------------------------------------------
# RESOLVES_TO reconciliation against inventory / topology nodes
# ---------------------------------------------------------------------------


def test_a_record_matching_interface_ip_resolves_to_that_ipaddress_node() -> None:
    dev = make_device("core-1", "192.0.2.1", device_id=DEV1)
    iface = make_interface(DEV1, "Ethernet1", "10.0.0.9/24", row_id=IF1)
    rec = make_record("www.corp.example.com", DnsRecordType.A, "10.0.0.9", zone="corp.example.com")
    result = derive_dns(records=[rec], zones=[], devices=[dev], interfaces=[iface])

    assert result.resolves_to == (
        ResolvesToEdge(
            record_key="www.corp.example.com|a|10.0.0.9",
            target_label=LABEL_IPADDRESS,
            target_key=str(IF1),
            value="10.0.0.9",
            reconciled=True,
        ),
    )


def test_a_record_matching_device_mgmt_ip_resolves_to_device_node() -> None:
    dev = make_device("core-1", "192.0.2.1", device_id=DEV1)
    rec = make_record("core-1.corp.example.com", DnsRecordType.A, "192.0.2.1", zone=None)
    result = derive_dns(records=[rec], zones=[], devices=[dev], interfaces=[])
    edge = result.resolves_to[0]
    assert edge.target_label == LABEL_DEVICE
    assert edge.target_key == str(DEV1)
    assert edge.reconciled is True


def test_interface_ip_match_wins_over_device_mgmt_ip_match() -> None:
    """When a value is both an interface IP and some device's mgmt_ip, prefer IP node."""
    dev = make_device("core-1", "10.0.0.9", device_id=DEV1)
    iface = make_interface(DEV1, "Ethernet1", "10.0.0.9/24", row_id=IF1)
    rec = make_record("www.corp.example.com", DnsRecordType.A, "10.0.0.9", zone=None)
    result = derive_dns(records=[rec], zones=[], devices=[dev], interfaces=[iface])
    edge = result.resolves_to[0]
    assert edge.target_label == LABEL_IPADDRESS
    assert edge.target_key == str(IF1)


def test_unreconciled_a_record_has_no_target_node_but_keeps_literal_value() -> None:
    rec = make_record("ext.corp.example.com", DnsRecordType.A, "203.0.113.7", zone=None)
    result = derive_dns(records=[rec], zones=[], devices=[], interfaces=[])
    edge = result.resolves_to[0]
    assert edge.target_label is None
    assert edge.target_key is None
    assert edge.value == "203.0.113.7"
    assert edge.reconciled is False


def test_non_address_records_resolve_to_literal_value_only() -> None:
    cname = make_record(
        "alias.corp.example.com", DnsRecordType.CNAME, "www.corp.example.com", zone=None
    )
    result = derive_dns(records=[cname], zones=[], devices=[], interfaces=[])
    edge = result.resolves_to[0]
    assert edge.target_label is None
    assert edge.value == "www.corp.example.com"
    assert edge.reconciled is False


def test_derive_dns_is_insensitive_to_input_ordering() -> None:
    dev = make_device("core-1", "192.0.2.1", device_id=DEV1)
    iface = make_interface(DEV1, "Ethernet1", "10.0.0.9/24", row_id=IF1)
    recs = [
        make_record("b.corp.example.com", DnsRecordType.A, "10.0.0.9", zone="corp.example.com"),
        make_record("a.corp.example.com", DnsRecordType.A, "203.0.113.7", zone="corp.example.com"),
    ]
    one = derive_dns(records=recs, zones=["corp.example.com"], devices=[dev], interfaces=[iface])
    two = derive_dns(
        records=list(reversed(recs)),
        zones=["corp.example.com"],
        devices=[dev],
        interfaces=[iface],
    )
    assert one.zones == two.zones
    assert one.records == two.records
    assert one.in_zone == two.in_zone
    assert one.resolves_to == two.resolves_to


def test_resolves_to_edges_match_the_source_zone_records_exactly() -> None:
    """Every record yields exactly one RESOLVES_TO edge keyed by its composite key."""
    zone = "corp.example.com"
    recs = [
        make_record("a.corp.example.com", DnsRecordType.A, "10.0.0.9", zone=zone),
        make_record("alias.corp.example.com", DnsRecordType.CNAME, "a.corp.example.com", zone=zone),
        make_record("ext.corp.example.com", DnsRecordType.A, "203.0.113.7", zone=zone),
    ]
    dev = make_device("core-1", "192.0.2.1", device_id=DEV1)
    iface = make_interface(DEV1, "Ethernet1", "10.0.0.9/24", row_id=IF1)
    result = derive_dns(records=recs, zones=[zone], devices=[dev], interfaces=[iface])
    by_record = {e.record_key: e for e in result.resolves_to}
    assert set(by_record) == {r.record_key for r in result.records}
    assert by_record["a.corp.example.com|a|10.0.0.9"].reconciled is True
    assert by_record["ext.corp.example.com|a|203.0.113.7"].reconciled is False
    alias_edge = by_record["alias.corp.example.com|cname|a.corp.example.com"]
    assert alias_edge.value == "a.corp.example.com"
