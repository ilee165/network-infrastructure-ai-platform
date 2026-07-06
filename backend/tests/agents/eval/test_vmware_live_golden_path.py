"""Opt-in LIVE VMware vCenter golden-path test (ADR-0051 §8, deferred-accepted → live lab).

The live-lab twin of the deterministic conformance suite
(``tests/plugins/test_vmware_conformance.py``). It drives the ADR-0051 §8 golden
path against a **real vCenter** (or the ``vcsim`` simulator, below) instead of
recorded property-set fixtures — proving the wiring works against the genuine
pyVmomi SOAP surface: ``SmartConnect`` session lifecycle, the PropertyCollector
``RetrievePropertiesEx`` / ``ContinueRetrievePropertiesEx`` continuation paging,
and the guest-info / device-backing / host-network property shapes that only a
running vCenter exhibits (ADR-0051 §9 open questions):

    discover (vCenter identity) → virtualization inventory
      (VMs + hosts + clusters + port groups, with placement + vNIC/pNIC/port-group
       joins) → [W2 derivation smoke consumes the §5.5 contract]

**This test NEVER runs in CI.** It is gated by ``@pytest.mark.integration`` AND a
``skipif`` keyed on the ``VMWARE_VCENTER_HOST`` / ``VMWARE_VCENTER_USERNAME`` /
``VMWARE_VCENTER_PASSWORD`` environment variables, which CI never sets — so it is
*collected but skipped* under the standard ``pytest`` gate run.

## Running it against a real vCenter

Provision a **dedicated read-only service account** (ADR-0051 §3: the built-in
Read-Only role on the root vCenter object with "Propagate to children" — never
``administrator@vsphere.local``, never a shared human account) and export:

    VMWARE_VCENTER_HOST       hostname / IP of the vCenter management interface
    VMWARE_VCENTER_USERNAME   the read-only service-account username
    VMWARE_VCENTER_PASSWORD   the service-account password (a SECRET — never
                              logged, never committed; rides the SmartConnect
                              login call only)
    VMWARE_VCENTER_PORT       optional: SOAP port (default 443)
    VMWARE_VCENTER_VERIFY     optional: "0"/"false" to disable TLS verify for a
                              self-signed lab cert (default: verify ON, ADR-0051 §1)

## Running it against ``vcsim`` (the documented preferred substitute, ADR-0051 §8)

``vcsim`` (from the govmomi project) speaks the same vSphere SOAP API pyVmomi
targets, so it is the ADR-0025 §9 ``n9000v`` pattern for VMware — a
CI/lab-startable simulator that needs no ESXi hardware or licenses::

    docker run --rm -p 8989:8989 vmware/vcsim -l 0.0.0.0:8989

    export VMWARE_VCENTER_HOST=127.0.0.1
    export VMWARE_VCENTER_PORT=8989
    export VMWARE_VCENTER_USERNAME=user
    export VMWARE_VCENTER_PASSWORD=pass
    export VMWARE_VCENTER_VERIFY=0
    pytest tests/agents/eval/test_vmware_live_golden_path.py

``vcsim`` fixture fidelity — which mandatory §8 cases it can reproduce vs which
need a real VCSA capture — is a named open question (ADR-0051 §9.5).

The password lives only inside :class:`VsphereClient` (name-mangled,
redaction-filtered) and is asserted absent from every raw artifact; the session
is always disconnected in a ``finally`` block (ADR-0051 §2).
"""

from __future__ import annotations

import os
import uuid

import pytest

from app.plugins.vendors.vmware.client import VsphereClient
from app.plugins.vendors.vmware.plugin import VmwareDiscoveryApi, VmwareVirtualizationInventory

_HOST = os.environ.get("VMWARE_VCENTER_HOST", "").strip()
_USER = os.environ.get("VMWARE_VCENTER_USERNAME", "").strip()
_PASS = os.environ.get("VMWARE_VCENTER_PASSWORD", "").strip()
_PORT = int(os.environ.get("VMWARE_VCENTER_PORT", "443") or "443")
_VERIFY = os.environ.get("VMWARE_VCENTER_VERIFY", "1").strip().lower() not in {"0", "false", "no"}

_LIVE_CONFIGURED = bool(_HOST and _USER and _PASS)
_SKIP_REASON = (
    "opt-in live lab gate: set VMWARE_VCENTER_HOST, VMWARE_VCENTER_USERNAME and "
    "VMWARE_VCENTER_PASSWORD to run against a real vCenter or a vcsim simulator "
    "(ADR-0051 §8). Skipped in CI."
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _LIVE_CONFIGURED, reason=_SKIP_REASON),
]


@pytest.fixture()
def live_client() -> VsphereClient:
    client = VsphereClient(
        host=_HOST,
        username=_USER,
        password=_PASS,
        port=_PORT,
        verify=_VERIFY,
    )
    try:
        yield client
    finally:
        client.disconnect()  # SOAP Logout in finally (ADR-0051 §2)


class TestVmwareLiveGoldenPath:
    def test_discover_then_virtualization_inventory(self, live_client: VsphereClient) -> None:
        device_id = uuid.uuid4()

        # 1. Discover vCenter identity over the genuine pyVmomi surface. Keep the
        #    instance — the secret-hygiene check below inspects the raw artifacts
        #    THIS call produced (a fresh instance has empty raw_outputs, ADR-0051 §2).
        discovery = VmwareDiscoveryApi(live_client, device_id)
        facts = discovery.get_device_facts()
        assert facts.vendor_id == "vmware"
        assert facts.hostname

        # 2. Virtualization inventory: VMs + hosts + clusters + port groups.
        inv = VmwareVirtualizationInventory(live_client, device_id)
        vms = inv.get_virtual_machines()
        hosts = inv.get_hypervisor_hosts()
        clusters = inv.get_compute_clusters()
        port_groups = inv.get_port_groups()

        # vcsim ships VMs and hosts by default (ADR-0051 §8), so an empty result is
        # itself a failure — assert non-empty before the per-record loops, which
        # would otherwise pass vacuously.
        assert vms, "golden-path vCenter/vcsim must expose at least one VM (ADR-0051 §8)"
        assert hosts, "golden-path vCenter/vcsim must expose at least one host (ADR-0051 §8)"

        # Every record re-validates against its normalized model by construction.
        for vm in vms:
            assert vm.source_vendor == "vmware"
            assert vm.moref
        for host in hosts:
            assert host.source_vendor == "vmware"
            assert host.moref
        for cluster in clusters:
            assert cluster.source_vendor == "vmware"
        for pg in port_groups:
            assert pg.source_vendor == "vmware"

        # 3. §5.5 join contract smoke: every placed VM's host_name resolves to a
        #    collected host (the W2 derivation's VM→host edge). vcsim ships hosts
        #    and VMs by default, so this holds on the simulator too.
        host_names = {h.name for h in hosts}
        for vm in vms:
            if vm.host_name is not None:
                assert vm.host_name in host_names

        # Secret hygiene: the password never lands in a raw artifact (ADR-0051 §2).
        # Inspect the instances that actually made calls — ``discovery`` (step 1)
        # and ``inv`` (step 2) both carry populated ``raw_outputs``.
        for source in (inv, discovery):
            assert source.raw_outputs, "secret-hygiene check needs exercised raw artifacts"
            for raw in source.raw_outputs:
                assert _PASS not in raw.output
                assert _PASS not in raw.command
