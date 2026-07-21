"""F5 BIG-IP plugin conformance + unit tests (ADR-0050, P4 W1-T1).

Covers:
- Shared conformance suite over recorded iControl REST fixtures (every declared
  capability, including ``fixtures:adc_services`` and
  ``fixtures:config_backup_archive`` — the three-file wiring, ADR-0050 §4.7).
- Mandatory fixture cases: multi-page collection (pagination); route-domain
  ``%<id>`` addresses; FQDN-node member; VS with no default pool; empty pool;
  ``forced_offline`` member; standalone (non-DSC) HA_STATUS; UCS
  save/download/delete control-plane JSON sequence over a synthetic binary blob.
- Zero-plaintext-leakage: login password, auth token, AND UCS passphrase appear
  in no raw artifact, log record, exception, repr, or normalized/result surface;
  the archive bytes themselves never leak (SecretBytes, metadata-only result).
- CR-gating negative control: restore refuses (typed PluginError) before ANY
  device call when the ChangePlan is not ``executing``.
- Route-domain / destination / member-state parsing units.

Live golden path deferred-accepted (no F5 hardware) — see
``tests/agents/eval/test_f5_bigip_live_golden_path.py`` and ADR-0050 §8/§9.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
from dataclasses import dataclass
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretBytes

from app.core.errors import PluginError
from app.plugins.base import (
    Capability,
    ChangeOutcome,
    ChangePlan,
    ConfigArchive,
    ConfigArchiveRef,
    PluginCapability,
)
from app.plugins.vendors.f5_bigip.client import F5Client
from app.plugins.vendors.f5_bigip.plugin import (
    F5BigipPlugin,
    F5ConfigArchiveBackup,
    F5ConfigArchiveRestore,
    F5DiscoveryApi,
    F5HaStatus,
    F5Services,
    _map_member_session,
    _map_member_state,
    _map_protocol,
    _parse_virtual_destination,
    _split_host_port,
    _split_route_domain,
)
from app.schemas.normalized import (
    AdcAdminState,
    AdcAvailability,
    AdcProtocol,
    HaPeerRole,
)
from tests.plugins.conformance import (
    ConformanceCase,
    assert_fixture_case_completeness,
    make_conformance_cases,
)

# ---------------------------------------------------------------------------
# Fake credentials — never real secrets (obviously-fake sentinels).
# ---------------------------------------------------------------------------

_FAKE_USERNAME = "netops-svc"
_FAKE_PASSWORD = "FakeF5+pass/word=="  # noqa: S105 — obviously-fake
_FAKE_TOKEN = "FakeF5AuthToken+secret/test=="  # noqa: S105 — obviously-fake
_FAKE_PASSPHRASE = "FakeUcsPassphrase+secret/test=="  # noqa: S105 — obviously-fake
#: Sentinel embedded in the synthetic UCS binary blob — must never leak.
_UCS_BLOB_SENTINEL = b"SYNTHETIC-UCS-PRIVATE-KEY-DO-NOT-LEAK"
_UCS_BLOB = b"UCSBLOB\x00" + _UCS_BLOB_SENTINEL + b"\x00" * 32


# ---------------------------------------------------------------------------
# Recorded iControl REST fixtures (realistic v16.x payload shapes).
# ---------------------------------------------------------------------------

_VERSION = {
    "entries": {
        "https://localhost/mgmt/tm/sys/version/0": {
            "nestedStats": {
                "entries": {
                    "Version": {"description": "16.1.3.1"},
                    "Product": {"description": "BIG-IP"},
                    "Build": {"description": "0.0.11"},
                }
            }
        }
    }
}

_GLOBAL_SETTINGS = {"hostname": "bigip-lab.example.com", "guiSetup": "disabled"}

_INTERFACES = {
    "items": [
        {
            "fullPath": "1.1",
            "macAddress": "00:01:02:03:04:05",
            "mtu": 9000,
            "enabled": True,
            "status": "up",
        },
        {"fullPath": "1.2", "macAddress": "none", "mtu": 1500, "disabled": True, "status": "down"},
    ]
}

_ROUTES = {
    "items": [
        {"fullPath": "/Common/default", "network": "default", "gw": "10.0.0.254"},
        {"fullPath": "/Common/rd2net", "network": "10.5.0.0%2/16", "gw": "10.5.0.254%2"},
    ]
}

_SELFIPS = {
    "items": [
        {"fullPath": "/Common/self_ext", "address": "10.2.2.1%2/24", "vlan": "/Common/external"},
        {"fullPath": "/Common/self_int", "address": "10.3.3.1/24", "vlan": "/Common/internal"},
    ]
}

# Virtual servers (single page): a route-domain VIP, a no-default-pool VS, a
# disabled VS, and an IPv6 destination.
_VIRTUALS = {
    "items": [
        {
            "fullPath": "/Common/vs_web",
            "destination": "/Common/10.2.2.2%2:443",
            "ipProtocol": "tcp",
            "pool": "/Common/pool_web",
            "enabled": True,
            "description": "web vip",
        },
        {
            "fullPath": "/Common/vs_nopool",
            "destination": "/Common/10.2.2.3:80",
            "ipProtocol": "tcp",
            "enabled": True,
        },
        {
            "fullPath": "/Common/vs_disabled",
            "destination": "/Common/10.2.2.4:80",
            "ipProtocol": "udp",
            "disabled": True,
            "pool": "/Common/pool_empty",
        },
        {
            "fullPath": "/Common/vs_v6",
            "destination": "/Common/2001:db8::1.8080",
            "ipProtocol": "tcp",
            "enabled": True,
        },
    ],
    "currentItemCount": 4,
    "totalItems": 4,
}

# Descriptive pools served on page 2: an empty pool, and a pool whose members
# exercise route-domain, forced_offline, and FQDN cases (ADR-0050 §8).
_DESCRIPTIVE_POOLS = [
    {
        "fullPath": "/Common/pool_empty",
        "monitor": "/Common/http",
        "membersReference": {"items": []},
    },
    {
        "fullPath": "/Common/pool_web",
        "monitor": "/Common/http and /Common/tcp",
        "membersReference": {
            "items": [
                {
                    "fullPath": "/Common/web01:80",
                    "address": "10.1.1.10%2",
                    "session": "monitor-enabled",
                    "state": "up",
                },
                {
                    "fullPath": "/Common/web02:80",
                    "address": "10.1.1.11",
                    "session": "user-down",
                    "state": "user-down",
                },
                {
                    "fullPath": "/Common/www.example.com:443",
                    "address": "any6",
                    "fqdn": {"tmName": "www.example.com"},
                    "session": "user-disabled",
                    "state": "unchecked",
                },
            ]
        },
    },
]


def _pool_page_one() -> dict:
    """100 generated pools (== page size) so the collection spans two pages."""
    items = [
        {
            "fullPath": f"/Common/genpool{i}",
            "monitor": "/Common/tcp",
            "membersReference": {
                "items": [
                    {
                        "fullPath": f"/Common/gen{i}:80",
                        "address": f"10.0.{i}.1",
                        "session": "monitor-enabled",
                        "state": "up",
                    }
                ]
            },
        }
        for i in range(100)
    ]
    return {
        "items": items,
        "currentItemCount": 100,
        "totalItems": 100 + len(_DESCRIPTIVE_POOLS),
        "nextLink": "https://localhost/mgmt/tm/ltm/pool?$top=100&$skip=100",
    }


# Standalone (non-DSC) HA fixtures.
_FAILOVER_STANDALONE = {
    "entries": {
        "https://localhost/mgmt/tm/cm/failover-status/0": {
            "nestedStats": {
                "entries": {
                    "status": {"description": "ACTIVE"},
                    "color": {"description": "green"},
                }
            }
        }
    }
}
_SYNC_STANDALONE = {
    "entries": {
        "https://localhost/mgmt/tm/cm/sync-status/0": {
            "nestedStats": {
                "entries": {
                    "mode": {"description": "standalone"},
                    "status": {"description": "Standalone"},
                    "summary": {"description": "Standalone"},
                }
            }
        }
    }
}

# Clustered HA fixtures (for the non-standalone unit test).
_FAILOVER_ACTIVE = {
    "entries": {
        "https://localhost/mgmt/tm/cm/failover-status/0": {
            "nestedStats": {
                "entries": {
                    "status": {"description": "STANDBY"},
                    "color": {"description": "green"},
                }
            }
        }
    }
}
_SYNC_IN_SYNC = {
    "entries": {
        "https://localhost/mgmt/tm/cm/sync-status/0": {
            "nestedStats": {
                "entries": {
                    "mode": {"description": "high-availability"},
                    "status": {"description": "In Sync"},
                    "summary": {"description": "device-group-1"},
                }
            }
        }
    }
}


# ---------------------------------------------------------------------------
# Mock iControl REST transport
# ---------------------------------------------------------------------------


def _make_handler(*, failover: dict = _FAILOVER_STANDALONE, sync: dict = _SYNC_STANDALONE):
    def _handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method

        def ok(payload: object) -> httpx.Response:
            return httpx.Response(
                200, text=json.dumps(payload), headers={"content-type": "application/json"}
            )

        if path == "/mgmt/shared/authn/login":
            # The login response carries the token — never raw-recorded/logged.
            return ok({"token": {"token": _FAKE_TOKEN, "timeout": 1200}})
        if path.startswith("/mgmt/shared/authz/tokens/"):
            return ok({"status": "revoked"})
        if path == "/mgmt/tm/sys/version":
            return ok(_VERSION)
        if path == "/mgmt/tm/sys/global-settings":
            return ok(_GLOBAL_SETTINGS)
        if path == "/mgmt/tm/net/interface":
            return ok(_INTERFACES)
        if path == "/mgmt/tm/net/route":
            return ok(_ROUTES)
        if path == "/mgmt/tm/net/self":
            return ok(_SELFIPS)
        if path == "/mgmt/tm/ltm/virtual":
            return ok(_VIRTUALS)
        if path == "/mgmt/tm/ltm/pool":
            skip = int(request.url.params.get("$skip", "0"))
            if skip == 0:
                return ok(_pool_page_one())
            return ok(
                {
                    "items": _DESCRIPTIVE_POOLS,
                    "currentItemCount": len(_DESCRIPTIVE_POOLS),
                    "totalItems": 100 + len(_DESCRIPTIVE_POOLS),
                }
            )
        if path == "/mgmt/tm/cm/failover-status":
            return ok(failover)
        if path == "/mgmt/tm/cm/sync-status":
            return ok(sync)
        if path == "/mgmt/tm/sys/ucs" and method == "POST":
            body = json.loads(request.content or b"{}")
            # The status echo carries NO passphrase (it must never be recorded).
            return ok({"command": body.get("command"), "name": body.get("name"), "generation": 1})
        if path.startswith("/mgmt/shared/file-transfer/ucs-downloads/"):
            return httpx.Response(
                200, content=_UCS_BLOB, headers={"content-type": "application/octet-stream"}
            )
        if path.startswith("/mgmt/tm/sys/ucs/") and method == "DELETE":
            return ok({"status": "deleted"})
        if path.startswith("/mgmt/shared/file-transfer/ucs-uploads/") and method == "POST":
            return ok({"status": "uploaded"})
        return ok({})

    return _handle


def _make_client(
    *, failover: dict = _FAILOVER_STANDALONE, sync: dict = _SYNC_STANDALONE
) -> F5Client:
    http = httpx.Client(transport=httpx.MockTransport(_make_handler(failover=failover, sync=sync)))
    return F5Client(
        host="bigip.example.com",
        username=_FAKE_USERNAME,
        password=_FAKE_PASSWORD,
        client=http,
    )


class _FakeVault:
    """In-memory PassphraseVault double (ADR-0050 §7.2 seam)."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self._counter = 0

    def issue_passphrase(self) -> tuple[str, str]:
        self._counter += 1
        ref = f"vault:archive-pass:{self._counter}"
        passphrase = f"{_FAKE_PASSPHRASE}-{self._counter}"
        self._store[ref] = passphrase
        return ref, passphrase

    def materialize_passphrase(self, passphrase_ref: str) -> str:
        return self._store[passphrase_ref]


@dataclass(frozen=True)
class _FixtureArchiveRef:
    """A :class:`ConfigArchiveRef` built from a freshly-fetched archive (test path)."""

    archive_id: object
    device_id: object
    archive_format: str
    sha256: str
    passphrase_ref: str
    content: SecretBytes


def _ref_from_archive(archive: ConfigArchive) -> _FixtureArchiveRef:
    ref = _FixtureArchiveRef(
        archive_id=uuid4(),
        device_id=uuid4(),
        archive_format=archive.format,
        sha256=archive.sha256,
        passphrase_ref=archive.passphrase_ref,
        content=archive.content,
    )
    assert isinstance(ref, ConfigArchiveRef)
    return ref


# ---------------------------------------------------------------------------
# Conformance suite
# ---------------------------------------------------------------------------


def _make_capability(impl: type[PluginCapability]) -> PluginCapability:
    return impl(_make_client(), uuid4(), _FakeVault())


def _invoke_restore(impl: type[PluginCapability]) -> object:
    """Change-write invoker for CONFIG_RESTORE_ARCHIVE (executing CR, ADR-0050 §7.4)."""
    vault = _FakeVault()
    client = _make_client()
    archive = F5ConfigArchiveBackup(client, uuid4(), vault).fetch_config_archive()
    ref = _ref_from_archive(archive)
    restore = impl(client, uuid4(), vault)
    plan = ChangePlan(change_request_id=uuid4(), cr_state="executing")
    return restore.restore_archive(ref, plan=plan)  # type: ignore[attr-defined]


CASES = make_conformance_cases(
    F5BigipPlugin(),
    capability_factory=_make_capability,
    change_write_invokers={Capability.CONFIG_RESTORE_ARCHIVE: _invoke_restore},
)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_f5_bigip_conformance(case: ConformanceCase) -> None:
    case.run()


def test_suite_covers_every_declared_capability() -> None:
    ids = {case.id for case in CASES}
    for capability in F5BigipPlugin.capabilities:
        assert f"implementation:{capability.value}" in ids
    assert_fixture_case_completeness(F5BigipPlugin(), CASES)


# ---------------------------------------------------------------------------
# Mandatory fixture-case assertions (beyond the generic conformance shape).
# ---------------------------------------------------------------------------


class TestF5AdcServices:
    def test_pagination_spans_two_pages(self) -> None:
        cap = F5Services(_make_client(), uuid4())
        pools = cap.get_pools()
        # 100 generated (page 1) + 2 descriptive (page 2) = 102.
        assert len(pools) == 102
        # Two raw page artifacts recorded (raw-first per page, ADR-0006 §3).
        page_raws = [r for r in cap.raw_outputs if "ltm_pool[page=" in r.command]
        assert len(page_raws) == 2

    def test_route_domain_vip_and_member(self) -> None:
        cap = F5Services(_make_client(), uuid4())
        vips = cap.get_virtual_servers()
        vs_web = next(v for v in vips if v.name == "/Common/vs_web")
        assert str(vs_web.vip_address) == "10.2.2.2"
        assert vs_web.vrf == "2"
        assert vs_web.port == 443
        assert vs_web.protocol == AdcProtocol.TCP
        assert vs_web.pool_name == "/Common/pool_web"

        pools = cap.get_pools()
        pool_web = next(p for p in pools if p.name == "/Common/pool_web")
        web01 = next(m for m in pool_web.members if m.name == "/Common/web01:80")
        assert str(web01.address) == "10.1.1.10"
        assert web01.vrf == "2"
        assert web01.admin_state == AdcAdminState.ENABLED
        assert web01.availability == AdcAvailability.AVAILABLE

    def test_vs_without_default_pool(self) -> None:
        cap = F5Services(_make_client(), uuid4())
        vs = next(v for v in cap.get_virtual_servers() if v.name == "/Common/vs_nopool")
        assert vs.pool_name is None

    def test_disabled_vs_collected(self) -> None:
        cap = F5Services(_make_client(), uuid4())
        vs = next(v for v in cap.get_virtual_servers() if v.name == "/Common/vs_disabled")
        assert vs.enabled is False
        assert vs.availability == AdcAvailability.DISABLED
        assert vs.protocol == AdcProtocol.UDP

    def test_ipv6_destination(self) -> None:
        cap = F5Services(_make_client(), uuid4())
        vs = next(v for v in cap.get_virtual_servers() if v.name == "/Common/vs_v6")
        assert str(vs.vip_address) == "2001:db8::1"
        assert vs.port == 8080

    def test_empty_pool(self) -> None:
        cap = F5Services(_make_client(), uuid4())
        pool = next(p for p in cap.get_pools() if p.name == "/Common/pool_empty")
        assert pool.members == ()
        assert pool.availability == AdcAvailability.UNKNOWN
        assert pool.monitors == ("/Common/http",)

    def test_forced_offline_member(self) -> None:
        cap = F5Services(_make_client(), uuid4())
        pool = next(p for p in cap.get_pools() if p.name == "/Common/pool_web")
        web02 = next(m for m in pool.members if m.name == "/Common/web02:80")
        assert web02.admin_state == AdcAdminState.FORCED_OFFLINE
        assert web02.availability == AdcAvailability.OFFLINE

    def test_fqdn_member(self) -> None:
        cap = F5Services(_make_client(), uuid4())
        pool = next(p for p in cap.get_pools() if p.name == "/Common/pool_web")
        fqdn_member = next(m for m in pool.members if m.fqdn is not None)
        assert fqdn_member.fqdn == "www.example.com"
        assert fqdn_member.address is None  # unresolved FQDN node
        assert fqdn_member.admin_state == AdcAdminState.DISABLED


class TestF5Routes:
    def test_static_and_connected_routes_with_vrf(self) -> None:
        from app.plugins.vendors.f5_bigip.plugin import F5Routes
        from app.schemas.normalized import RouteProtocol

        cap = F5Routes(_make_client(), uuid4())
        routes = cap.get_routes()
        default = next(r for r in routes if str(r.destination) == "0.0.0.0/0")
        assert default.protocol == RouteProtocol.STATIC
        rd = next(r for r in routes if str(r.destination) == "10.5.0.0/16")
        assert rd.vrf == "2"
        connected = [r for r in routes if r.protocol == RouteProtocol.CONNECTED]
        assert any(str(r.destination) == "10.2.2.0/24" and r.vrf == "2" for r in connected)


class TestF5HaStatus:
    def test_standalone_reports_unknown_role(self) -> None:
        cap = F5HaStatus(_make_client(), uuid4())
        rows = cap.get_ha_status()
        assert len(rows) == 1
        assert rows[0].peer_role == HaPeerRole.UNKNOWN
        assert rows[0].consistency_check_ok is None

    def test_clustered_reports_role_and_sync(self) -> None:
        client = _make_client(failover=_FAILOVER_ACTIVE, sync=_SYNC_IN_SYNC)
        cap = F5HaStatus(client, uuid4())
        rows = cap.get_ha_status()
        assert rows[0].peer_role == HaPeerRole.STANDBY
        assert rows[0].consistency_check_ok is True
        assert rows[0].ha_domain == "device-group-1"


class TestF5DiscoveryApi:
    def test_device_facts(self) -> None:
        cap = F5DiscoveryApi(_make_client(), uuid4())
        facts = cap.get_device_facts()
        assert facts.hostname == "bigip-lab.example.com"
        assert facts.vendor_id == "f5_bigip"
        assert facts.os_version == "16.1.3.1"


# ---------------------------------------------------------------------------
# UCS archive control plane + restore gating (ADR-0050 §7.2/§7.4).
# ---------------------------------------------------------------------------


class TestF5ConfigArchive:
    def test_backup_returns_secret_archive(self) -> None:
        cap = F5ConfigArchiveBackup(_make_client(), uuid4(), _FakeVault())
        archive = cap.fetch_config_archive()
        assert archive.format == "ucs"
        assert archive.size_bytes == len(_UCS_BLOB)
        assert len(archive.sha256) == 64
        assert archive.passphrase_ref.startswith("vault:")
        assert archive.content.get_secret_value() == _UCS_BLOB
        # Save + delete control-plane JSON recorded; the binary body is NOT.
        commands = [r.command for r in cap.raw_outputs]
        assert any("ucs_save" in c for c in commands)
        assert any("ucs_delete" in c for c in commands)
        for raw in cap.raw_outputs:
            assert _UCS_BLOB_SENTINEL.decode("latin-1") not in raw.output

    def test_restore_success_over_fixtures(self) -> None:
        result = _invoke_restore(F5ConfigArchiveRestore)
        assert result.outcome == ChangeOutcome.APPLIED
        assert result.verified is True
        assert result.rollback is None
        # Metadata only — never archive contents (ADR-0050 §7.4).
        blob = str(result.applied_diff)
        assert _UCS_BLOB_SENTINEL.decode("latin-1") not in blob

    def test_restore_refuses_without_executing_cr(self) -> None:
        """Restore refuses (typed PluginError) BEFORE any device call (ADR-0050 §7.4)."""
        seen: list[str] = []

        def _explode(request: httpx.Request) -> httpx.Response:
            seen.append(request.url.path)
            raise AssertionError(f"restore made a device call before CR gate: {request.url.path}")

        http = httpx.Client(transport=httpx.MockTransport(_explode))
        client = F5Client(
            host="bigip.example.com", username=_FAKE_USERNAME, password=_FAKE_PASSWORD, client=http
        )
        restore = F5ConfigArchiveRestore(client, uuid4(), _FakeVault())
        ref = _FixtureArchiveRef(
            archive_id=uuid4(),
            device_id=uuid4(),
            archive_format="ucs",
            sha256="a" * 64,
            passphrase_ref="vault:x",
            content=SecretBytes(b"x"),
        )
        plan = ChangePlan(change_request_id=uuid4(), cr_state="approved")  # NOT executing
        with pytest.raises(PluginError):
            restore.restore_archive(ref, plan=plan)
        assert seen == []  # zero device calls

    def test_restore_rollback_succeeds_when_baseline_reachable(self) -> None:
        """Verify fails once then recovers: rollback loads baseline and verifies OK."""
        vault = _FakeVault()
        state = {"loads": 0}

        def _handle(request: httpx.Request) -> httpx.Response:
            base = _make_handler()
            path = request.url.path
            if path == "/mgmt/tm/sys/ucs" and request.method == "POST":
                body = json.loads(request.content or b"{}")
                if body.get("command") == "load":
                    state["loads"] += 1
                return base(request)
            if path == "/mgmt/tm/sys/version" and state["loads"] == 1:
                # Fails right after the TARGET load; the baseline (2nd) load recovers.
                return httpx.Response(503, text="{}")
            return base(request)

        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = F5Client(
            host="bigip.example.com", username=_FAKE_USERNAME, password=_FAKE_PASSWORD, client=http
        )
        archive = F5ConfigArchiveBackup(_make_client(), uuid4(), vault).fetch_config_archive()
        restore = F5ConfigArchiveRestore(client, uuid4(), vault)
        plan = ChangePlan(change_request_id=uuid4(), cr_state="executing")
        result = restore.restore_archive(_ref_from_archive(archive), plan=plan)
        assert result.outcome == ChangeOutcome.ROLLED_BACK
        assert result.rollback is not None
        assert result.rollback.succeeded is True

    def test_restore_rolls_back_on_verify_failure(self) -> None:
        """A failed verify-after triggers a baseline reload; never silent (ADR-0021)."""
        vault = _FakeVault()
        # A client whose post-load verify (get_version) fails deterministically.
        state = {"loaded": False}

        def _handle(request: httpx.Request) -> httpx.Response:
            base = _make_handler()
            path = request.url.path
            if path == "/mgmt/tm/sys/ucs" and request.method == "POST":
                body = json.loads(request.content or b"{}")
                if body.get("command") == "load":
                    state["loaded"] = True
                return base(request)
            if path == "/mgmt/tm/sys/version" and state["loaded"]:
                # Post-restore reachability check fails -> rollback path.
                return httpx.Response(503, text="{}")
            return base(request)

        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = F5Client(
            host="bigip.example.com", username=_FAKE_USERNAME, password=_FAKE_PASSWORD, client=http
        )
        archive = F5ConfigArchiveBackup(_make_client(), uuid4(), vault).fetch_config_archive()
        restore = F5ConfigArchiveRestore(client, uuid4(), vault)
        plan = ChangePlan(change_request_id=uuid4(), cr_state="executing")
        result = restore.restore_archive(_ref_from_archive(archive), plan=plan)
        assert result.outcome == ChangeOutcome.ROLLBACK_FAILED
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.attempted is True
        assert result.rollback.succeeded is False  # never reported as rolled_back

    def test_backup_deletes_residue_when_download_fails(self) -> None:
        """A ``download_ucs`` failure after ``save_ucs`` must still delete the on-box
        UCS — a download error must never orphan passphrase-encrypted residue
        (ADR-0050 §7.2; the ``finally`` cleanup path)."""

        def _handle(request: httpx.Request) -> httpx.Response:
            base = _make_handler()
            if request.url.path.startswith("/mgmt/shared/file-transfer/ucs-downloads/"):
                # The just-saved UCS fails to download.
                return httpx.Response(503, text="{}")
            return base(request)

        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = F5Client(
            host="bigip.example.com", username=_FAKE_USERNAME, password=_FAKE_PASSWORD, client=http
        )
        cap = F5ConfigArchiveBackup(client, uuid4(), _FakeVault())
        with pytest.raises(PluginError):
            cap.fetch_config_archive()
        # The residue delete ran despite the download failure (no on-box leftover).
        commands = [r.command for r in cap.raw_outputs]
        assert any("ucs_save" in c for c in commands)
        assert any("ucs_delete" in c for c in commands), (
            "on-box UCS residue must be deleted even when download_ucs fails (ADR-0050 §7.2)"
        )

    def test_restore_deletes_baseline_and_target_residue(self) -> None:
        """Restore leaves NO on-box UCS behind: both the baseline and the target
        archive are deleted on the success path (ADR-0050 §7.2/§7.4)."""
        vault = _FakeVault()
        client = _make_client()
        archive = F5ConfigArchiveBackup(client, uuid4(), vault).fetch_config_archive()
        restore = F5ConfigArchiveRestore(client, uuid4(), vault)
        plan = ChangePlan(change_request_id=uuid4(), cr_state="executing")
        result = restore.restore_archive(_ref_from_archive(archive), plan=plan)
        assert result.outcome == ChangeOutcome.APPLIED
        commands = [r.command for r in restore.raw_outputs]
        assert any("target_ucs_delete" in c for c in commands), "target UCS residue not deleted"
        assert any("baseline_ucs_delete" in c for c in commands), "baseline UCS residue not deleted"


# ---------------------------------------------------------------------------
# Zero-plaintext-leakage (password, token, passphrase, archive bytes).
# ADR-0050 §1/§2/§7.3 — the escalated secret-surface gate.
# ---------------------------------------------------------------------------


class TestF5SecretHygiene:
    def _forbidden(self) -> tuple[str, ...]:
        enc_pass = urllib.parse.quote(_FAKE_PASSWORD, safe="")
        enc_token = urllib.parse.quote(_FAKE_TOKEN, safe="")
        return (
            _FAKE_PASSWORD,
            enc_pass,
            _FAKE_TOKEN,
            enc_token,
            _FAKE_PASSPHRASE,
            _UCS_BLOB_SENTINEL.decode("latin-1"),
        )

    def test_client_repr_hides_secrets(self) -> None:
        client = _make_client()
        client.get_version()  # mint a token
        r = repr(client)
        assert _FAKE_PASSWORD not in r
        assert _FAKE_TOKEN not in r
        assert _FAKE_USERNAME not in r

    def test_no_secret_in_raw_artifacts(self) -> None:
        vault = _FakeVault()
        client = _make_client()
        for cap in (
            F5DiscoveryApi(client, uuid4()),
            F5Services(client, uuid4()),
            F5HaStatus(client, uuid4()),
        ):
            getattr(
                cap,
                {
                    "F5DiscoveryApi": "discover",
                    "F5Services": "get_virtual_servers",
                    "F5HaStatus": "get_ha_status",
                }[type(cap).__name__],
            )()
            for raw in cap.raw_outputs:
                for needle in self._forbidden():
                    assert needle not in raw.output
                    assert needle not in raw.command

        backup = F5ConfigArchiveBackup(client, uuid4(), vault)
        backup.fetch_config_archive()
        for raw in backup.raw_outputs:
            for needle in self._forbidden():
                assert needle not in raw.output
                assert needle not in raw.command

    def test_no_secret_in_logs(self, caplog: pytest.LogCaptureFixture) -> None:
        vault = _FakeVault()
        client = _make_client()
        with caplog.at_level(logging.DEBUG, logger="httpx"), caplog.at_level(logging.DEBUG):
            F5DiscoveryApi(client, uuid4()).discover()
            F5ConfigArchiveBackup(client, uuid4(), vault).fetch_config_archive()
        for record in caplog.records:
            message = record.getMessage()
            for needle in self._forbidden():
                assert needle not in message, f"secret leaked in log: {message!r}"

    def test_no_secret_in_archive_result_surfaces(self) -> None:
        vault = _FakeVault()
        archive = F5ConfigArchiveBackup(_make_client(), uuid4(), vault).fetch_config_archive()
        # SecretBytes masks in repr + model_dump.
        for blob in (repr(archive), str(archive.model_dump())):
            assert _UCS_BLOB_SENTINEL.decode("latin-1") not in blob
        result = _invoke_restore(F5ConfigArchiveRestore)
        for needle in self._forbidden():
            assert needle not in str(result.model_dump())

    def test_login_failure_error_hides_secret(self) -> None:
        def _fail(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, text='{"code":401}')

        http = httpx.Client(transport=httpx.MockTransport(_fail))
        client = F5Client(
            host="bigip.example.com", username=_FAKE_USERNAME, password=_FAKE_PASSWORD, client=http
        )
        with pytest.raises(PluginError) as exc:
            F5DiscoveryApi(client, uuid4()).discover()
        assert _FAKE_PASSWORD not in str(exc.value)
        assert _FAKE_PASSWORD not in str(exc.value.args)


# ---------------------------------------------------------------------------
# Parser units (route domains, destinations, member state — ADR-0050 §5).
# ---------------------------------------------------------------------------


class TestF5Parsers:
    def test_split_route_domain(self) -> None:
        assert _split_route_domain("10.1.1.1%2") == ("10.1.1.1", "2")
        assert _split_route_domain("10.1.1.1%0") == ("10.1.1.1", None)
        assert _split_route_domain("10.1.1.1") == ("10.1.1.1", None)

    def test_split_host_port_v4_v6(self) -> None:
        assert _split_host_port("10.1.1.1:443") == ("10.1.1.1", 443)
        assert _split_host_port("2001:db8::1.443") == ("2001:db8::1", 443)
        assert _split_host_port("10.1.1.1") == ("10.1.1.1", None)
        assert _split_host_port("10.1.1.1:any") == ("10.1.1.1", None)

    def test_parse_virtual_destination_address_list(self) -> None:
        # A non-literal destination (named address list) yields no VIP address.
        assert _parse_virtual_destination("/Common/vip_addr_list") == (None, None, None)

    def test_map_protocol(self) -> None:
        assert _map_protocol("tcp") == AdcProtocol.TCP
        assert _map_protocol(None) == AdcProtocol.ANY
        assert _map_protocol("gre") == AdcProtocol.OTHER

    def test_map_member_state_and_session(self) -> None:
        assert _map_member_session("user-down") == AdcAdminState.FORCED_OFFLINE
        assert _map_member_session(None) == AdcAdminState.ENABLED
        assert _map_member_state("up") == AdcAvailability.AVAILABLE
        assert _map_member_state(None) == AdcAvailability.UNKNOWN


# ---------------------------------------------------------------------------
# Client lifecycle: token re-auth, revocation, upload (ADR-0050 §2).
# ---------------------------------------------------------------------------


class TestF5ClientLifecycle:
    def test_reauth_once_on_401(self) -> None:
        """A 401 on a tokened request triggers exactly one re-auth + retry."""
        logins = {"n": 0}
        first = {"done": False}

        def _handle(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/mgmt/shared/authn/login":
                logins["n"] += 1
                return httpx.Response(200, json={"token": {"token": _FAKE_TOKEN}})
            if request.url.path == "/mgmt/tm/sys/version" and not first["done"]:
                first["done"] = True
                return httpx.Response(401, json={"code": 401})
            return httpx.Response(200, json=_VERSION)

        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = F5Client(
            host="bigip.example.com", username=_FAKE_USERNAME, password=_FAKE_PASSWORD, client=http
        )
        client.get_version()
        assert logins["n"] == 2  # initial login + one re-auth

    def test_close_revokes_token(self) -> None:
        revoked: list[str] = []

        def _handle(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/mgmt/shared/authn/login":
                return httpx.Response(200, json={"token": {"token": _FAKE_TOKEN}})
            if (
                request.url.path.startswith("/mgmt/shared/authz/tokens/")
                and request.method == "DELETE"
            ):
                revoked.append(request.url.path)
                return httpx.Response(200, json={"status": "revoked"})
            return httpx.Response(200, json=_VERSION)

        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = F5Client(
            host="bigip.example.com", username=_FAKE_USERNAME, password=_FAKE_PASSWORD, client=http
        )
        client.get_version()
        client.close()
        assert len(revoked) == 1  # token revoked on close (ADR-0050 §2)

    def test_revocation_failure_is_nonfatal(self, caplog: pytest.LogCaptureFixture) -> None:
        def _handle(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/mgmt/shared/authn/login":
                return httpx.Response(200, json={"token": {"token": _FAKE_TOKEN}})
            if request.method == "DELETE":
                raise httpx.ConnectError("boom")
            return httpx.Response(200, json=_VERSION)

        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = F5Client(
            host="bigip.example.com", username=_FAKE_USERNAME, password=_FAKE_PASSWORD, client=http
        )
        client.get_version()
        with caplog.at_level(logging.WARNING):
            client.close()  # must not raise
        for record in caplog.records:
            assert _FAKE_TOKEN not in record.getMessage()

    def test_upload_ucs_records_status(self) -> None:
        client = _make_client()
        assert "uploaded" in client.upload_ucs("x.ucs", b"bytes")


# ---------------------------------------------------------------------------
# Plugin registration (ADR-0006 §5).
# ---------------------------------------------------------------------------


class TestF5Registration:
    def test_iter_builtin_plugins_includes_f5(self) -> None:
        from app.plugins.vendors import iter_builtin_plugins

        assert "f5_bigip" in [p.vendor_id for p in iter_builtin_plugins()]

    def test_default_registry_contains_f5(self) -> None:
        from app.plugins.registry import get_default_registry

        get_default_registry.cache_clear()
        try:
            assert "f5_bigip" in get_default_registry().vendor_ids()
        finally:
            get_default_registry.cache_clear()

    def test_declares_expected_capabilities(self) -> None:
        assert F5BigipPlugin.capabilities == frozenset(
            {
                Capability.DISCOVERY_API,
                Capability.INTERFACES,
                Capability.ROUTES,
                Capability.ADC_SERVICES,
                Capability.HA_STATUS,
                Capability.CONFIG_BACKUP_ARCHIVE,
                Capability.CONFIG_RESTORE_ARCHIVE,
            }
        )
