"""Opt-in LIVE F5 BIG-IP golden-path test (ADR-0050 §8, deferred-accepted -> live lab).

The live-lab twin of the deterministic conformance suite
(``tests/plugins/test_f5_bigip_conformance.py``). It drives the ADR-0050 §8
golden path against a **real / virtual BIG-IP** instead of an
``httpx.MockTransport`` — proving the wiring works against the genuine iControl
REST surface, token lifecycle, ``$top``/``$skip`` paging, and the UCS
save/download/delete control plane that only a running appliance exhibits
(ADR-0050 §9 open questions):

    discover (facts) -> ADC inventory (virtual servers + pools + members)
      -> UCS backup (passphrase-encrypted on-box, downloaded, on-box residue
         deleted; returned as a secret-bearing ConfigArchive)
      -> [OPT-IN, DESTRUCTIVE] CR-gated restore with a pre-captured baseline and
         the ADR-0021 never-silent rollback contract.

**This test NEVER runs in CI.** It is gated by ``@pytest.mark.integration`` AND a
``skipif`` keyed on the ``F5_BIGIP_HOST`` / ``F5_BIGIP_USERNAME`` /
``F5_BIGIP_PASSWORD`` environment variables, which CI never sets — so it is
*collected but skipped* under the standard ``pytest`` gate run. To run it against
a lab appliance, bring up a BIG-IP VE (or a lab device), provision a dedicated
admin-role service account (UCS create/download/load require admin — ADR-0050 §2
least-privilege note), and export:

    F5_BIGIP_HOST        hostname / IP of the management interface
    F5_BIGIP_USERNAME    the service-account username
    F5_BIGIP_PASSWORD    the service-account password (a SECRET — never logged,
                         never committed; rides the login POST body only)
    F5_BIGIP_LOGIN_PROVIDER  optional: loginProviderName (default ``tmos``;
                             set for RADIUS/TACACS+/LDAP-backed accounts)
    F5_BIGIP_VERIFY      optional: "0"/"false" to disable TLS verify for a
                         self-signed lab cert (default: verify ON)
    F5_BIGIP_ALLOW_DESTRUCTIVE_RESTORE  optional: "1" to ALSO exercise the
                         restore step. A UCS load restarts BIG-IP services and can
                         force an HA failover (ADR-0050 §7.4 blast radius) — it is
                         OFF by default so even a live lab does not reboot an
                         appliance unless the operator explicitly opts in.

The passphrase used to encrypt the UCS is minted here with real entropy
(``secrets.token_urlsafe``) and held only in-process; it is asserted absent from
every raw artifact and is never logged (parity with the mock variant). The login
password + session token live only inside :class:`F5Client`.
"""

from __future__ import annotations

import os
import secrets
import uuid

import pytest

from app.plugins.base import ChangeOutcome, ChangePlan, ConfigArchiveRef
from app.plugins.vendors.f5_bigip.client import F5Client
from app.plugins.vendors.f5_bigip.plugin import (
    F5ConfigArchiveBackup,
    F5ConfigArchiveRestore,
    F5DiscoveryApi,
    F5Services,
)

_HOST = os.environ.get("F5_BIGIP_HOST", "").strip()
_USER = os.environ.get("F5_BIGIP_USERNAME", "").strip()
_PASS = os.environ.get("F5_BIGIP_PASSWORD", "").strip()
_PROVIDER = os.environ.get("F5_BIGIP_LOGIN_PROVIDER", "tmos").strip() or "tmos"
_VERIFY = os.environ.get("F5_BIGIP_VERIFY", "1").strip().lower() not in {"0", "false", "no"}
_ALLOW_RESTORE = os.environ.get("F5_BIGIP_ALLOW_DESTRUCTIVE_RESTORE", "").strip() in {"1", "true"}

_LIVE_CONFIGURED = bool(_HOST and _USER and _PASS)
_SKIP_REASON = (
    "opt-in live lab gate: set F5_BIGIP_HOST, F5_BIGIP_USERNAME and F5_BIGIP_PASSWORD "
    "to run against a real/virtual BIG-IP (ADR-0050 §8). Skipped in CI."
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _LIVE_CONFIGURED, reason=_SKIP_REASON),
]


class _LivePassphraseVault:
    """A real-entropy in-memory PassphraseVault for the live golden path.

    Mints per-backup passphrases with ``secrets.token_urlsafe`` (production uses
    the credential vault, ADR-0050 §7.2). Held in-process only; never logged.
    """

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def issue_passphrase(self) -> tuple[str, str]:
        ref = f"live:archive-pass:{uuid.uuid4().hex}"
        passphrase = secrets.token_urlsafe(32)
        self._store[ref] = passphrase
        return ref, passphrase

    def materialize_passphrase(self, passphrase_ref: str) -> str:
        return self._store[passphrase_ref]


@pytest.fixture()
def live_client() -> F5Client:
    client = F5Client(
        host=_HOST,
        username=_USER,
        password=_PASS,
        login_provider=_PROVIDER,
        verify=_VERIFY,
    )
    try:
        yield client
    finally:
        client.close()  # best-effort token revocation (ADR-0050 §2)


class TestF5LiveGoldenPath:
    def test_discover_then_adc_inventory_then_ucs_backup(self, live_client: F5Client) -> None:
        device_id = uuid.uuid4()
        vault = _LivePassphraseVault()

        # 1. Discover device identity facts over the genuine REST surface.
        facts = F5DiscoveryApi(live_client, device_id).get_device_facts()
        assert facts.vendor_id == "f5_bigip"
        assert facts.hostname

        # 2. ADC inventory: virtual servers + pools with nested members (paged).
        services = F5Services(live_client, device_id)
        vips = services.get_virtual_servers()
        pools = services.get_pools()
        # Every record re-validates against its normalized model by construction.
        for vip in vips:
            assert vip.source_vendor == "f5_bigip"
        for pool in pools:
            assert pool.source_vendor == "f5_bigip"

        # 3. UCS backup: passphrase-encrypted on-box, downloaded, residue deleted.
        backup = F5ConfigArchiveBackup(live_client, device_id, vault)
        archive = backup.fetch_config_archive()
        assert archive.format == "ucs"
        assert len(archive.sha256) == 64
        assert archive.size_bytes > 0

        # Secret hygiene: the passphrase never lands in a raw artifact (ADR-0050 §7.2).
        passphrase = vault.materialize_passphrase(archive.passphrase_ref)
        for raw in backup.raw_outputs:
            assert passphrase not in raw.output
            assert passphrase not in raw.command

        if not _ALLOW_RESTORE:
            pytest.skip(
                "restore step is destructive (UCS load restarts services / can force an HA "
                "failover, ADR-0050 §7.4); set F5_BIGIP_ALLOW_DESTRUCTIVE_RESTORE=1 to run it"
            )

        # 4. CR-gated restore. In production the Automation Agent builds this
        #    ChangePlan only from a four-eyes-approved, EXECUTING ChangeRequest
        #    (ADR-0020/0021); the golden path attests it directly.
        ref = _archive_ref(archive, device_id)
        restore = F5ConfigArchiveRestore(live_client, device_id, vault)
        plan = ChangePlan(change_request_id=uuid.uuid4(), cr_state="executing")
        result = restore.restore_archive(ref, plan=plan)
        assert result.outcome in {ChangeOutcome.APPLIED, ChangeOutcome.ROLLED_BACK}
        # A metadata-only result — never archive contents (ADR-0050 §7.4).
        assert all(
            archive.sha256 in d or "archive" in d or "baseline" in d
            for d in result.applied_diff
            if "sha256" in d or d == "archive loaded"
        )


def _archive_ref(archive: object, device_id: uuid.UUID) -> ConfigArchiveRef:
    """Build a ConfigArchiveRef from a freshly-fetched archive (live path).

    In production the ref comes from the persisted ``config_archives`` row (the
    platform envelope removed); here the just-fetched archive already carries the
    passphrase-encrypted bytes + vault ref, so it is adapted directly.
    """
    from dataclasses import dataclass

    from pydantic import SecretBytes

    @dataclass(frozen=True)
    class _Ref:
        archive_id: uuid.UUID
        device_id: uuid.UUID
        archive_format: str
        sha256: str
        passphrase_ref: str
        content: SecretBytes

    return _Ref(
        archive_id=uuid.uuid4(),
        device_id=device_id,
        archive_format=archive.format,  # type: ignore[attr-defined]
        sha256=archive.sha256,  # type: ignore[attr-defined]
        passphrase_ref=archive.passphrase_ref,  # type: ignore[attr-defined]
        content=archive.content,  # type: ignore[attr-defined]
    )
