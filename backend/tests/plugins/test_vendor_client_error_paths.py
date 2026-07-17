"""Shared error-path contract for HTTP and SOAP vendor clients (Wave 7 F7).

The four HTTP clients share one :class:`httpx.MockTransport` fixture. VMware
implements the same scenario contract through its accepted pyVmomi/SOAP seam;
ADR-0051 explicitly rejects a raw vSphere REST client.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest
from pyVmomi import vim, vmodl

from app.core.errors import PluginError
from app.plugins.vendors.bluecat.client import BamClient, BamCredentials
from app.plugins.vendors.f5_bigip.client import F5Client
from app.plugins.vendors.f5_bigip.plugin import F5DiscoveryApi
from app.plugins.vendors.fortios.client import FortiosRestClient
from app.plugins.vendors.fortios.plugin import FortiosDiscoveryApi
from app.plugins.vendors.panos.client import PanosClient
from app.plugins.vendors.panos.plugin import PanosDiscoveryApi
from app.plugins.vendors.vmware.client import VsphereClient
from app.schemas.discovery import DeviceFacts

_BLUECAT_TOKEN = "FAKE-bluecat-token-error-paths"  # noqa: S105
_FORTIOS_TOKEN = "FAKE-fortios-token-error-paths"  # noqa: S105
_PANOS_KEY = "FAKE-panos-key-error-paths"  # noqa: S105
_F5_TOKEN = "FAKE-f5-token-error-paths"  # noqa: S105
_F5_PASSWORD = "FAKE-f5-password-error-paths"  # noqa: S105
_VMWARE_PASSWORD = "FAKE-vmware-password-error-paths"  # noqa: S105


class Scenario(StrEnum):
    """The observable paths every vendor client must exercise."""

    PARSING = "parsing"
    MALFORMED = "malformed"
    AUTH = "auth"
    SERVER_ERROR = "server-error"
    TIMEOUT = "timeout"


class _UnusedSshTransport:
    """FortiOS discovery is REST-only; fail if its named SSH fallback is used."""

    def send_command(self, command: str) -> str:
        raise AssertionError(f"unexpected FortiOS SSH command: {command}")


@dataclass(frozen=True)
class RestVendorSpec:
    vendor: str
    make_client: Callable[[httpx.Client, Scenario], Any]
    invoke: Callable[[Any], object]
    handle: Callable[[Scenario, httpx.Request], httpx.Response]
    assert_parsed: Callable[[object], None]
    error_matches: dict[Scenario, str]


@dataclass(frozen=True)
class RestVendorRun:
    spec: RestVendorSpec
    scenario: Scenario
    client: Any


def _authorized(request: httpx.Request, *, header: str, value: str, secret: str) -> bool:
    """Require header authentication and prove the credential stayed out of the URL."""
    return request.headers.get(header) == value and secret not in str(request.url)


def _make_bluecat(http: httpx.Client, scenario: Scenario) -> BamClient:
    token = None if scenario in {Scenario.MALFORMED, Scenario.AUTH} else _BLUECAT_TOKEN
    return BamClient(
        base_url="https://bam.example.test",
        credentials=BamCredentials(username="api-user", password="FAKE-bluecat-password"),
        client=http,
        session_token=token,
    )


def _handle_bluecat(scenario: Scenario, request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/sessions"):
        if scenario is Scenario.AUTH:
            return httpx.Response(401, json={"error": "bad credentials"})
        if scenario is Scenario.MALFORMED:
            return httpx.Response(200, text="not-json")
        return httpx.Response(200, json={"token": _BLUECAT_TOKEN})

    if not _authorized(
        request,
        header="BAMAuthToken",
        value=_BLUECAT_TOKEN,
        secret=_BLUECAT_TOKEN,
    ):
        return httpx.Response(401, json={"error": "unauthorized"})
    if scenario is Scenario.SERVER_ERROR:
        return httpx.Response(503, json={"error": "unavailable"})
    if scenario is Scenario.TIMEOUT:
        raise httpx.ReadTimeout("BAM read timed out", request=request)
    return httpx.Response(
        200,
        json={"count": 1, "data": [{"id": 1, "name": "Default"}]},
    )


def _invoke_bluecat(client: Any) -> object:
    return cast(BamClient, client).get_configurations()


def _assert_bluecat_parsed(result: object) -> None:
    assert result == [{"id": 1, "name": "Default"}]


def _make_fortios(http: httpx.Client, scenario: Scenario) -> FortiosRestClient:
    del scenario
    return FortiosRestClient(
        host="fortigate.example.test",
        api_token=_FORTIOS_TOKEN,
        client=http,
    )


def _handle_fortios(scenario: Scenario, request: httpx.Request) -> httpx.Response:
    if not _authorized(
        request,
        header="Authorization",
        value=f"Bearer {_FORTIOS_TOKEN}",
        secret=_FORTIOS_TOKEN,
    ):
        return httpx.Response(401, json={"error": "unauthorized"})
    if scenario is Scenario.AUTH:
        return httpx.Response(401, json={"error": "bad token"})
    if scenario is Scenario.SERVER_ERROR:
        return httpx.Response(503, json={"error": "unavailable"})
    if scenario is Scenario.TIMEOUT:
        raise httpx.ReadTimeout("FortiOS read timed out", request=request)
    if scenario is Scenario.MALFORMED:
        return httpx.Response(200, text="not-json")
    return httpx.Response(
        200,
        json={
            "status": "success",
            "results": {
                "hostname": "fortigate-lab",
                "model_name": "FortiGate-VM64",
                "version": "v7.4.2",
                "serial": "FGVM000000000001",
            },
        },
    )


def _invoke_fortios(client: Any) -> object:
    capability = FortiosDiscoveryApi(
        cast(FortiosRestClient, client), _UnusedSshTransport(), uuid4()
    )
    return capability.get_device_facts()


def _assert_fortios_parsed(result: object) -> None:
    assert isinstance(result, DeviceFacts)
    assert result.hostname == "fortigate-lab"
    assert result.model == "FortiGate-VM64"


def _make_panos(http: httpx.Client, scenario: Scenario) -> PanosClient:
    del scenario
    return PanosClient(host="panos.example.test", api_key=_PANOS_KEY, client=http)


def _handle_panos(scenario: Scenario, request: httpx.Request) -> httpx.Response:
    if not _authorized(
        request,
        header="X-PAN-KEY",
        value=_PANOS_KEY,
        secret=_PANOS_KEY,
    ):
        return httpx.Response(401, text='<response status="error"/>')
    if scenario is Scenario.AUTH:
        return httpx.Response(
            200,
            text='<response status="error"><msg>Authentication failed</msg></response>',
        )
    if scenario is Scenario.SERVER_ERROR:
        return httpx.Response(503, text="unavailable")
    if scenario is Scenario.TIMEOUT:
        raise httpx.ReadTimeout("PAN-OS read timed out", request=request)
    if scenario is Scenario.MALFORMED:
        return httpx.Response(200, text="<response")
    return httpx.Response(
        200,
        text=(
            '<response status="success"><result><system>'
            "<hostname>panos-lab</hostname><model>PA-VM</model>"
            "<sw-version>11.1.2</sw-version><serial>PA0000000001</serial>"
            "</system></result></response>"
        ),
    )


def _invoke_panos(client: Any) -> object:
    return PanosDiscoveryApi(cast(PanosClient, client), uuid4()).get_device_facts()


def _assert_panos_parsed(result: object) -> None:
    assert isinstance(result, DeviceFacts)
    assert result.hostname == "panos-lab"
    assert result.os_version == "11.1.2"


def _make_f5(http: httpx.Client, scenario: Scenario) -> F5Client:
    token = None if scenario is Scenario.AUTH else _F5_TOKEN
    return F5Client(
        host="bigip.example.test",
        username="netops-service",
        password=_F5_PASSWORD,
        client=http,
        session_token=token,
    )


def _handle_f5(scenario: Scenario, request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path.startswith("/mgmt/shared/authz/tokens/"):
        return httpx.Response(200, json={"status": "revoked"})
    if path == "/mgmt/shared/authn/login":
        if scenario is Scenario.AUTH:
            return httpx.Response(401, json={"error": "bad credentials"})
        return httpx.Response(200, json={"token": {"token": _F5_TOKEN}})

    if not _authorized(
        request,
        header="X-F5-Auth-Token",
        value=_F5_TOKEN,
        secret=_F5_TOKEN,
    ):
        return httpx.Response(401, json={"error": "unauthorized"})
    if scenario is Scenario.SERVER_ERROR:
        return httpx.Response(503, json={"error": "unavailable"})
    if scenario is Scenario.TIMEOUT:
        raise httpx.ReadTimeout("BIG-IP read timed out", request=request)
    if scenario is Scenario.MALFORMED:
        return httpx.Response(200, text="not-json")
    if path == "/mgmt/tm/sys/version":
        return httpx.Response(
            200,
            json={
                "entries": {
                    "https://localhost/mgmt/tm/sys/version/0": {
                        "nestedStats": {
                            "entries": {
                                "Version": {"description": "17.1.1"},
                                "Product": {"description": "BIG-IP"},
                            }
                        }
                    }
                }
            },
        )
    if path == "/mgmt/tm/sys/global-settings":
        return httpx.Response(200, json={"hostname": "bigip-lab"})
    return httpx.Response(404, json={"error": "unexpected path"})


def _invoke_f5(client: Any) -> object:
    return F5DiscoveryApi(cast(F5Client, client), uuid4()).get_device_facts()


def _assert_f5_parsed(result: object) -> None:
    assert isinstance(result, DeviceFacts)
    assert result.hostname == "bigip-lab"
    assert result.os_version == "17.1.1"


_REST_SPECS = (
    RestVendorSpec(
        vendor="bluecat",
        make_client=_make_bluecat,
        invoke=_invoke_bluecat,
        handle=_handle_bluecat,
        assert_parsed=_assert_bluecat_parsed,
        error_matches={
            Scenario.MALFORMED: "login response was not JSON",
            Scenario.AUTH: "session login failed with status 401",
            Scenario.SERVER_ERROR: "status 503",
            Scenario.TIMEOUT: "transport error",
        },
    ),
    RestVendorSpec(
        vendor="fortios",
        make_client=_make_fortios,
        invoke=_invoke_fortios,
        handle=_handle_fortios,
        assert_parsed=_assert_fortios_parsed,
        error_matches={
            Scenario.MALFORMED: "non-JSON body",
            Scenario.AUTH: "HTTP 401",
            Scenario.SERVER_ERROR: "HTTP 503",
            Scenario.TIMEOUT: "transport error",
        },
    ),
    RestVendorSpec(
        vendor="panos",
        make_client=_make_panos,
        invoke=_invoke_panos,
        handle=_handle_panos,
        assert_parsed=_assert_panos_parsed,
        error_matches={
            Scenario.MALFORMED: "non-XML body",
            Scenario.AUTH: "returned status='error'",
            Scenario.SERVER_ERROR: "HTTP status 503",
            Scenario.TIMEOUT: "transport error",
        },
    ),
    RestVendorSpec(
        vendor="f5_bigip",
        make_client=_make_f5,
        invoke=_invoke_f5,
        handle=_handle_f5,
        assert_parsed=_assert_f5_parsed,
        error_matches={
            Scenario.MALFORMED: "non-JSON body",
            Scenario.AUTH: "login failed with HTTP 401",
            Scenario.SERVER_ERROR: "HTTP 503",
            Scenario.TIMEOUT: "transport error",
        },
    ),
)


@pytest.fixture(params=_REST_SPECS, ids=lambda spec: spec.vendor)
def rest_vendor_spec(request: pytest.FixtureRequest) -> RestVendorSpec:
    return cast(RestVendorSpec, request.param)


@pytest.fixture(params=tuple(Scenario), ids=lambda scenario: scenario.value)
def vendor_scenario(request: pytest.FixtureRequest) -> Scenario:
    return cast(Scenario, request.param)


@pytest.fixture
def rest_vendor_run(
    rest_vendor_spec: RestVendorSpec,
    vendor_scenario: Scenario,
) -> Iterator[RestVendorRun]:
    """The single MockTransport fixture shared by all four HTTP vendor clients."""
    transport = httpx.MockTransport(
        lambda request: rest_vendor_spec.handle(vendor_scenario, request)
    )
    http = httpx.Client(transport=transport)
    client = rest_vendor_spec.make_client(http, vendor_scenario)
    try:
        yield RestVendorRun(rest_vendor_spec, vendor_scenario, client)
    finally:
        client.close()


def test_rest_vendor_scenario_matrix(rest_vendor_run: RestVendorRun) -> None:
    """All HTTP vendors expose parsed success and typed, sanitized failures."""
    if rest_vendor_run.scenario is Scenario.PARSING:
        result = rest_vendor_run.spec.invoke(rest_vendor_run.client)
        rest_vendor_run.spec.assert_parsed(result)
        return

    expected = rest_vendor_run.spec.error_matches[rest_vendor_run.scenario]
    with pytest.raises(PluginError, match=expected):
        rest_vendor_run.spec.invoke(rest_vendor_run.client)


class _VmwareStub:
    cookie = 'vmware_soap_session="FAKE-F7-COOKIE"; Path=/; secure'


class _VmwareContent:
    def __init__(self, about: object) -> None:
        self._about = about

    @property
    def about(self) -> object:
        if isinstance(self._about, BaseException):
            raise self._about
        return self._about


class _VmwareServiceInstance:
    def __init__(self, about: object) -> None:
        self.content = _VmwareContent(about)
        self._stub = _VmwareStub()


class _MalformedAbout:
    def __str__(self) -> str:
        return "malformed-about"


@dataclass(frozen=True)
class VmwareRun:
    scenario: Scenario
    client: VsphereClient


@pytest.fixture
def vmware_run(
    vendor_scenario: Scenario,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[VmwareRun]:
    """Drive the shared scenarios through VMware's pyVmomi/SOAP seam."""
    if vendor_scenario is Scenario.AUTH:
        import pyVim.connect as connect_mod

        def invalid_login(**_kwargs: object) -> object:
            raise vim.fault.InvalidLogin()

        monkeypatch.setattr(connect_mod, "SmartConnect", invalid_login)
        client = VsphereClient(
            host="vcenter.example.test",
            username="netops-service",
            password=_VMWARE_PASSWORD,
            disconnect_fn=lambda _si: None,
        )
    else:
        about: object
        if vendor_scenario is Scenario.PARSING:
            about = vim.AboutInfo(
                name="vcenter-lab",
                fullName="VMware vCenter Server 8.0.2",
                version="8.0.2",
                instanceUuid="vc-instance-f7",
                apiType="VirtualCenter",
            )
        elif vendor_scenario is Scenario.MALFORMED:
            about = _MalformedAbout()
        elif vendor_scenario is Scenario.SERVER_ERROR:
            about = vmodl.fault.SystemError(reason="vCenter service unavailable")
        else:
            about = TimeoutError("SOAP read timed out")
        service_instance = _VmwareServiceInstance(about)
        client = VsphereClient(
            host="vcenter.example.test",
            username="netops-service",
            password=_VMWARE_PASSWORD,
            connect_fn=lambda: service_instance,
            disconnect_fn=lambda _si: None,
        )
    try:
        yield VmwareRun(vendor_scenario, client)
    finally:
        client.disconnect()


def test_vmware_uses_same_scenario_contract_over_soap(vmware_run: VmwareRun) -> None:
    """VMware covers equivalent paths without violating ADR-0051's SOAP choice."""
    if vmware_run.scenario is Scenario.PARSING:
        result = vmware_run.client.fetch_about()
        assert result["properties"]["version"] == "8.0.2"
        return
    if vmware_run.scenario is Scenario.MALFORMED:
        result = vmware_run.client.fetch_about()
        assert result["properties"] == "malformed-about"
        return

    expected = {
        Scenario.AUTH: "invalid credentials",
        Scenario.SERVER_ERROR: "SystemError",
        Scenario.TIMEOUT: "transport error",
    }[vmware_run.scenario]
    with pytest.raises(PluginError, match=expected):
        vmware_run.client.fetch_about()
