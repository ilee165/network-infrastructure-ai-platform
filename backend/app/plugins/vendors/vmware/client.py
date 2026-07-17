"""VMware vCenter client over pyVmomi (SOAP) — ADR-0051 §1/§2/§6/§7, ADR-0007 D7.

A thin, synchronous client wrapping :mod:`pyVmomi` against a vCenter Server.
Used only inside the ``vmware`` plugin (ADR-0006 §6: vendor-private
connectivity); engines and agents never see pyVmomi types. Synchronous by
design — collection runs inside Celery worker tasks, never on the FastAPI event
loop (ADR-0007 §3).

Security posture (ADR-0011 / ADR-0051 §1/§2 — the escalated secret surface).
Two secrets exist: the vCenter **password** and the SOAP **session cookie**
(``vmware_soap_session``).

- **Secrets in name-mangled slots, no leaking repr.** Both the password and the
  live session cookie live in name-mangled attributes; :meth:`__repr__` omits
  both. A per-instance :class:`_SessionRedactFilter` on the pyVmomi loggers
  drops any record containing either secret in literal or percent-encoded form
  (the ``_ApiKeyRedactFilter`` pattern, ADR-0051 §2).
- **The login exchange is never raw-recorded and never logged.** The password
  crosses the process boundary only inside the TLS-protected ``SmartConnect``
  login call; typed error mapping guarantees exception messages carry
  host/port + fault type only — ``vim.fault.InvalidLogin`` becomes a
  credential-free :class:`PluginError` (ADR-0051 §2).
- **TLS verification on by default.** An unverified context is only used when
  the device connection config explicitly disables verification (visible in
  config review); a CA-bundle path is honored (ADR-0051 §1).
- **No debug transports.** The client never enables pyVmomi / ``http.client``
  debug output (which would print raw headers, incl. the session cookie,
  outside the logging framework where no redaction filter can catch it).
- **Short-lived, per-collection sessions (ADR-0051 §2).** The client connects
  lazily on first use; the owning job context calls :meth:`disconnect` in a
  ``finally`` block (SOAP ``Logout``). Sessions never outlive the task and are
  never cached across tasks/workers. If vCenter expires the session mid-run
  (``vim.fault.NotAuthenticated``), the client re-authenticates **once** and
  retries; a second failure is a typed :class:`PluginError`.

Raw-first adaptation (ADR-0051 §7). pyVmomi deserializes SOAP into Python
objects before the plugin sees them, so the raw artifact is a deterministic
**property-set JSON** rendering of each ``RetrievePropertiesEx`` batch — object
type, moref, and the exact property paths + values as returned — recorded by the
capability layer before normalization. The ``fetch_*`` methods return exactly
those property-set documents (plain JSON-serializable dicts); this seam is what
conformance fixtures replay (ADR-0051 §8), so fixtures and raw artifacts share
one format. Continuation paging (``ContinueRetrievePropertiesEx``) is followed
until token exhaustion; every batch is a separate document list.
"""

from __future__ import annotations

import contextlib
import logging
import ssl
import urllib.parse
from collections.abc import Callable, Sequence
from typing import Any

from pyVmomi import VmomiSupport, vim, vmodl

from app.core.errors import PluginError

__all__ = ["PropertySetBatch", "PropertySetDoc", "VsphereClient", "vmodl_to_json"]

_log = logging.getLogger(__name__)

#: Loggers the SOAP transport / SDK emit through — the redaction filter is
#: registered on each so a stray record naming a secret is dropped before it
#: propagates to the root handler (ADR-0051 §2).
_REDACTED_LOGGERS = (__name__, "pyVmomi", "suds", "http.client")

#: A property-set document: object type + moref + collection datacenter +
#: the exact property paths→values as vCenter returned them (ADR-0051 §7).
PropertySetDoc = dict[str, Any]

#: One ``RetrievePropertiesEx``/``ContinueRetrievePropertiesEx`` batch — the unit
#: recorded raw before normalization (ADR-0051 §7).
PropertySetBatch = list[PropertySetDoc]

# Property paths requested per managed-object type (ADR-0051 §6 — named paths
# only, never a full-object pull).
_VM_PATHS: tuple[str, ...] = (
    "name",
    "config.instanceUuid",
    "config.template",
    "runtime.powerState",
    "runtime.host",
    "guest.hostName",
    "guest.ipAddress",
    "guest.net",
    "config.hardware.device",
)
_HOST_PATHS: tuple[str, ...] = (
    "name",
    "parent",
    "runtime.connectionState",
    "runtime.inMaintenanceMode",
    "hardware.systemInfo.vendor",
    "hardware.systemInfo.model",
    "config.product.fullName",
    "config.network",
)
_CLUSTER_PATHS: tuple[str, ...] = (
    "name",
    "configuration.dasConfig.enabled",
    "configuration.drsConfig.enabled",
)
_DVS_PATHS: tuple[str, ...] = ("name", "config.uplinkPortPolicy", "config.host")
_DVPG_PATHS: tuple[str, ...] = (
    "config.name",
    "config.distributedVirtualSwitch",
    "config.defaultPortConfig.vlan",
    "config.defaultPortConfig.uplinkTeamingPolicy",
)


def vmodl_to_json(value: object) -> Any:
    """Convert a pyVmomi value to a deterministic JSON-serializable Python value.

    Scalars pass through; a pyVmomi ``Enum`` becomes its ``str`` wire value; a
    ``ManagedObject`` becomes its moref id (``vm-1042``); arrays become lists;
    a ``DataObject`` becomes a ``{property: value}`` dict over its **set**
    properties (``dynamicType``/``dynamicProperty`` and unset/empty values are
    dropped for determinism). Anything else is stringified. This is the generic
    serialization behind the property-set JSON raw artifact (ADR-0051 §7); the
    deep guest-nic / device-backing / host-network shapes it produces are
    validated live against ``vcsim`` / a real vCenter (ADR-0051 §9).
    """
    if isinstance(value, VmomiSupport.Enum):
        return str(value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, VmomiSupport.ManagedObject):
        return value._moId
    if isinstance(value, (list, tuple)):
        return [vmodl_to_json(item) for item in value]
    if isinstance(value, VmomiSupport.DataObject):
        out: dict[str, Any] = {}
        for prop in value._GetPropertyList():
            if prop.name in ("dynamicType", "dynamicProperty"):
                continue
            item = getattr(value, prop.name, None)
            if item is None:
                continue
            if isinstance(item, (list, tuple)) and len(item) == 0:
                continue
            out[prop.name] = vmodl_to_json(item)
        return out
    return str(value)


class _SessionRedactFilter(logging.Filter):
    """Block any SDK log record containing the password OR the session cookie.

    Defence-in-depth backstop (ADR-0051 §2). Secrets are stored in name-mangled
    slots so ``vars(filter)`` / a debugger display does not expose them under a
    guessable attribute name (ADR-0011 §1). Both the **literal** and
    **URL-percent-encoded** forms are matched (matching only the literal would
    miss a percent-encoded cookie). The live cookie is registered lazily via
    :meth:`add_secret` once ``SmartConnect`` mints it.
    """

    def __init__(self, password: str) -> None:
        super().__init__()
        self.__needles: set[str] = set()
        self.add_secret(password)

    def add_secret(self, secret: str | None) -> None:
        """Register a secret (both literal + percent-encoded forms)."""
        if not secret:
            return
        self.__needles.add(secret)
        self.__needles.add(urllib.parse.quote(secret, safe=""))

    def filter(self, record: logging.LogRecord) -> bool:
        """Return False (block) if the record message would expose a secret."""
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 — a broken record must never crash logging
            return True
        return not any(needle in msg for needle in self.__needles)


class VsphereClient:
    """Synchronous pyVmomi client against one vCenter Server (one per collection).

    Parameters:
        host: vCenter hostname / IP.
        username: Vault-materialized service-account username.
        password: Vault-materialized password (never logged / repr'd).
        port: SOAP port (default 443).
        verify: TLS verify — ``True`` (default, system trust), a CA-bundle path
            (``str``), or ``False`` to disable (explicit per-device opt-out,
            visible in config review; ADR-0051 §1).
        connect_fn: Injectable ``() -> ServiceInstance`` (test seam). Defaults to
            :meth:`_default_connect` (pyVmomi ``SmartConnect``).
        disconnect_fn: Injectable ``(ServiceInstance) -> None`` (test seam).
            Defaults to pyVmomi ``Disconnect``.

    The password and session cookie are held in name-mangled slots so neither
    appears in ``repr()``, ``__dict__``, or a debugger display (ADR-0011 §1).
    """

    def __init__(
        self,
        *,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        verify: bool | str = True,
        connect_fn: Callable[[], Any] | None = None,
        disconnect_fn: Callable[[Any], None] | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._verify = verify
        # Name-mangled secret slots (ADR-0011 §1) — never rendered by repr().
        self.__username = username
        self.__password = password
        self.__cookie: str | None = None
        # Any (not Any | None): the live ServiceInstance is a dynamic pyVmomi
        # object; ``None`` before connect is checked at runtime in _ensure_connected.
        self._si: Any = None
        self._connect_fn = connect_fn or self._default_connect
        self._disconnect_fn = disconnect_fn or _default_disconnect
        # Register the redaction backstop on the SDK loggers for BOTH secrets.
        self.__log_filter = _SessionRedactFilter(password)
        for name in _REDACTED_LOGGERS:
            logging.getLogger(name).addFilter(self.__log_filter)

    def __repr__(self) -> str:
        # Deliberately omit username/password/cookie — all bearer material.
        return f"{type(self).__name__}(host={self._host!r}, port={self._port!r})"

    # ------------------------------------------------------------------
    # Session lifecycle (ADR-0051 §2)
    # ------------------------------------------------------------------

    def _default_connect(self) -> Any:
        """Open a vCenter session via pyVmomi ``SmartConnect`` (TLS verify on by default)."""
        from pyVim.connect import SmartConnect

        if self._verify is False:
            context = ssl._create_unverified_context()  # explicit per-device opt-out (§1)
        else:
            context = ssl.create_default_context()
            if isinstance(self._verify, str):
                context.load_verify_locations(self._verify)
        try:
            return SmartConnect(
                host=self._host,
                user=self.__username,
                pwd=self.__password,
                port=self._port,
                sslContext=context,
            )
        except vim.fault.InvalidLogin:
            # Strip credentials from the error — host/port + fault type only (§2).
            raise PluginError(
                f"vmware: login to {self._host}:{self._port} failed (invalid credentials)"
            ) from None
        except vim.fault.VimFault as exc:
            raise PluginError(
                f"vmware: login to {self._host}:{self._port} failed ({type(exc).__name__})"
            ) from None
        except (OSError, ConnectionError):
            raise PluginError(
                f"vmware: could not connect to {self._host}:{self._port} (transport error)"
            ) from None

    def _ensure_connected(self) -> Any:
        if self._si is None:
            self._si = self._connect_fn()
            self.__register_cookie()
        return self._si

    def __register_cookie(self) -> None:
        """Extract the live SOAP session cookie and register it for redaction (§2)."""
        cookie = _session_cookie(self._si)
        self.__cookie = cookie
        self.__log_filter.add_secret(cookie)

    def _reconnect(self) -> Any:
        """Re-authenticate once after a mid-run ``NotAuthenticated`` (ADR-0051 §2)."""
        old = self._si
        self._si = None
        self.__cookie = None
        if old is not None:
            with contextlib.suppress(Exception):  # best-effort teardown of the dead session
                self._disconnect_fn(old)
        return self._ensure_connected()

    def disconnect(self) -> None:
        """Terminate the vCenter session server-side (SOAP ``Logout``); idempotent.

        Called by the owning job context in a ``finally`` block (ADR-0051 §2).
        Failure is non-fatal and never names the cookie in a log line.
        """
        si = self._si
        self._si = None
        self.__cookie = None
        if si is not None:
            try:
                self._disconnect_fn(si)
            except Exception:  # noqa: BLE001 — logout is best-effort; the session idle-expires
                _log.warning("vmware: session logout failed (non-fatal)")
        for name in _REDACTED_LOGGERS:
            logging.getLogger(name).removeFilter(self.__log_filter)

    def __enter__(self) -> VsphereClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.disconnect()

    # ------------------------------------------------------------------
    # PropertyCollector retrieval + continuation paging (ADR-0051 §6)
    # ------------------------------------------------------------------

    def _with_reauth(self, build: Callable[[], list[PropertySetBatch]]) -> list[PropertySetBatch]:
        """Run *build* with typed SDK/transport errors and one re-auth retry (§2)."""
        self._ensure_connected()
        for attempt in range(2):
            try:
                return build()
            except vim.fault.NotAuthenticated:
                if attempt == 1:
                    raise PluginError(
                        f"vmware: session re-authentication to {self._host}:{self._port} failed "
                        "after one retry"
                    ) from None
                self._reconnect()
            except vmodl.MethodFault as exc:
                raise PluginError(
                    f"vmware: collection from {self._host}:{self._port} failed "
                    f"({type(exc).__name__})"
                ) from None
            except (OSError, ConnectionError):
                raise PluginError(
                    f"vmware: collection from {self._host}:{self._port} failed (transport error)"
                ) from None
        raise AssertionError("unreachable")  # pragma: no cover

    def _datacenters(self) -> list[Any]:
        content = self._si.content
        view = content.viewManager.CreateContainerView(
            container=content.rootFolder, type=[vim.Datacenter], recursive=True
        )
        try:
            return list(view.view)
        finally:
            view.Destroy()

    def _retrieve(
        self, root: Any, obj_type: type, path_set: Sequence[str], datacenter: str | None
    ) -> list[PropertySetBatch]:
        """Retrieve *path_set* for every *obj_type* under *root*, following continuation tokens.

        One ``RetrievePropertiesEx`` call plus a ``ContinueRetrievePropertiesEx``
        loop until the token is exhausted (ADR-0051 §6). Each batch is one entry
        in the returned list of documents-lists so the caller records every batch
        raw before normalization (ADR-0051 §7).
        """
        content = self._si.content
        view = content.viewManager.CreateContainerView(
            container=root, type=[obj_type], recursive=True
        )
        pc = content.propertyCollector
        batches: list[PropertySetBatch] = []
        try:
            traversal = vmodl.query.PropertyCollector.TraversalSpec(
                name="traverseView", type=vim.view.ContainerView, path="view", skip=False
            )
            obj_spec = vmodl.query.PropertyCollector.ObjectSpec(
                obj=view, skip=True, selectSet=[traversal]
            )
            prop_spec = vmodl.query.PropertyCollector.PropertySpec(
                type=obj_type, all=False, pathSet=list(path_set)
            )
            filter_spec = vmodl.query.PropertyCollector.FilterSpec(
                objectSet=[obj_spec], propSet=[prop_spec]
            )
            options = vmodl.query.PropertyCollector.RetrieveOptions()
            result = pc.RetrievePropertiesEx([filter_spec], options)
            while result is not None:
                batches.append(
                    [_object_content_to_doc(oc, datacenter) for oc in (result.objects or [])]
                )
                token = result.token
                if not token:
                    break
                result = pc.ContinueRetrievePropertiesEx(token)
        finally:
            view.Destroy()
        return batches

    def _retrieve_by_datacenter(
        self, obj_type: type, path_set: Sequence[str], folder_attr: str
    ) -> list[PropertySetBatch]:
        """Collect *obj_type* rooted at each datacenter's *folder_attr* (DC-scoped, §5.5)."""

        def build() -> list[PropertySetBatch]:
            batches: list[PropertySetBatch] = []
            for dc in self._datacenters():
                root = getattr(dc, folder_attr)
                batches.extend(self._retrieve(root, obj_type, path_set, datacenter=dc.name))
            return batches

        return self._with_reauth(build)

    # ------------------------------------------------------------------
    # fetch_* seam — property-set documents (ADR-0051 §1/§7); the fixture-replay
    # boundary. Each returns a list of BATCHES (one per RetrievePropertiesEx call).
    # ------------------------------------------------------------------

    def fetch_about(self) -> PropertySetDoc:
        """Return the vCenter ``ServiceInstance.content.about`` as one property-set doc (§4)."""

        def build() -> list[PropertySetBatch]:
            about = self._si.content.about
            doc: PropertySetDoc = {
                "type": "AboutInfo",
                "moref": None,
                "datacenter": None,
                "properties": vmodl_to_json(about),
            }
            return [[doc]]

        return self._with_reauth(build)[0][0]

    def fetch_virtual_machines(self) -> list[PropertySetBatch]:
        """Return VM property-set batches (ADR-0051 §6)."""
        return self._retrieve_by_datacenter(vim.VirtualMachine, _VM_PATHS, "vmFolder")

    def fetch_hypervisor_hosts(self) -> list[PropertySetBatch]:
        """Return host property-set batches (ADR-0051 §6)."""
        return self._retrieve_by_datacenter(vim.HostSystem, _HOST_PATHS, "hostFolder")

    def fetch_compute_clusters(self) -> list[PropertySetBatch]:
        """Return cluster property-set batches (ADR-0051 §6)."""
        return self._retrieve_by_datacenter(
            vim.ClusterComputeResource, _CLUSTER_PATHS, "hostFolder"
        )

    def fetch_distributed_switches(self) -> list[PropertySetBatch]:
        """Return distributed-vSwitch property-set batches (ADR-0051 §6)."""
        return self._retrieve_by_datacenter(
            vim.DistributedVirtualSwitch, _DVS_PATHS, "networkFolder"
        )

    def fetch_distributed_portgroups(self) -> list[PropertySetBatch]:
        """Return distributed-portgroup property-set batches (ADR-0051 §6)."""
        return self._retrieve_by_datacenter(
            vim.dvs.DistributedVirtualPortgroup, _DVPG_PATHS, "networkFolder"
        )


def _object_content_to_doc(oc: Any, datacenter: str | None) -> PropertySetDoc:
    """Render one ``ObjectContent`` as a property-set document (ADR-0051 §7)."""
    properties: dict[str, Any] = {}
    for prop in oc.propSet or []:
        properties[prop.name] = vmodl_to_json(prop.val)
    return {
        # pyVmomi class __name__ is dotted (``vim.VirtualMachine``); keep the
        # short managed-object type name (``VirtualMachine``).
        "type": type(oc.obj).__name__.rsplit(".", 1)[-1],
        "moref": oc.obj._moId,
        "datacenter": datacenter,
        "properties": properties,
    }


def _session_cookie(si: Any) -> str | None:
    """Best-effort extraction of the live SOAP session cookie for redaction (§2)."""
    stub = getattr(si, "_stub", None)
    cookie = getattr(stub, "cookie", None)
    return cookie if isinstance(cookie, str) and cookie else None


def _default_disconnect(si: Any) -> None:
    from pyVim.connect import Disconnect

    Disconnect(si)
