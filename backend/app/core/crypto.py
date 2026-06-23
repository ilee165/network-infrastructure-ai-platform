"""Credential-vault envelope encryption (ADR-0011 §1, ADR-0032 §1/§4/§6).

Every secret gets its own random 256-bit **DEK**; the payload is encrypted
with AES-256-GCM (96-bit random nonce, caller-supplied AAD binding the
ciphertext to its database row). The DEK is **wrapped** by the platform **KEK**
(master key) behind the :class:`KeyProvider` *wrap/unwrap* contract (ADR-0032
§1): the provider exposes only :meth:`~KeyProvider.wrap_dek` /
:meth:`~KeyProvider.unwrap_dek` — never a KEK byte-export — so a real KMS
(AWS / Azure / Vault) can implement it without ever releasing key material into
the process. ``kek_version`` makes rotation cheap — :func:`rewrap` re-wraps the
DEK only and never touches the payload ciphertext.

The credential row-id AAD is bound at **both** envelope layers: DEK->secret
(payload) and KEK->DEK (wrap). Binding it at the wrap layer too means a wrapped
DEK lifted from one row cannot be replayed onto another even with KEK access
(ADR-0032 §1, cross-row replay guard). Local providers bind it in-process; a
provider that can neither pass nor inner-wrap ``aad`` MUST reject a non-empty
``aad`` at construction.

Fail closed (ADR-0032 §4): when the provider is unreachable, wrap/unwrap raise
the typed :class:`KeyProviderUnavailable` (503-class) — never plaintext, never a
cached KEK. The plaintext DEK lives only for the single AESGCM op and is
zeroized after use; it is never cached, serialized, queued, or audited.

Secure by default (ADR-0032 §6): no function, ``__repr__``, or exception in this
module ever places key material (KEK, DEK, wrapped blob) or plaintext in a log
line, repr, or message. :class:`WrappedDek` redacts its bytes; raw backend SDK
errors are wrapped as a typed :class:`KeyProviderError` so they never surface
verbatim.
"""

from __future__ import annotations

import base64
import contextlib
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import Settings
from app.core.errors import NetOpsError

#: AES-256 key size (bytes) for both the KEK and every per-secret DEK.
KEY_BYTES = 32

#: GCM standard 96-bit nonce size (bytes).
NONCE_BYTES = 12

#: Local-provider wrap-format discriminator (ADR-0032 §1). A single leading
#: version byte on ``WrappedDek.ciphertext`` for the in-process providers makes
#: the wrap format detectable so a future change fails loudly instead of
#: silently mis-decrypting. ``v1`` is the row-id-AAD-bound GCM wrap shipped in
#: P1 W6-T1 (``nonce ‖ AESGCM(kek).encrypt(nonce, dek, aad=row_id)``).
#:
#: ``v0`` is the *legacy, pre-W6-T1* shape that wrapped the DEK with ``aad=None``
#: and carried **no** version byte (``nonce ‖ AESGCM(kek).encrypt(nonce, dek,
#: None)``). It is recognised on unwrap only — never produced — so any
#: ``device_credentials`` row written before W6-T1 stays readable across the
#: upgrade (one-time, transparent backfill: a subsequent ``rewrap``/rotate
#: re-stores it in ``v1``). KMS backends (W6-T2) carry their own version in the
#: opaque ``kek_version`` and do not use this local discriminator.
WRAP_FORMAT_V1 = b"\x01"


class KekConfigurationError(NetOpsError):
    """The credential-vault KEK is missing or malformed (deployment problem)."""

    status_code = 500
    title = "Credential Vault Misconfigured"
    slug = "kek-misconfigured"


class UnknownKekVersionError(NetOpsError):
    """A stored secret references a KEK version this provider cannot supply."""

    status_code = 500
    title = "Unknown KEK Version"
    slug = "unknown-kek-version"


class DecryptionError(NetOpsError):
    """Authenticated decryption failed (wrong key, wrong AAD, or tampered data)."""

    status_code = 500
    title = "Credential Decryption Failed"
    slug = "decryption-failed"


class KeyProviderError(NetOpsError):
    """A key-provider operation failed.

    Raw backend SDK exceptions (boto3 / azure / hvac) are wrapped in this typed
    error — and only a coarse ``reason_class`` is ever exposed — so a provider's
    request/response context can never surface verbatim in a log, trace, or API
    response (ADR-0032 §6). The originating exception is chained for local
    debugging but is *not* part of any rendered message.
    """

    status_code = 500
    title = "Key Provider Error"
    slug = "key-provider-error"

    def __init__(self, reason_class: str) -> None:
        #: Coarse, non-sensitive machine label for the failure (e.g. the
        #: backend exception's class name) — safe to log/audit.
        self.reason_class = reason_class
        super().__init__(f"key-provider operation failed ({reason_class})")


class KeyProviderUnavailable(KeyProviderError):
    """The key provider is unreachable; the vault fails closed (ADR-0032 §4).

    A 503-class error: on writes no row is stored unwrapped; on reads the
    dependent Celery task fails and retries (``acks_late``) and a ChangeRequest
    that cannot unwrap its credential goes to ``failed``, never ``completed``.
    """

    status_code = 503
    title = "Key Provider Unavailable"
    slug = "key-provider-unavailable"


class LocalKeyProviderInProductionError(RuntimeError):
    """A non-production local KEK provider was selected in production (ADR-0032 §2).

    The credential service refuses to start (secure-by-default opt-out): an
    in-process Env/File KEK is a local fallback only, never a production backend,
    so it can never hide behind a green prod deploy. Configure a KMS backend
    (``VAULT_KEY_PROVIDER=aws|azure|vault``). A :class:`RuntimeError` (not a
    :class:`NetOpsError`) because this is a deployment misconfiguration that must
    crash startup loudly, not surface as an HTTP problem.
    """


@dataclass(frozen=True, slots=True)
class WrappedDek:
    """A DEK wrapped under the active KEK (ADR-0032 §1).

    Maps 1:1 onto the existing ``device_credentials`` columns:
    ``ciphertext`` -> ``wrapped_dek`` (with the wrap nonce prepended for local
    providers) and ``kek_version`` -> ``kek_version``. The ciphertext is
    redacted from ``repr`` so an accidental log shows only the KEK version.
    """

    ciphertext: bytes = field(repr=False)
    kek_version: str

    def __repr__(self) -> str:
        return f"<wrapped:{self.kek_version}>"


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    """Liveness of a :class:`KeyProvider` for the fail-closed readiness gate.

    ``detail`` carries a coarse machine reason only (never key material); the
    readiness-probe / ``/metrics`` wiring lands with the KMS backends in W6-T2.
    """

    available: bool
    kek_version: str
    detail: str | None = None


@runtime_checkable
class KeyProvider(Protocol):
    """KMS-compatible wrap/unwrap source for the platform KEK (ADR-0032 §1).

    The KEK is used *only* through :meth:`wrap_dek` / :meth:`unwrap_dek` — there
    is deliberately **no** ``get_kek()`` / ``export()`` byte method, so a network
    KMS can implement the same contract without ever releasing key material
    (ADR-0032 §1/§6). MVP ships the in-process :class:`EnvKeyProvider` /
    :class:`FileKeyProvider`; AWS / Azure / Vault backends land in W6-T2.
    """

    @property
    def kek_version(self) -> str:
        """Stable id of the *active* wrapping key, stored on each row."""
        ...

    @property
    def is_production_grade(self) -> bool:
        """Whether this provider is a production-grade KEK backend (ADR-0032 §2).

        ``False`` for the in-process :class:`EnvKeyProvider` / :class:`FileKeyProvider`
        local fallbacks (the KEK is held as bytes in env/file); a real KMS backend
        (W6-T2) reports ``True``. Surfaced on the ``kek.provider.select`` audit row,
        the startup banner, and ``/metrics`` so a non-prod KEK cannot hide behind a
        green deploy.
        """
        ...

    def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDek:
        """Wrap *dek* under the active KEK, binding *aad* (the credential row id).

        Raises:
            KeyProviderUnavailable: If the provider is unreachable (fail closed).
            KeyProviderError: If wrapping fails for any other backend reason.
        """
        ...

    def unwrap_dek(self, wrapped: WrappedDek, *, aad: bytes) -> bytes:
        """Unwrap *wrapped* under its recorded KEK version, verifying *aad*.

        Returns the transient plaintext DEK; the caller zeroizes it after the
        single AESGCM op (ADR-0032 §6 — no DEK cache).

        Raises:
            UnknownKekVersionError: If the provider cannot supply the version.
            DecryptionError: If authentication fails (wrong KEK, wrong AAD, or
                tampered data — the cross-row replay guard).
            KeyProviderUnavailable: If the provider is unreachable (fail closed).
        """
        ...

    def health(self) -> ProviderHealth:
        """Report provider liveness for the fail-closed readiness gate (§4)."""
        ...


def _decode_kek(encoded: str, *, source: str) -> bytes:
    """Decode and validate a urlsafe-base64 KEK; *source* names where it came from.

    Error messages identify the source, never the key material itself.
    """
    try:
        # base64.b64decode with altchars instead of urlsafe_b64decode: only the
        # former supports validate=True (reject garbage instead of skipping it).
        raw = base64.b64decode(encoded.encode("ascii"), altchars=b"-_", validate=True)
    except ValueError as exc:  # binascii.Error and UnicodeEncodeError subclass ValueError
        raise KekConfigurationError(f"KEK from {source} is not valid urlsafe base64") from exc
    if len(raw) != KEY_BYTES:
        raise KekConfigurationError(
            f"KEK from {source} must decode to exactly {KEY_BYTES} bytes (AES-256)"
        )
    return raw


def _zeroize(buf: bytearray) -> None:
    """Best-effort wipe of a mutable plaintext-DEK buffer after the AESGCM op."""
    for i in range(len(buf)):
        buf[i] = 0


class _StaticKeyProvider:
    """In-process wrap/unwrap base for single-version local providers (ADR-0032 §2).

    Holds one KEK in memory (local fallback, non-production) and binds the
    row-id ``aad`` *natively* via the AESGCM wrap layer — so the same
    cross-row-replay guard a KMS gives applies here too.
    """

    def __init__(self, kek: bytes, version: str) -> None:
        self._kek = kek
        self._version = version

    @property
    def kek_version(self) -> str:
        """Return the configured KEK version (``NETOPS_KEK_VERSION``, default ``v1``)."""
        return self._version

    @property
    def is_production_grade(self) -> bool:
        """Local in-process KEK is a non-production fallback (ADR-0032 §2)."""
        return False

    def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDek:
        """AESGCM-wrap *dek* under the in-process KEK, binding *aad*.

        The blob is ``WRAP_FORMAT_V1 ‖ nonce ‖ GCM(dek, aad)``: a one-byte
        wrap-format discriminator (so the format is detectable, ADR-0032 §1),
        then the 96-bit nonce, then the AAD-bound GCM output — self-contained in
        the single ``WrappedDek.ciphertext`` column.
        """
        nonce = os.urandom(NONCE_BYTES)
        sealed = AESGCM(self._kek).encrypt(nonce, dek, aad)
        return WrappedDek(ciphertext=WRAP_FORMAT_V1 + nonce + sealed, kek_version=self._version)

    def unwrap_dek(self, wrapped: WrappedDek, *, aad: bytes) -> bytes:
        """Unwrap *wrapped* if its version matches and *aad* authenticates.

        Reads the leading wrap-format byte: a ``WRAP_FORMAT_V1`` blob is the
        AAD-bound GCM wrap (W6-T1). A blob with **no** recognised version byte is
        treated as the legacy pre-W6-T1 ``v0`` shape and unwrapped with
        ``aad=None`` so credentials written before the AAD-at-wrap-layer change
        stay readable across the upgrade (one-time transparent compatibility; a
        later ``rewrap`` re-stores them in ``v1``).

        Raises:
            UnknownKekVersionError: For any other version — restore the matching
                KEK material to read secrets wrapped under it.
            DecryptionError: If GCM authentication fails (wrong KEK, wrong AAD,
                or tampered wrapped blob).
        """
        if wrapped.kek_version != self._version:
            raise UnknownKekVersionError(
                f"KEK version {wrapped.kek_version!r} is not available "
                f"(provider holds {self._version!r})"
            )
        blob = wrapped.ciphertext
        # A v1 blob is exactly ``WRAP_FORMAT_V1 ‖ nonce ‖ GCM(dek, aad)`` with the
        # DEK always KEY_BYTES and a 128-bit GCM tag, so its length is fixed. A
        # legacy v0 blob (``nonce ‖ GCM(dek, None)``, no version byte) is one byte
        # shorter and length-disjoint, but ~1/256 of them start with a random
        # nonce byte equal to WRAP_FORMAT_V1. Disambiguate on the fixed length AND
        # the marker so such a v0 blob is not misrouted into the v1 (aad=row_id)
        # path — which would fail GCM auth and make ~0.4% of legacy rows look
        # tampered. Otherwise fall through to the legacy aad=None path.
        v1_len = 1 + NONCE_BYTES + KEY_BYTES + 16  # marker ‖ nonce ‖ DEK ‖ GCM tag
        if len(blob) == v1_len and blob[:1] == WRAP_FORMAT_V1:
            body, wrap_aad = blob[1:], aad
        else:
            # Legacy v0: no version byte, DEK wrapped with aad=None (pre-W6-T1).
            body, wrap_aad = blob, None
        nonce, sealed = body[:NONCE_BYTES], body[NONCE_BYTES:]
        try:
            return AESGCM(self._kek).decrypt(nonce, sealed, wrap_aad)
        except InvalidTag as exc:
            raise DecryptionError(
                "Wrapped DEK failed authenticated decryption (wrong KEK, wrong AAD, "
                "or tampered data)"
            ) from exc

    def health(self) -> ProviderHealth:
        """A local in-process KEK is always reachable."""
        return ProviderHealth(available=True, kek_version=self._version)


class EnvKeyProvider(_StaticKeyProvider):
    """KEK from the environment: ``NETOPS_KEK`` (urlsafe-base64, 32 bytes decoded)."""

    def __init__(self, settings: Settings) -> None:
        if settings.kek is None:
            raise KekConfigurationError("NETOPS_KEK is not set; cannot build EnvKeyProvider")
        super().__init__(
            _decode_kek(settings.kek.get_secret_value(), source="NETOPS_KEK"),
            settings.kek_version,
        )


class FileKeyProvider(_StaticKeyProvider):
    """KEK from a mounted file (Docker/K8s secret): ``NETOPS_KEK_FILE`` path."""

    def __init__(self, settings: Settings) -> None:
        if settings.kek_file is None:
            raise KekConfigurationError("NETOPS_KEK_FILE is not set; cannot build FileKeyProvider")
        try:
            encoded = settings.kek_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise KekConfigurationError(f"KEK file {settings.kek_file} could not be read") from exc
        super().__init__(
            _decode_kek(encoded, source=str(settings.kek_file)),
            settings.kek_version,
        )


# ---------------------------------------------------------------------------
# KMS backends (W6-T2, ADR-0032 §2). AWS / Azure / Vault Transit each implement
# the SAME wrap/unwrap contract behind a thin, injectable low-level client so
# the boto3 / azure / hvac SDKs (a) stay an OPTIONAL dependency and (b) are the
# ONLY place that touches the network — the wrap/unwrap logic (incl. the Azure
# inner-AESGCM AAD layer) is exercised by unit tests against an in-memory fake.
#
# No KEK export, no GenerateDataKey (carried from W6-T1): the DEK is generated
# locally (``envelope_encrypt``) and the KEK never leaves the KMS. Raw SDK
# exceptions are wrapped as a typed :class:`KeyProviderError` so a backend's
# request/response context never surfaces verbatim (ADR-0032 §6).
# ---------------------------------------------------------------------------

#: Class names of SDK exceptions that mean the backend is unreachable (a 503
#: fail-closed condition) rather than a request-level error. Matched on the
#: exception type's name so this module never has to import the cloud SDKs.
_UNAVAILABLE_EXC_NAMES: frozenset[str] = frozenset(
    {
        "ConnectionError",
        "ConnectTimeout",
        "ConnectTimeoutError",
        "ConnectionClosedError",
        "EndpointConnectionError",
        "ReadTimeout",
        "ReadTimeoutError",
        "Timeout",
        "TimeoutError",
        "VaultDown",
        "ServiceRequestError",
        "ServiceRequestTimeoutError",
    }
)


def _is_unavailable(exc: Exception) -> bool:
    """Whether *exc* (a raw SDK error) means the backend is unreachable (§4)."""
    return type(exc).__name__ in _UNAVAILABLE_EXC_NAMES


class _KmsKeyProvider:
    """Shared base for the production KMS backends (ADR-0032 §2).

    Subclasses implement :meth:`_wrap` / :meth:`_unwrap` / :meth:`_ping` against
    their injected low-level client; this base centralises the no-leak posture:
    a raw SDK exception is wrapped as :class:`KeyProviderUnavailable` (unreachable)
    or :class:`KeyProviderError` (any other backend reason), carrying only the
    exception's class name — never its message, request context, or key material.
    ``health()`` reports liveness without ever surfacing the backend's raw error.
    """

    _version: str

    def __init__(self, client: object) -> None:
        self._client = client

    @property
    def kek_version(self) -> str:
        """Stable id of the active wrapping key, stored on each credential row."""
        return self._version

    @property
    def is_production_grade(self) -> bool:
        """A real KMS backend is production-grade (ADR-0032 §2)."""
        return True

    def __repr__(self) -> str:
        # Class + kek_version only — never a key handle/ARN/URI/credential_ref.
        return f"<{type(self).__name__}:{self._version}>"

    # -- subclass hooks ------------------------------------------------------
    def _wrap(self, dek: bytes, *, aad: bytes) -> bytes:
        raise NotImplementedError

    def _unwrap(self, ciphertext: bytes, *, aad: bytes) -> bytes:
        raise NotImplementedError

    def _ping(self) -> None:
        """Cheapest liveness check (a wrap/unwrap of a throwaway probe DEK)."""
        probe = os.urandom(KEY_BYTES)
        self._unwrap(self._wrap(probe, aad=b"healthcheck"), aad=b"healthcheck")

    # -- contract ------------------------------------------------------------
    def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDek:
        try:
            ciphertext = self._wrap(dek, aad=aad)
        except (KeyProviderError, DecryptionError):
            raise
        except Exception as exc:  # noqa: BLE001 — wrap ALL raw SDK errors typed
            if _is_unavailable(exc):
                raise KeyProviderUnavailable(type(exc).__name__) from exc
            raise KeyProviderError(type(exc).__name__) from exc
        return WrappedDek(ciphertext=ciphertext, kek_version=self._version)

    def unwrap_dek(self, wrapped: WrappedDek, *, aad: bytes) -> bytes:
        try:
            return self._unwrap(wrapped.ciphertext, aad=aad)
        except (KeyProviderError, DecryptionError):
            raise
        except Exception as exc:  # noqa: BLE001 — wrap ALL raw SDK errors typed
            if _is_unavailable(exc):
                raise KeyProviderUnavailable(type(exc).__name__) from exc
            raise KeyProviderError(type(exc).__name__) from exc

    def health(self) -> ProviderHealth:
        try:
            self._ping()
        except Exception as exc:  # noqa: BLE001 — coarse reason class only
            return ProviderHealth(
                available=False, kek_version=self._version, detail=type(exc).__name__
            )
        return ProviderHealth(available=True, kek_version=self._version)


class AwsKmsKeyProvider(_KmsKeyProvider):
    """AWS KMS backend (ADR-0032 §2): ``kms:Encrypt`` / ``kms:Decrypt``.

    The row-id ``aad`` is bound **natively** via ``EncryptionContext={row_id}`` —
    Decrypt fails on a different context, so a wrapped DEK cannot be replayed onto
    another row (cross-row replay guard). Auth is IRSA / IAM role from the pod's
    ambient credential chain (boto3 default provider) — NO static access keys; the
    key is referenced by ARN only. ``kek_version`` is the key ARN.
    """

    def __init__(self, *, key_arn: str, client: object | None = None) -> None:
        self._key_arn = key_arn
        self._version = key_arn
        super().__init__(client if client is not None else _build_aws_kms_client(key_arn))

    def _context(self, aad: bytes) -> dict[str, str]:
        # EncryptionContext values are strings; the row-id AAD is UTF-8 text.
        return {"row_id": aad.decode("utf-8")}

    def _wrap(self, dek: bytes, *, aad: bytes) -> bytes:
        resp = self._client.encrypt(  # type: ignore[attr-defined]
            KeyId=self._key_arn, Plaintext=dek, EncryptionContext=self._context(aad)
        )
        blob = resp["CiphertextBlob"]
        return bytes(blob)

    def _unwrap(self, ciphertext: bytes, *, aad: bytes) -> bytes:
        try:
            resp = self._client.decrypt(  # type: ignore[attr-defined]
                CiphertextBlob=ciphertext, EncryptionContext=self._context(aad)
            )
        except Exception as exc:  # noqa: BLE001
            if _is_unavailable(exc):
                raise
            # A context mismatch (cross-row replay) or invalid ciphertext is a
            # KMS InvalidCiphertextException — surface the cross-row guard as the
            # same typed DecryptionError every backend uses, never the raw text.
            raise DecryptionError(
                "Wrapped DEK failed AWS KMS decryption (wrong row-id context or tampered data)"
            ) from exc
        return bytes(resp["Plaintext"])


class HashiCorpVaultTransitKeyProvider(_KmsKeyProvider):
    """HashiCorp Vault Transit backend (ADR-0032 §2): ``transit/encrypt|decrypt``.

    The row-id ``aad`` is bound **natively** via Transit ``context={row_id}`` —
    decrypt fails on a different context (cross-row replay guard). The short-lived
    token is obtained from a k8s-auth / AppRole login keyed by ``credential_ref``
    (an INDIRECT handle, never a token value) and auto-renewed; the value of
    ``credential_ref`` is never logged. ``kek_version`` is ``<key>:vN`` so an old
    transit key version still decrypts after rotation (ADR-0032 §2 rotation model).

    The injected *client* is the :class:`_VaultTransitClient` adapter contract
    (``encrypt_data`` / ``decrypt_data`` / ``read_key_version`` taking **raw**
    bytes + the bound mount). The adapter — not this provider — owns the real
    hvac shape (Transit's base64 plaintext/context wire encoding, ``mount_point``,
    ``read_key``); tests inject an in-memory double of that same adapter contract.
    """

    def __init__(
        self,
        *,
        transit_mount: str,
        transit_key: str,
        client: object | None = None,
        addr: str | None = None,
        credential_ref: str | None = None,
    ) -> None:
        self._mount = transit_mount
        self._key = transit_key
        # credential_ref is stored only to drive token login/renew; it is NEVER
        # rendered in repr/health/errors (a name-mangled attribute keeps it out of
        # any default dataclass-style introspection).
        self.__credential_ref = credential_ref
        resolved = (
            client
            if client is not None
            else _build_vault_transit_client(addr, transit_mount, credential_ref)
        )
        super().__init__(resolved)
        # The active transit key version; ``<key>:vN`` is the stored kek_version.
        # Read from the live key (real hvac: read_key()["data"]["latest_version"])
        # so a real KEK rotation moves kek_version and the T3 worklist predicate
        # (WHERE kek_version != active) actually fires — never a hardcoded v1.
        self._key_version = self._read_key_version()
        self._version = f"{self._key}:v{self._key_version}"

    def _read_key_version(self) -> int:
        return int(self._client.read_key_version(name=self._key))  # type: ignore[attr-defined]

    def _context(self, aad: bytes) -> bytes:
        return aad

    def _wrap(self, dek: bytes, *, aad: bytes) -> bytes:
        resp = self._client.encrypt_data(  # type: ignore[attr-defined]
            name=self._key, plaintext=dek, context=self._context(aad)
        )
        ciphertext: str = resp["data"]["ciphertext"]
        return ciphertext.encode("utf-8")

    def _unwrap(self, ciphertext: bytes, *, aad: bytes) -> bytes:
        try:
            resp = self._client.decrypt_data(  # type: ignore[attr-defined]
                name=self._key,
                ciphertext=ciphertext.decode("utf-8"),
                context=self._context(aad),
            )
        except Exception as exc:  # noqa: BLE001
            if _is_unavailable(exc):
                raise
            raise DecryptionError(
                "Wrapped DEK failed Vault Transit decryption (wrong row-id context "
                "or tampered data)"
            ) from exc
        return bytes(resp["data"]["plaintext"])


class AzureKeyVaultKeyProvider(_KmsKeyProvider):
    """Azure Key Vault backend (ADR-0032 §2): ``wrapKey`` / ``unwrapKey``.

    Azure ``wrapKey``/``unwrapKey`` (RSA-OAEP / AES-KW) has **no native AAD**, so
    the row-id is bound by a **local AESGCM inner layer**: a fresh random
    256-bit *inner key* seals the DEK with ``aad=row_id`` (fresh 96-bit nonce);
    the inner key — not the DEK — is sent to ``wrapKey``. ``unwrapKey`` reverses
    it and the AESGCM open **fails on a row-id mismatch**, giving the identical
    cross-row replay guard the native backends get. The single-blob schema is
    unchanged (ADR-0032 §1):

        ``WrappedDek.ciphertext = inner-nonce ‖ wrapped-inner-key ‖ inner-ciphertext``

    Auth is the pod managed identity (``DefaultAzureCredential``) — no client
    secret inlined; the key is referenced by vault URI + key name.

    The injected *client* is the :class:`_AzureKeyClient` adapter contract
    (``wrap_key`` / ``unwrap_key`` taking raw bytes + ``key_version``). The
    adapter — not this provider — pins the real azure shape:
    ``wrap_key(KeyWrapAlgorithm.rsa_oaep_256, key).encrypted_key`` /
    ``unwrap_key(KeyWrapAlgorithm.rsa_oaep_256, encrypted_key).key`` and the live
    ``key.properties.version``; tests inject an in-memory double of it.
    """

    def __init__(
        self,
        *,
        vault_uri: str,
        key_name: str,
        client: object | None = None,
    ) -> None:
        self._vault_uri = vault_uri
        self._key_name = key_name
        resolved = client if client is not None else _build_azure_key_client(vault_uri, key_name)
        super().__init__(resolved)
        # kek_version reflects the REAL Key Vault key version fetched at build
        # (key.properties.version) so a key rotation moves kek_version and the T3
        # worklist predicate fires — never a hardcoded ``azure-aesgcm-v1``. The
        # inner-AESGCM layer is the active row-id wrap; the configured key wraps
        # the inner key, so the wrapping-key version is the Key Vault key version.
        key_version = self._client.key_version()  # type: ignore[attr-defined]
        self._version = f"{key_name}:{key_version}"

    def _wrap(self, dek: bytes, *, aad: bytes) -> bytes:
        inner_key = AESGCM.generate_key(bit_length=KEY_BYTES * 8)
        inner_nonce = os.urandom(NONCE_BYTES)
        inner_ciphertext = AESGCM(inner_key).encrypt(inner_nonce, dek, aad)
        wrapped_inner = self._client.wrap_key(inner_key)  # type: ignore[attr-defined]
        return inner_nonce + bytes(wrapped_inner) + inner_ciphertext

    def _unwrap(self, ciphertext: bytes, *, aad: bytes) -> bytes:
        # Blob layout: inner-nonce(12) ‖ wrapped-inner-key(var) ‖ inner-ciphertext.
        # The DEK is always exactly KEY_BYTES, and AESGCM appends a 128-bit tag,
        # so the inner ciphertext is a fixed KEY_BYTES+16 tail; the wrapped inner
        # key (AES-KW / RSA-OAEP fixed output) is everything between the nonce and
        # that tail — no length prefix needed, the schema stays a single blob.
        inner_nonce = ciphertext[:NONCE_BYTES]
        body = ciphertext[NONCE_BYTES:]
        inner_ct_len = KEY_BYTES + 16  # AESGCM ciphertext = plaintext + 128-bit tag
        wrapped_inner = body[:-inner_ct_len]
        inner_ciphertext = body[-inner_ct_len:]
        try:
            inner_key = self._client.unwrap_key(wrapped_inner)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            if _is_unavailable(exc):
                raise
            raise DecryptionError(
                "Azure Key Vault could not unwrap the inner key (tampered data)"
            ) from exc
        try:
            return AESGCM(bytes(inner_key)).decrypt(inner_nonce, inner_ciphertext, aad)
        except InvalidTag as exc:
            raise DecryptionError(
                "Wrapped DEK failed inner-AESGCM authentication (wrong row-id aad or tampered data)"
            ) from exc


class FakeKmsKeyProvider(_KmsKeyProvider):
    """Deterministic in-memory KMS double for unit tests (ADR-0032 Negative).

    Production-grade by self-report (so prod-gating tests can exercise the allow
    path) yet fully in-process: it wraps the DEK with a process-local AESGCM key,
    binding the row-id ``aad`` natively so the cross-row replay guard holds. Set
    ``available=False`` to simulate an unreachable KMS (fail-closed tests).
    """

    def __init__(self, *, available: bool = True, version: str = "fake-kms:v1") -> None:
        self._version = version
        self._kek = AESGCM.generate_key(bit_length=KEY_BYTES * 8)
        self._available = available
        super().__init__(client=object())

    def _wrap(self, dek: bytes, *, aad: bytes) -> bytes:
        if not self._available:
            raise ConnectionError("fake kms unreachable")
        nonce = os.urandom(NONCE_BYTES)
        return nonce + AESGCM(self._kek).encrypt(nonce, dek, aad)

    def _unwrap(self, ciphertext: bytes, *, aad: bytes) -> bytes:
        if not self._available:
            raise ConnectionError("fake kms unreachable")
        nonce, sealed = ciphertext[:NONCE_BYTES], ciphertext[NONCE_BYTES:]
        try:
            return AESGCM(self._kek).decrypt(nonce, sealed, aad)
        except InvalidTag as exc:
            raise DecryptionError(
                "Wrapped DEK failed authenticated decryption (wrong row-id aad or tampered data)"
            ) from exc


# ---------------------------------------------------------------------------
# Real-SDK adapters. Each ``_build_*`` returns a thin adapter that maps the
# provider's raw-bytes contract onto the EXACT cloud-SDK call shape (the only
# place that imports boto3 / hvac / azure). The contract tests in
# ``tests/core/test_kms_contract.py`` pin these shapes against a mock SDK client
# so the prod path is covered without a live cloud (the CI emulator job is the
# real integration gate); the offline unit suite drives the providers via the
# in-memory adapter doubles in ``tests/core/test_kms_providers.py``.
# ---------------------------------------------------------------------------


def _build_aws_kms_client(key_arn: str) -> object:  # pragma: no cover - import needs boto3 extra
    """Build a boto3 ``kms`` client from the pod's ambient IAM/IRSA credentials.

    Lazy import keeps boto3 an OPTIONAL dependency (installed only where the AWS
    backend is selected); no static access keys — boto3's default provider chain
    resolves IRSA / instance-role credentials. The boto3 ``kms`` client already
    speaks the provider's ``encrypt(KeyId=, Plaintext=, EncryptionContext=)`` /
    ``decrypt(CiphertextBlob=, EncryptionContext=)`` shape natively, so it is
    returned directly (no adapter needed); the shape is pinned by a contract test.
    """
    try:
        import boto3  # noqa: PLC0415
    except ImportError as exc:
        raise KekConfigurationError(
            "VAULT_KEY_PROVIDER=aws requires the 'boto3' extra to be installed"
        ) from exc
    return boto3.client("kms")


class _VaultTransitClient:
    """Adapter mapping the provider's raw-bytes contract onto real hvac Transit.

    Transit's HTTP API takes **base64** ``plaintext`` / ``context`` and returns a
    base64 ``plaintext`` on decrypt, and the calls are namespaced under
    ``client.secrets.transit.*`` with an explicit ``mount_point``. This adapter
    owns exactly that translation — base64 in/out + the bound mount — so the
    provider stays a clean raw-bytes caller and the offline tests inject an
    in-memory double of *this* contract. The active version is read from the live
    key (``read_key()["data"]["latest_version"]``) so rotation is visible.
    """

    def __init__(self, client: object, mount: str) -> None:
        self._client = client
        self._mount = mount

    def encrypt_data(self, *, name: str, plaintext: bytes, context: bytes) -> dict[str, object]:
        resp = self._client.secrets.transit.encrypt_data(  # type: ignore[attr-defined]
            name=name,
            plaintext=base64.b64encode(plaintext).decode("ascii"),
            context=base64.b64encode(context).decode("ascii"),
            mount_point=self._mount,
        )
        return {"data": {"ciphertext": resp["data"]["ciphertext"]}}

    def decrypt_data(self, *, name: str, ciphertext: str, context: bytes) -> dict[str, object]:
        resp = self._client.secrets.transit.decrypt_data(  # type: ignore[attr-defined]
            name=name,
            ciphertext=ciphertext,
            context=base64.b64encode(context).decode("ascii"),
            mount_point=self._mount,
        )
        return {"data": {"plaintext": base64.b64decode(resp["data"]["plaintext"])}}

    def read_key_version(self, *, name: str) -> int:
        resp = self._client.secrets.transit.read_key(  # type: ignore[attr-defined]
            name=name, mount_point=self._mount
        )
        return int(resp["data"]["latest_version"])


#: Standard projected-ServiceAccount-token path inside a K8s pod (k8s-auth).
_SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"


def _read_sa_jwt() -> str | None:
    """Return the pod's projected ServiceAccount JWT, or ``None`` outside K8s.

    A thin, easily-stubbed indirection: this is the only place that reads the
    token file, so the value never enters a log line, and tests can override the
    k8s-vs-AppRole branch without filesystem games.
    """
    try:
        return Path(_SA_TOKEN_PATH).read_text(encoding="utf-8")
    except OSError:
        return None


def _vault_login(client: object, credential_ref: str | None) -> None:
    """Authenticate *client* via k8s-auth (default) or AppRole, then auto-renew.

    ``credential_ref`` is the INDIRECT login handle — a k8s-auth / AppRole **role**
    name, never a token value. The pod's projected ServiceAccount JWT is exchanged
    for a short-lived Vault token; the lease is renewed in the background. The
    ``credential_ref`` value is never logged (only its presence/absence drives the
    branch). If no ServiceAccount JWT is present we fall back to AppRole using the
    ref as the role id (the secret id arrives via the standard ``VAULT_*`` env /
    the agent sidecar), so the platform never inlines a secret here.
    """
    if not credential_ref:
        return
    jwt = _read_sa_jwt()
    if jwt is not None:
        client.auth.kubernetes.login(role=credential_ref, jwt=jwt)  # type: ignore[attr-defined]
    else:
        secret_id = os.environ.get("VAULT_SECRET_ID")
        client.auth.approle.login(  # type: ignore[attr-defined]
            role_id=credential_ref, secret_id=secret_id
        )
    # Best-effort lease renewal so a long-lived process keeps a valid token; the
    # fail-closed readiness gate catches an expired/unrenewable token as an outage.
    with contextlib.suppress(Exception):  # renewal is best-effort; readiness gate is the backstop
        client.auth.token.renew_self()  # type: ignore[attr-defined]


def _build_vault_transit_client(
    addr: str | None, mount: str, credential_ref: str | None
) -> object:  # pragma: no cover - import needs hvac extra + a live Vault
    """Build an hvac-backed :class:`_VaultTransitClient` authenticated via ``credential_ref``.

    Lazy import keeps hvac OPTIONAL. The ``credential_ref`` is the INDIRECT login
    handle (k8s-auth / AppRole role), exchanged for a short-lived, auto-renewed
    token (:func:`_vault_login`); its value is never logged. The returned adapter
    pins the real ``client.secrets.transit.*`` shape (base64 + ``mount_point``).
    """
    try:
        import hvac  # noqa: PLC0415
    except ImportError as exc:
        raise KekConfigurationError(
            "VAULT_KEY_PROVIDER=vault requires the 'hvac' extra to be installed"
        ) from exc
    client = hvac.Client(url=addr)
    _vault_login(client, credential_ref)
    return _VaultTransitClient(client, mount)


class _AzureKeyClient:
    """Adapter mapping the provider's raw-bytes contract onto real azure crypto.

    Azure ``wrapKey``/``unwrapKey`` is
    ``CryptographyClient.wrap_key(algorithm, key) -> WrapResult.encrypted_key`` and
    ``unwrap_key(algorithm, encrypted_key) -> UnwrapResult.key`` — a pinned
    ``rsa_oaep_256`` algorithm and result-object attribute access, NOT
    ``wrap_key(key=...)`` / ``bytes(result)``. This adapter owns that shape so the
    provider stays a raw-bytes caller; the offline tests inject a double of it.
    """

    def __init__(self, crypto_client: object, algorithm: object, key_version: str) -> None:
        self._crypto = crypto_client
        self._algorithm = algorithm
        self._key_version = key_version

    def wrap_key(self, key: bytes) -> bytes:
        result = self._crypto.wrap_key(self._algorithm, key)  # type: ignore[attr-defined]
        return bytes(result.encrypted_key)

    def unwrap_key(self, encrypted_key: bytes) -> bytes:
        result = self._crypto.unwrap_key(self._algorithm, encrypted_key)  # type: ignore[attr-defined]
        return bytes(result.key)

    def key_version(self) -> str:
        return self._key_version


def _build_azure_key_client(
    vault_uri: str, key_name: str
) -> object:  # pragma: no cover - import needs azure extra + cloud
    """Build an :class:`_AzureKeyClient` over a ``CryptographyClient`` via managed identity.

    Lazy import keeps the azure SDK OPTIONAL; ``DefaultAzureCredential`` resolves
    the pod's managed identity — no client secret inlined. The fetched key's real
    ``properties.version`` becomes the wrapping-key version (so a rotation moves
    ``kek_version``); the adapter pins the ``wrap_key(rsa_oaep_256, ...)`` shape.
    """
    try:
        from azure.identity import DefaultAzureCredential  # noqa: PLC0415
        from azure.keyvault.keys import KeyClient  # noqa: PLC0415
        from azure.keyvault.keys.crypto import (  # noqa: PLC0415
            CryptographyClient,
            KeyWrapAlgorithm,
        )
    except ImportError as exc:
        raise KekConfigurationError(
            "VAULT_KEY_PROVIDER=azure requires the 'azure' extra to be installed"
        ) from exc
    credential = DefaultAzureCredential()
    key = KeyClient(vault_url=vault_uri, credential=credential).get_key(key_name)
    crypto_client = CryptographyClient(key, credential=credential)
    return _AzureKeyClient(crypto_client, KeyWrapAlgorithm.rsa_oaep_256, key.properties.version)


def get_key_provider(settings: Settings, *, client: object | None = None) -> KeyProvider:
    """Build the configured :class:`KeyProvider` (ADR-0032 §2 config-only swap).

    ``VAULT_KEY_PROVIDER`` selects the backend: ``aws`` / ``azure`` / ``vault``
    (production KMS) or ``env`` / ``file`` (local fallback). When it is unset the
    legacy selection applies (``kek`` wins over ``kek_file``) so an existing local
    deployment is unchanged. *client* is a test-only injection point for the
    low-level KMS client; production resolves it from the pod's ambient identity.

    Raises:
        KekConfigurationError: If the selected backend's required settings are
            missing, or no KEK is configured at all.
    """
    selector = settings.vault_key_provider
    if selector == "aws":
        if not settings.aws_kms_key_arn:
            raise KekConfigurationError(
                "VAULT_KEY_PROVIDER=aws requires NETOPS_AWS_KMS_KEY_ARN (the KMS key ARN)"
            )
        return AwsKmsKeyProvider(key_arn=settings.aws_kms_key_arn, client=client)
    if selector == "vault":
        if not settings.vault_transit_key or not settings.vault_credential_ref:
            raise KekConfigurationError(
                "VAULT_KEY_PROVIDER=vault requires NETOPS_VAULT_TRANSIT_KEY and "
                "NETOPS_VAULT_CREDENTIAL_REF (an indirect login handle, never a token)"
            )
        return HashiCorpVaultTransitKeyProvider(
            transit_mount=settings.vault_transit_mount,
            transit_key=settings.vault_transit_key,
            addr=settings.vault_addr,
            credential_ref=settings.vault_credential_ref,
            client=client,
        )
    if selector == "azure":
        if not settings.azure_key_vault_uri or not settings.azure_key_name:
            raise KekConfigurationError(
                "VAULT_KEY_PROVIDER=azure requires NETOPS_AZURE_KEY_VAULT_URI and "
                "NETOPS_AZURE_KEY_NAME"
            )
        return AzureKeyVaultKeyProvider(
            vault_uri=settings.azure_key_vault_uri,
            key_name=settings.azure_key_name,
            client=client,
        )
    if selector == "file":
        return FileKeyProvider(settings)
    if selector == "env":
        return EnvKeyProvider(settings)
    # Legacy selection (no explicit VAULT_KEY_PROVIDER): kek wins over kek_file.
    if settings.kek is not None:
        return EnvKeyProvider(settings)
    if settings.kek_file is not None:
        return FileKeyProvider(settings)
    raise KekConfigurationError(
        "Credential vault KEK is not configured: set VAULT_KEY_PROVIDER to a KMS "
        "backend (aws|azure|vault) or NETOPS_KEK / NETOPS_KEK_FILE for the local "
        "fallback"
    )


def require_production_grade(provider: KeyProvider, *, is_prod: bool) -> None:
    """Refuse to start on a local KEK provider in production (ADR-0032 §2).

    Secure-by-default opt-out: when *is_prod* is true and *provider* is not a
    production-grade KMS backend, raise :class:`LocalKeyProviderInProductionError`
    so the credential service crashes startup loudly rather than silently running
    a non-production KEK behind a green deploy. The credential service stays
    provider-agnostic: this gate keys off ``is_production_grade`` only and never
    branches on which backend is configured.

    Raises:
        LocalKeyProviderInProductionError: If a local provider is selected in prod.
    """
    if is_prod and not is_production_grade(provider):
        name = type(provider).__name__
        raise LocalKeyProviderInProductionError(
            f"local KeyProvider {name!r} is not permitted in production; configure "
            f"a KMS backend (D11/ADR-0032 §2)"
        )


def is_production_grade(provider: KeyProvider) -> bool:
    """Whether *provider* is a production-grade KEK backend (ADR-0032 §2).

    Reads ``provider.is_production_grade`` when present (the Protocol property),
    defaulting to ``False`` (fail safe: an unknown provider is treated as a
    non-production local fallback so a non-prod KEK can never hide behind a green
    deploy). Used for the ``kek.provider.select`` audit row and the startup gate.
    """
    return bool(getattr(provider, "is_production_grade", False))


@dataclass(frozen=True, slots=True)
class EncryptedSecret:
    """Envelope-encrypted secret as persisted in ``device_credentials``.

    ``wrapped_dek`` / ``dek_nonce`` are the wrap-layer columns; for local
    providers the :class:`WrappedDek` blob is split back into them on store and
    recombined on unwrap. Byte fields are excluded from ``repr`` so accidental
    logging shows only the KEK version, never blob contents.
    """

    ciphertext: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    wrapped_dek: bytes = field(repr=False)
    dek_nonce: bytes = field(repr=False)
    kek_version: str

    def _wrapped(self) -> WrappedDek:
        """Recombine the two wrap-layer columns into a provider :class:`WrappedDek`."""
        return WrappedDek(
            ciphertext=self.dek_nonce + self.wrapped_dek, kek_version=self.kek_version
        )


def _split_wrapped(wrapped: WrappedDek) -> tuple[bytes, bytes]:
    """Split a local-provider blob into ``(dek_nonce, wrapped_dek)`` columns."""
    return wrapped.ciphertext[:NONCE_BYTES], wrapped.ciphertext[NONCE_BYTES:]


def envelope_encrypt(plaintext: bytes, aad: bytes, provider: KeyProvider) -> EncryptedSecret:
    """Encrypt *plaintext* under a fresh random DEK, wrapping the DEK with the KEK.

    Args:
        plaintext: Secret bytes to protect.
        aad: Associated data authenticated with **both** envelope layers — per
            ADR-0011/ADR-0032 the credential row id, binding the payload *and*
            the wrapped DEK to its row.
        provider: Wrap/unwrap source of the active KEK.

    Returns:
        The full envelope; every field is safe to persist.

    Raises:
        KeyProviderUnavailable: If the provider is unreachable (no row written).
    """
    dek = bytearray(AESGCM.generate_key(bit_length=KEY_BYTES * 8))
    try:
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(bytes(dek)).encrypt(nonce, plaintext, aad)
        wrapped = provider.wrap_dek(bytes(dek), aad=aad)
    finally:
        _zeroize(dek)
    dek_nonce, wrapped_dek = _split_wrapped(wrapped)
    return EncryptedSecret(
        ciphertext=ciphertext,
        nonce=nonce,
        wrapped_dek=wrapped_dek,
        dek_nonce=dek_nonce,
        kek_version=wrapped.kek_version,
    )


def envelope_decrypt(secret: EncryptedSecret, aad: bytes, provider: KeyProvider) -> bytes:
    """Decrypt *secret*, verifying *aad*; the inverse of :func:`envelope_encrypt`.

    The plaintext DEK is transient and zeroized after the single AESGCM op
    (ADR-0032 §6 — no DEK cache).

    Raises:
        UnknownKekVersionError: If the provider cannot supply ``secret.kek_version``.
        DecryptionError: If either GCM layer fails authentication (wrong AAD,
            wrong key, or tampered ciphertext).
        KeyProviderUnavailable: If the provider is unreachable (fail closed).
    """
    dek = bytearray(provider.unwrap_dek(secret._wrapped(), aad=aad))
    try:
        return AESGCM(bytes(dek)).decrypt(secret.nonce, secret.ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "Secret payload failed authenticated decryption (wrong AAD or tampered data)"
        ) from exc
    finally:
        _zeroize(dek)


def rewrap(secret: EncryptedSecret, aad: bytes, provider: KeyProvider) -> EncryptedSecret:
    """Re-wrap the DEK under the provider's active KEK (cheap rotation, ADR-0032 §3).

    The payload ``ciphertext``/``nonce`` are returned untouched — rotation never
    re-encrypts the payload. *aad* (the credential row id) is bound on both the
    old unwrap and the new wrap, so the row binding survives rotation. The
    provider must still be able to supply the old ``secret.kek_version``.

    Raises:
        UnknownKekVersionError: If the provider cannot supply the old version.
        KeyProviderUnavailable: If the provider is unreachable (fail closed).
    """
    dek = bytearray(provider.unwrap_dek(secret._wrapped(), aad=aad))
    try:
        wrapped = provider.wrap_dek(bytes(dek), aad=aad)
    finally:
        _zeroize(dek)
    dek_nonce, wrapped_dek = _split_wrapped(wrapped)
    return replace(
        secret, wrapped_dek=wrapped_dek, dek_nonce=dek_nonce, kek_version=wrapped.kek_version
    )
