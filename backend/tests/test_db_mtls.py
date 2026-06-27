"""api/worker -> Postgres mTLS client configuration (W4-T4, ADR-0039 §4).

The DB engine must present a CLIENT certificate and verify the SERVER (the
``verify-full`` class) whenever the deployment supplies mTLS material. ADR-0039
§4: ``api`` and ``worker`` connect with ``sslmode=verify-full`` and
``sslcert``/``sslkey``/``sslrootcert`` pointing at mounted cert files.

These are the client-side "bite": with the mTLS settings populated, the async
engine MUST be built with an asyncpg ``ssl`` connect-arg that is a verify-full
``SSLContext`` (hostname check ON + peer cert REQUIRED + the client chain
loaded); with them unset the engine stays plaintext (current behaviour). The
cert material is files on disk (mounted K8s Secret), never a literal — so these
tests generate a throwaway CA + server/client pair in a temp dir.
"""

from __future__ import annotations

import datetime as dt
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import app.db as db
from app.core.config import Settings


def _write_cert_material(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Generate a self-signed CA + a client cert/key, written as PEM files.

    Returns ``(ca_path, client_cert_path, client_key_path)``. Mirrors the
    chart's dev cert material (a CA that signs a client cert) so the loaded
    SSLContext has a real chain to verify against.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "netops-test-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.crt"
    client_cert_path = tmp_path / "client.crt"
    client_key_path = tmp_path / "client.key"
    # The CA cert doubles as the client cert here (a single self-signed leaf the
    # SSLContext can load) — the test only exercises SSLContext construction, not
    # a live handshake (that is the kind assertion's job).
    pem = cert.public_bytes(serialization.Encoding.PEM)
    ca_path.write_bytes(pem)
    client_cert_path.write_bytes(pem)
    client_key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return ca_path, client_cert_path, client_key_path


def test_no_ssl_settings_keeps_plaintext_connect_args() -> None:
    """With no mTLS settings, the engine carries no ssl connect-arg (unchanged)."""
    settings = Settings(database_url="postgresql+asyncpg://netops:netops@h:5432/netops")
    assert settings.db_ssl_mode is None
    args = db.build_ssl_connect_args(settings)
    assert args == {}


def test_verify_full_builds_mutual_tls_context(tmp_path: Path) -> None:
    """sslmode=verify-full + cert material => a mutual-TLS SSLContext connect-arg."""
    ca, cert, key = _write_cert_material(tmp_path)
    settings = Settings(
        database_url="postgresql+asyncpg://netops:netops@netops-postgres:5432/netops",
        db_ssl_mode="verify-full",
        db_ssl_root_cert=ca,
        db_ssl_cert=cert,
        db_ssl_key=key,
    )
    args = db.build_ssl_connect_args(settings)
    ctx = args["ssl"]
    assert isinstance(ctx, ssl.SSLContext)
    # verify-full == verify the server identity (hostname) AND require its cert.
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_verify_ca_disables_hostname_check_but_still_requires_cert(tmp_path: Path) -> None:
    """verify-ca verifies the chain but not the hostname (the libpq distinction)."""
    ca, cert, key = _write_cert_material(tmp_path)
    settings = Settings(
        database_url="postgresql+asyncpg://netops:netops@netops-postgres:5432/netops",
        db_ssl_mode="verify-ca",
        db_ssl_root_cert=ca,
        db_ssl_cert=cert,
        db_ssl_key=key,
    )
    ctx = db.build_ssl_connect_args(settings)["ssl"]
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_verify_full_requires_root_cert(tmp_path: Path) -> None:
    """verify-full without a root CA must fail closed, never silently downgrade."""
    _, cert, key = _write_cert_material(tmp_path)
    settings = Settings(
        database_url="postgresql+asyncpg://netops:netops@netops-postgres:5432/netops",
        db_ssl_mode="verify-full",
        db_ssl_cert=cert,
        db_ssl_key=key,
    )
    with pytest.raises(ValueError, match="root cert"):
        db.build_ssl_connect_args(settings)


def test_mode_set_without_client_cert_key_fails_closed(tmp_path: Path) -> None:
    """A mode + root CA but NO client cert/key must fail closed (no one-way downgrade).

    ADR-0039 §4 mandates mutual TLS: the client must PRESENT a cert. Building a
    server-auth-only context here would silently downgrade mTLS to one-way TLS at
    the client's own layer (the fail-open class the root-cert guard already blocks).
    """
    ca, _, _ = _write_cert_material(tmp_path)
    settings = Settings(
        database_url="postgresql+asyncpg://netops:netops@netops-postgres:5432/netops",
        db_ssl_mode="verify-full",
        db_ssl_root_cert=ca,
    )
    with pytest.raises(ValueError, match="client cert"):
        db.build_ssl_connect_args(settings)


def test_half_set_client_cert_key_fails_closed(tmp_path: Path) -> None:
    """Only one of NETOPS_DB_SSL_CERT / NETOPS_DB_SSL_KEY set must fail closed."""
    ca, cert, _ = _write_cert_material(tmp_path)
    settings = Settings(
        database_url="postgresql+asyncpg://netops:netops@netops-postgres:5432/netops",
        db_ssl_mode="verify-full",
        db_ssl_root_cert=ca,
        db_ssl_cert=cert,  # key omitted
    )
    with pytest.raises(ValueError, match="must be set together"):
        db.build_ssl_connect_args(settings)


def test_mutual_tls_actually_loads_client_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mutual leg is covered: load_cert_chain is called with the client cert/key.

    Spies on ``SSLContext.load_cert_chain`` so the test proves the client chain is
    actually loaded (the mTLS-presenting leg), not merely that a context is built.
    """
    ca, cert, key = _write_cert_material(tmp_path)
    settings = Settings(
        database_url="postgresql+asyncpg://netops:netops@netops-postgres:5432/netops",
        db_ssl_mode="verify-full",
        db_ssl_root_cert=ca,
        db_ssl_cert=cert,
        db_ssl_key=key,
    )
    loaded: dict[str, object] = {}
    real_load = ssl.SSLContext.load_cert_chain

    def _spy(self: ssl.SSLContext, certfile: object, keyfile: object = None, **kw: object) -> None:
        loaded["certfile"] = certfile
        loaded["keyfile"] = keyfile
        real_load(self, certfile, keyfile)  # type: ignore[arg-type]

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", _spy)
    db.build_ssl_connect_args(settings)
    assert loaded["certfile"] == str(cert)
    assert loaded["keyfile"] == str(key)


def test_create_engine_threads_ssl_connect_args(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """create_engine feeds the verify-full SSLContext into create_async_engine.

    Asserted at the seam (the ``connect_args`` passed to ``create_async_engine``)
    so the test is not coupled to SQLAlchemy's internal connection-pool layout:
    the content of the SSLContext itself is covered by the build_* tests above.
    """
    ca, cert, key = _write_cert_material(tmp_path)
    settings = Settings(
        database_url="postgresql+asyncpg://netops:netops@netops-postgres:5432/netops",
        db_ssl_mode="verify-full",
        db_ssl_root_cert=ca,
        db_ssl_cert=cert,
        db_ssl_key=key,
    )
    captured: dict[str, object] = {}

    def _spy(url: str, **kwargs: object) -> object:
        captured["connect_args"] = kwargs.get("connect_args")
        return object()

    monkeypatch.setattr(db, "create_async_engine", _spy)
    db.create_engine(settings)
    connect_args = captured["connect_args"]
    assert isinstance(connect_args, dict)
    assert isinstance(connect_args["ssl"], ssl.SSLContext)
    assert connect_args["ssl"].verify_mode == ssl.CERT_REQUIRED
