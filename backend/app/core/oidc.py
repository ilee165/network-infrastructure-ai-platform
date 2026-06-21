"""OIDC relying-party primitives: discovery, PKCE, JWKS, ID-token validation.

This module is the **JOSE / flow core** behind the ADR-0028 OIDC
``IdentityProvider``. It is deliberately pure-``core`` (no DB, no app models,
no FastAPI) so it sits below every app-internal layer and is unit-testable in
isolation; the route + DB-anchoring half lives in
:mod:`app.services.oidc.service` and :mod:`app.api.v1.auth`.

Security posture (ADR-0028 §1/§3, ADR-0011 / ADR-0024 §2 redaction):

- **PKCE ``S256`` always** — :func:`generate_pkce` mints a CSPRNG
  ``code_verifier`` and the ``S256`` challenge; PKCE is used even though the
  client is confidential (OAuth 2.1).
- **Full ID-token validation** — :func:`validate_id_token` verifies the
  signature against the IdP JWKS by ``kid``, pins the algorithm to the
  asymmetric set (**``alg:none`` and every HMAC alg are rejected**, closing the
  alg-confusion class), and exact-matches ``iss``/``aud``/``nonce`` with a
  bounded ``exp``/``iat``/``nbf`` skew leeway.
- **JWKS rotation** — :class:`JwksCache` caches keys per issuer with a bounded
  TTL and performs exactly **one** rate-limited forced refresh on an unknown
  ``kid`` before failing closed (§3).
- **No secret/token in logs** — nothing here logs a token, ``code``,
  ``code_verifier``, client secret, or raw claim set; failures raise
  :class:`OidcError` with a coarse, non-leaking reason and never echo token
  material.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import warnings
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.errors import NetOpsError

# ``authlib.jose`` is the ADR-0010/ADR-0028-named JOSE implementation. It emits
# a forward-looking deprecation warning (joserfc is the eventual successor);
# silence only that one import-time warning so it never pollutes log/test output.
with warnings.catch_warnings():
    from authlib.deprecate import AuthlibDeprecationWarning

    warnings.simplefilter("ignore", AuthlibDeprecationWarning)
    from authlib.jose import JsonWebKey, JsonWebToken
    from authlib.jose.errors import JoseError

#: Asymmetric signing algorithms the platform will accept from an IdP. HMAC
#: algorithms (``HS*``) and ``none`` are deliberately absent: accepting an HMAC
#: alg against a public JWKS key is the classic alg-confusion forgery, and
#: ``alg:none`` is an unsigned token — both are rejected (ADR-0028 §1).
ALLOWED_ID_TOKEN_ALGS: tuple[str, ...] = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")

#: Discovery suffix appended to the issuer to find the provider metadata.
_DISCOVERY_SUFFIX = "/.well-known/openid-configuration"

_PKCE_VERIFIER_BYTES = 64  # → ~86 url-safe chars, within the 43–128 RFC range.
_STATE_BYTES = 32  # 256-bit CSRF token (≥128-bit required, ADR-0028 §1).
_NONCE_BYTES = 32  # 256-bit anti-replay nonce.


class OidcError(NetOpsError):
    """An OIDC flow / token-validation failure (fail-closed, ADR-0028 §3).

    Surfaces as a generic 401 so the callback never leaks *why* validation
    failed to the browser; the coarse :attr:`reason` is for the audit trail
    (``auth.oidc.login_failed``) only and never carries token material.
    """

    status_code = 401
    title = "Unauthorized"
    slug = "unauthorized"

    def __init__(self, reason: str) -> None:
        #: Coarse machine reason for the audit detail — never a raw claim/token.
        self.reason = reason
        super().__init__("OIDC authentication failed")


def _b64url(raw: bytes) -> str:
    """Base64url-encode *raw* without padding (PKCE / JOSE convention)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True, slots=True)
class PkceChallenge:
    """A PKCE pair: the server-held ``verifier`` and the ``S256`` ``challenge``.

    The ``verifier`` is single-use and **never** leaves the server (it is held
    in the pending-auth store and replayed only on the back-channel token
    exchange); only the ``challenge`` is sent to the IdP on the authorize redirect.
    """

    verifier: str
    challenge: str
    method: str = "S256"


def generate_pkce() -> PkceChallenge:
    """Mint a fresh CSPRNG PKCE ``S256`` pair (ADR-0028 §1)."""
    verifier = _b64url(secrets.token_bytes(_PKCE_VERIFIER_BYTES))
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return PkceChallenge(verifier=verifier, challenge=_b64url(digest))


def generate_state() -> str:
    """A single-use CSPRNG ``state`` (≥128-bit) bound to the pending-auth entry."""
    return _b64url(secrets.token_bytes(_STATE_BYTES))


def generate_nonce() -> str:
    """A single-use CSPRNG ``nonce`` bound into the ID token (anti-replay)."""
    return _b64url(secrets.token_bytes(_NONCE_BYTES))


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """The subset of OIDC discovery metadata the relying party needs (§1)."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    end_session_endpoint: str | None = None


def parse_provider_metadata(doc: dict[str, Any]) -> ProviderMetadata:
    """Extract + validate the required discovery fields, else fail closed.

    A discovery document whose ``issuer`` / ``authorization_endpoint`` /
    ``token_endpoint`` / ``jwks_uri`` are missing is a misconfigured or hostile
    provider — :class:`OidcError`, never a partial config.
    """
    try:
        return ProviderMetadata(
            issuer=str(doc["issuer"]),
            authorization_endpoint=str(doc["authorization_endpoint"]),
            token_endpoint=str(doc["token_endpoint"]),
            jwks_uri=str(doc["jwks_uri"]),
            end_session_endpoint=(
                str(doc["end_session_endpoint"]) if doc.get("end_session_endpoint") else None
            ),
        )
    except KeyError as exc:
        raise OidcError("discovery_incomplete") from exc


async def fetch_discovery(issuer: str, *, verify: bool = True) -> ProviderMetadata:
    """Fetch + parse ``<issuer>/.well-known/openid-configuration`` over TLS.

    TLS verification is on by default (ADR-0007). Any transport/parse failure is
    fail-closed (:class:`OidcError`); the IdP error body is discarded so nothing
    it echoes can leak.
    """
    url = issuer.rstrip("/") + _DISCOVERY_SUFFIX
    try:
        async with httpx.AsyncClient(verify=verify, timeout=10.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            doc = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError("discovery_fetch_failed") from exc
    return parse_provider_metadata(doc)


def build_authorize_url(
    metadata: ProviderMetadata,
    *,
    client_id: str,
    redirect_uri: str,
    scopes: str,
    state: str,
    nonce: str,
    challenge: PkceChallenge,
) -> str:
    """Build the Authorization-Code + PKCE authorize URL (ADR-0028 §1 step 1)."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge.challenge,
        "code_challenge_method": challenge.method,
    }
    # httpx.QueryParams percent-encodes each value into a safe query string.
    encoded = str(httpx.QueryParams(params))
    return f"{metadata.authorization_endpoint}?{encoded}"


@dataclass(frozen=True, slots=True)
class TokenResponse:
    """The back-channel token-endpoint response (ADR-0028 §1 step 5).

    Tokens live here transiently and are consumed immediately by validation;
    the dataclass is never logged and the tokens never reach a response body.
    """

    id_token: str
    access_token: str | None = None
    refresh_token: str | None = None


async def exchange_code(
    metadata: ProviderMetadata,
    *,
    code: str,
    redirect_uri: str,
    client_id: str,
    client_secret: str,
    code_verifier: str,
    verify: bool = True,
) -> TokenResponse:
    """Exchange ``code`` + ``code_verifier`` + client secret for tokens (TLS, §1).

    The client secret is materialized in-process from the vault by the caller
    and passed here only to pin it onto the back-channel POST body; it is never
    logged. A failure (bad code, IdP error, missing ``id_token``) is fail-closed.
    """
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "code_verifier": code_verifier,
    }
    try:
        async with httpx.AsyncClient(verify=verify, timeout=10.0) as client:
            resp = await client.post(metadata.token_endpoint, data=data)
            resp.raise_for_status()
            body = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError("token_exchange_failed") from exc
    id_token = body.get("id_token")
    if not id_token:
        raise OidcError("token_exchange_no_id_token")
    return TokenResponse(
        id_token=str(id_token),
        access_token=body.get("access_token"),
        refresh_token=body.get("refresh_token"),
    )


@dataclass
class JwksCache:
    """Per-issuer JWKS cache with a bounded TTL + one rate-limited forced refresh.

    On an unknown ``kid`` in an otherwise well-formed token, exactly **one**
    forced refresh is attempted (handling a just-rotated key) before failing
    closed; a minimum interval between forced refreshes blunts a forged-``kid``
    refresh-storm DoS (ADR-0028 §3). A JWKS fetch failure is fail-closed.
    """

    #: Minimum seconds between two forced (unknown-``kid``) refreshes per issuer.
    forced_refresh_min_interval_secs: float = 5.0
    ttl_secs: float = 600.0
    verify: bool = True
    _keys: dict[str, dict[str, Any]] = field(default_factory=dict)
    _fetched_at: dict[str, float] = field(default_factory=dict)
    _last_forced: dict[str, float] = field(default_factory=dict)

    def _now(self) -> float:
        return time.monotonic()

    async def _fetch(self, jwks_uri: str) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(verify=self.verify, timeout=10.0) as client:
                resp = await client.get(jwks_uri)
                resp.raise_for_status()
                return dict(resp.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise OidcError("jwks_fetch_failed") from exc

    async def get_key(self, issuer: str, jwks_uri: str, kid: str) -> dict[str, Any]:
        """Return the JWK for *kid* under *issuer*, forcing one refresh if unseen.

        Raises :class:`OidcError` if the key is unknown after the single allowed
        forced refresh, or if a needed fetch fails (fail-closed).
        """
        cached = self._keys.get(issuer)
        age = self._now() - self._fetched_at.get(issuer, 0.0)
        if cached is None or age >= self.ttl_secs:
            cached = await self._fetch(jwks_uri)
            self._keys[issuer] = cached
            self._fetched_at[issuer] = self._now()
        key = _find_jwk(cached, kid)
        if key is not None:
            return key
        # Unknown kid: attempt exactly one rate-limited forced refresh.
        last = self._last_forced.get(issuer, 0.0)
        if self._now() - last < self.forced_refresh_min_interval_secs and last != 0.0:
            raise OidcError("jwks_unknown_kid")
        self._last_forced[issuer] = self._now()
        refreshed = await self._fetch(jwks_uri)
        self._keys[issuer] = refreshed
        self._fetched_at[issuer] = self._now()
        key = _find_jwk(refreshed, kid)
        if key is None:
            raise OidcError("jwks_unknown_kid")
        return key


def _find_jwk(jwks: dict[str, Any], kid: str) -> dict[str, Any] | None:
    """Return the JWK dict whose ``kid`` matches, or ``None``."""
    for jwk in jwks.get("keys", []):
        if jwk.get("kid") == kid:
            return dict(jwk)
    return None


def _peek_header(id_token: str) -> dict[str, Any]:
    """Decode the JOSE header without verifying — for ``kid``/``alg`` only.

    The result is used solely to select the verification key and to reject
    ``alg:none``/HMAC *before* any signature work; it is never trusted as data.
    """
    try:
        header_b64 = id_token.split(".", 1)[0]
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        return dict(json.loads(base64.urlsafe_b64decode(padded)))
    except (ValueError, IndexError) as exc:
        raise OidcError("id_token_malformed") from exc


async def validate_id_token(
    id_token: str,
    *,
    jwks_cache: JwksCache,
    issuer: str,
    jwks_uri: str,
    client_id: str,
    nonce: str,
    clock_skew_secs: int = 120,
) -> dict[str, Any]:
    """Fully validate an ID token, returning its claims or failing closed.

    Every check is mandatory (ADR-0028 §1): algorithm pinned to the asymmetric
    set (``alg:none``/HMAC rejected), signature verified against the JWKS key
    matched by ``kid``, exact ``iss``/``aud``/``nonce`` match, and bounded
    ``exp``/``iat``/``nbf`` skew. Any failure ⇒ :class:`OidcError` (no claims).
    """
    header = _peek_header(id_token)
    alg = header.get("alg")
    if alg not in ALLOWED_ID_TOKEN_ALGS:
        # Closes alg:none + HMAC alg-confusion before any key work (§1).
        raise OidcError("id_token_alg_rejected")
    kid = header.get("kid")
    if not kid:
        raise OidcError("id_token_no_kid")

    jwk_dict = await jwks_cache.get_key(issuer, jwks_uri, str(kid))
    key = JsonWebKey.import_key(jwk_dict)

    claims_options = {
        "iss": {"essential": True, "value": issuer},
        "aud": {"essential": True, "value": client_id},
        "exp": {"essential": True},
        "nonce": {"essential": True, "value": nonce},
    }
    jwt = JsonWebToken(list(ALLOWED_ID_TOKEN_ALGS))
    try:
        claims = jwt.decode(id_token, key, claims_options=claims_options)
        # Validate time-based claims with bounded leeway (exp/iat/nbf, §3).
        claims.validate(leeway=clock_skew_secs)
    except JoseError as exc:
        raise OidcError("id_token_invalid") from exc

    # Defensive belt-and-braces: ensure aud actually contains our client_id even
    # when the IdP emits aud as a list (Authlib value-match handles scalar aud).
    aud = claims.get("aud")
    aud_values = aud if isinstance(aud, list) else [aud]
    if client_id not in aud_values:
        raise OidcError("id_token_aud_mismatch")
    # Multi-audience ID tokens (aud is a list with >1 entry) MUST carry an azp
    # (authorized party) equal to our client_id (OIDC Core §3.1.3.7 step 4/5).
    # Containment alone is insufficient here: another audience could replay a
    # token minted for itself. Single-audience behaviour is unchanged. Fail-closed.
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != client_id:
        raise OidcError("id_token_azp_mismatch")
    if claims.get("nonce") != nonce:
        raise OidcError("id_token_nonce_mismatch")
    if claims.get("iss") != issuer:
        raise OidcError("id_token_iss_mismatch")
    sub = claims.get("sub")
    if not sub:
        raise OidcError("id_token_no_sub")
    return dict(claims)
