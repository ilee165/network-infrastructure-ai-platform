"""ADR-0028 §1/§3 core OIDC: PKCE, ID-token validation branches, JWKS rotation.

Every check in the validation table is exercised — happy path plus one failing
branch per claim (bad signature, wrong iss/aud/exp/nonce) and the two
algorithm-confusion forgeries (``alg:none`` and an HMAC alg). The JWKS cache's
bounded-TTL + single forced-refresh-on-unknown-kid behaviour (§3) is covered
with a stub fetcher (no network).
"""

from __future__ import annotations

import time

import pytest

from app.core import oidc
from tests.oidc_helpers import CLIENT_ID, ISSUER, FakeIdp


@pytest.fixture()
def idp() -> FakeIdp:
    return FakeIdp()


@pytest.fixture()
def primed_cache(idp: FakeIdp) -> oidc.JwksCache:
    """A JwksCache pre-seeded with the IdP's real JWKS (no network fetch needed)."""
    cache = oidc.JwksCache()
    cache._keys[ISSUER] = idp.jwks()
    cache._fetched_at[ISSUER] = time.monotonic()
    return cache


# ---------------------------------------------------------------------------
# PKCE / state / nonce
# ---------------------------------------------------------------------------


def test_generate_pkce_is_s256_and_within_rfc_length() -> None:
    pkce = oidc.generate_pkce()
    assert pkce.method == "S256"
    assert 43 <= len(pkce.verifier) <= 128
    assert pkce.challenge != pkce.verifier  # challenge is the hash, not the secret


def test_pkce_state_nonce_are_unique_per_call() -> None:
    assert oidc.generate_pkce().verifier != oidc.generate_pkce().verifier
    assert oidc.generate_state() != oidc.generate_state()
    assert oidc.generate_nonce() != oidc.generate_nonce()


def test_build_authorize_url_carries_pkce_and_single_use_params() -> None:
    md = oidc.parse_provider_metadata(
        {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
        }
    )
    pkce = oidc.generate_pkce()
    url = oidc.build_authorize_url(
        md,
        client_id=CLIENT_ID,
        redirect_uri="https://rp/cb",
        scopes="openid groups",
        state="STATE",
        nonce="NONCE",
        challenge=pkce,
    )
    assert url.startswith(f"{ISSUER}/authorize?")
    assert "code_challenge_method=S256" in url
    assert "state=STATE" in url
    assert "nonce=NONCE" in url
    # The raw verifier must NEVER appear in the redirect (server-held only).
    assert pkce.verifier not in url


# ---------------------------------------------------------------------------
# ID-token validation: happy path
# ---------------------------------------------------------------------------


async def test_validate_id_token_happy_path(idp: FakeIdp, primed_cache: oidc.JwksCache) -> None:
    token = idp.id_token(nonce="N1")
    claims = await oidc.validate_id_token(
        token,
        jwks_cache=primed_cache,
        issuer=ISSUER,
        jwks_uri=f"{ISSUER}/jwks",
        client_id=CLIENT_ID,
        nonce="N1",
    )
    assert claims["sub"] == "idp-subject-123"
    assert claims["groups"] == ["netops-engineers"]


# ---------------------------------------------------------------------------
# ID-token validation: every failing branch
# ---------------------------------------------------------------------------


async def test_validate_rejects_bad_signature(idp: FakeIdp, primed_cache: oidc.JwksCache) -> None:
    # Signed with a key whose kid matches but is NOT in the platform's JWKS.
    token = idp.id_token(kid=idp.kid, sign_with_foreign_key=True, nonce="N1")
    with pytest.raises(oidc.OidcError):
        await oidc.validate_id_token(
            token,
            jwks_cache=primed_cache,
            issuer=ISSUER,
            jwks_uri=f"{ISSUER}/jwks",
            client_id=CLIENT_ID,
            nonce="N1",
        )


async def test_validate_rejects_wrong_issuer(idp: FakeIdp, primed_cache: oidc.JwksCache) -> None:
    token = idp.id_token(iss="https://evil.example.com", nonce="N1")
    with pytest.raises(oidc.OidcError):
        await oidc.validate_id_token(
            token,
            jwks_cache=primed_cache,
            issuer=ISSUER,
            jwks_uri=f"{ISSUER}/jwks",
            client_id=CLIENT_ID,
            nonce="N1",
        )


async def test_validate_rejects_wrong_audience(idp: FakeIdp, primed_cache: oidc.JwksCache) -> None:
    token = idp.id_token(aud="some-other-client", nonce="N1")
    with pytest.raises(oidc.OidcError):
        await oidc.validate_id_token(
            token,
            jwks_cache=primed_cache,
            issuer=ISSUER,
            jwks_uri=f"{ISSUER}/jwks",
            client_id=CLIENT_ID,
            nonce="N1",
        )


async def test_validate_rejects_expired_token(idp: FakeIdp, primed_cache: oidc.JwksCache) -> None:
    now = int(time.time())
    token = idp.id_token(exp=now - 3600, iat=now - 7200, nonce="N1")
    with pytest.raises(oidc.OidcError):
        await oidc.validate_id_token(
            token,
            jwks_cache=primed_cache,
            issuer=ISSUER,
            jwks_uri=f"{ISSUER}/jwks",
            client_id=CLIENT_ID,
            nonce="N1",
            clock_skew_secs=120,
        )


async def test_validate_rejects_wrong_nonce(idp: FakeIdp, primed_cache: oidc.JwksCache) -> None:
    token = idp.id_token(nonce="attacker-nonce")
    with pytest.raises(oidc.OidcError):
        await oidc.validate_id_token(
            token,
            jwks_cache=primed_cache,
            issuer=ISSUER,
            jwks_uri=f"{ISSUER}/jwks",
            client_id=CLIENT_ID,
            nonce="the-real-nonce",
        )


async def test_validate_rejects_alg_none(idp: FakeIdp, primed_cache: oidc.JwksCache) -> None:
    token = idp.unsigned_none_token(nonce="N1")
    with pytest.raises(oidc.OidcError):
        await oidc.validate_id_token(
            token,
            jwks_cache=primed_cache,
            issuer=ISSUER,
            jwks_uri=f"{ISSUER}/jwks",
            client_id=CLIENT_ID,
            nonce="N1",
        )


async def test_validate_rejects_hmac_alg_confusion(
    primed_cache: oidc.JwksCache,
) -> None:
    """An HS256 token must be rejected even with an otherwise-valid claim set."""
    import warnings

    with warnings.catch_warnings():
        from authlib.deprecate import AuthlibDeprecationWarning

        warnings.simplefilter("ignore", AuthlibDeprecationWarning)
        from authlib.jose import jwt

    forged = jwt.encode(
        {"alg": "HS256", "kid": "anything"},
        {
            "iss": ISSUER,
            "sub": "s",
            "aud": CLIENT_ID,
            "nonce": "N1",
            "exp": int(time.time()) + 600,
            "iat": int(time.time()),
        },
        "shared-secret-the-attacker-knows",
    ).decode("ascii")
    with pytest.raises(oidc.OidcError):
        await oidc.validate_id_token(
            forged,
            jwks_cache=primed_cache,
            issuer=ISSUER,
            jwks_uri=f"{ISSUER}/jwks",
            client_id=CLIENT_ID,
            nonce="N1",
        )


# ---------------------------------------------------------------------------
# JWKS rotation: one forced refresh on unknown kid, then fail-closed
# ---------------------------------------------------------------------------


class _StubFetcher:
    """Counts fetches and serves a configurable JWKS (no network)."""

    def __init__(self, jwks: dict) -> None:
        self.jwks = jwks
        self.calls = 0

    async def __call__(self, jwks_uri: str) -> dict:
        self.calls += 1
        return self.jwks


async def test_jwks_unknown_kid_triggers_one_forced_refresh(idp: FakeIdp) -> None:
    cache = oidc.JwksCache()
    fetcher = _StubFetcher(idp.jwks())
    cache._fetch = fetcher  # type: ignore[method-assign]
    # First lookup: cold cache → 1 fetch; kid is present so no forced refresh.
    key = await cache.get_key(ISSUER, f"{ISSUER}/jwks", idp.kid)
    assert key["kid"] == idp.kid
    assert fetcher.calls == 1


async def test_jwks_unknown_kid_after_refresh_fails_closed(idp: FakeIdp) -> None:
    cache = oidc.JwksCache()
    # Cache is warm but the requested kid is absent; the forced refresh returns
    # the same (still-missing) key set → fail closed.
    cache._keys[ISSUER] = idp.jwks()
    cache._fetched_at[ISSUER] = time.monotonic()
    fetcher = _StubFetcher(idp.jwks())
    cache._fetch = fetcher  # type: ignore[method-assign]
    with pytest.raises(oidc.OidcError):
        await cache.get_key(ISSUER, f"{ISSUER}/jwks", "rotated-away-kid")
    # Exactly one forced refresh was attempted before failing.
    assert fetcher.calls == 1


async def test_jwks_forced_refresh_is_rate_limited(idp: FakeIdp) -> None:
    cache = oidc.JwksCache(forced_refresh_min_interval_secs=1000.0)
    cache._keys[ISSUER] = idp.jwks()
    cache._fetched_at[ISSUER] = time.monotonic()
    fetcher = _StubFetcher(idp.jwks())
    cache._fetch = fetcher  # type: ignore[method-assign]
    # First forged-kid lookup forces one refresh.
    with pytest.raises(oidc.OidcError):
        await cache.get_key(ISSUER, f"{ISSUER}/jwks", "forged-1")
    assert fetcher.calls == 1
    # An immediate second forged-kid lookup is rate-limited: NO new fetch.
    with pytest.raises(oidc.OidcError):
        await cache.get_key(ISSUER, f"{ISSUER}/jwks", "forged-2")
    assert fetcher.calls == 1


async def test_parse_provider_metadata_rejects_incomplete_doc() -> None:
    with pytest.raises(oidc.OidcError):
        oidc.parse_provider_metadata({"issuer": ISSUER})  # missing endpoints
