"""Shared OIDC test helpers: an in-memory IdP that mints signed ID tokens.

Pure local crypto (Authlib RSA keygen + ``jwt.encode``) — no network, no real
IdP. Used by the core, service, and API OIDC suites to exercise every
ID-token-validation branch (good signature vs. wrong key / wrong claim /
``alg:none``) and to prime the JWKS cache with a known key.
"""

from __future__ import annotations

import time
import warnings
from typing import Any

with warnings.catch_warnings():
    from authlib.deprecate import AuthlibDeprecationWarning

    warnings.simplefilter("ignore", AuthlibDeprecationWarning)
    from authlib.jose import JsonWebKey, jwt

ISSUER = "https://idp.example.com"
CLIENT_ID = "platform-client-id"


class FakeIdp:
    """A local OIDC IdP double: holds an RSA signing key + mints ID tokens."""

    def __init__(self, issuer: str = ISSUER, client_id: str = CLIENT_ID) -> None:
        self.issuer = issuer
        self.client_id = client_id
        self.key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        self._public = self.key.as_dict(is_private=False)
        # A second, unrelated key the platform will NOT have in its JWKS — used
        # to forge a token with a valid-looking but unverifiable signature.
        self.foreign_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)

    @property
    def kid(self) -> str:
        return str(self._public["kid"])

    def jwks(self) -> dict[str, Any]:
        """The public JWKS the platform fetches (only the real signing key)."""
        return {"keys": [self._public]}

    def claims(self, **overrides: Any) -> dict[str, Any]:
        now = int(time.time())
        base: dict[str, Any] = {
            "iss": self.issuer,
            "sub": "idp-subject-123",
            "aud": self.client_id,
            "nonce": "test-nonce",
            "exp": now + 600,
            "iat": now,
            "nbf": now,
            "email": "alice@example.com",
            "name": "Alice",
            "groups": ["netops-engineers"],
        }
        base.update(overrides)
        return base

    def id_token(
        self,
        *,
        alg: str = "RS256",
        kid: str | None = None,
        sign_with_foreign_key: bool = False,
        **claim_overrides: Any,
    ) -> str:
        """Mint a signed ID token; tweak ``alg``/``kid``/signing key/claims to forge failures."""
        header: dict[str, Any] = {"alg": alg}
        if alg != "none":
            header["kid"] = kid if kid is not None else self.kid
        signing_key = self.foreign_key if sign_with_foreign_key else self.key
        return jwt.encode(header, self.claims(**claim_overrides), signing_key).decode("ascii")

    def unsigned_none_token(self, **claim_overrides: Any) -> str:
        """An ``alg:none`` (unsigned) token — must always be rejected."""
        import base64
        import json

        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=")
        payload = base64.urlsafe_b64encode(
            json.dumps(self.claims(**claim_overrides)).encode()
        ).rstrip(b"=")
        return f"{header.decode()}.{payload.decode()}."
