"""JWT and password-hashing tests (no I/O)."""

from __future__ import annotations

from datetime import timedelta

import jwt as pyjwt
import pytest

from app.core.config import Settings
from app.core.errors import AuthError
from app.core.security import (
    ALGORITHM,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


class TestJwt:
    def test_roundtrip_returns_subject(self, settings: Settings) -> None:
        token = create_access_token("alice", settings)
        claims = decode_access_token(token, settings)
        assert claims["sub"] == "alice"
        assert claims["exp"] > claims["iat"]

    def test_extra_claims_are_embedded(self, settings: Settings) -> None:
        token = create_access_token("alice", settings, extra_claims={"role": "engineer"})
        claims = decode_access_token(token, settings)
        assert claims["role"] == "engineer"

    def test_extra_claims_cannot_override_subject(self, settings: Settings) -> None:
        token = create_access_token("alice", settings, extra_claims={"sub": "mallory"})
        claims = decode_access_token(token, settings)
        assert claims["sub"] == "alice"

    def test_expired_token_raises_auth_error(self, settings: Settings) -> None:
        token = create_access_token(
            "alice", settings, expires_delta=timedelta(seconds=-10)
        )
        with pytest.raises(AuthError, match="expired"):
            decode_access_token(token, settings)

    def test_tampered_token_raises_auth_error(self, settings: Settings) -> None:
        token = create_access_token("alice", settings)
        header, payload, signature = token.split(".")
        tampered = f"{header}.{payload}.{'A' * len(signature)}"
        with pytest.raises(AuthError):
            decode_access_token(tampered, settings)

    def test_token_signed_with_other_key_raises_auth_error(self, settings: Settings) -> None:
        forged = pyjwt.encode(
            {"sub": "alice", "exp": 4_102_444_800}, "wrong-key", algorithm=ALGORITHM
        )
        with pytest.raises(AuthError):
            decode_access_token(forged, settings)

    def test_token_without_required_claims_raises_auth_error(self, settings: Settings) -> None:
        no_exp = pyjwt.encode({"sub": "alice"}, settings.secret_key, algorithm=ALGORITHM)
        with pytest.raises(AuthError):
            decode_access_token(no_exp, settings)

    def test_garbage_token_raises_auth_error(self, settings: Settings) -> None:
        with pytest.raises(AuthError):
            decode_access_token("not-a-jwt", settings)


class TestPasswords:
    def test_hash_then_verify_roundtrip(self) -> None:
        hashed = hash_password("correct horse battery staple")
        assert hashed != "correct horse battery staple"
        assert verify_password("correct horse battery staple", hashed)

    def test_wrong_password_fails_verification(self) -> None:
        hashed = hash_password("correct horse battery staple")
        assert not verify_password("Tr0ub4dor&3", hashed)

    def test_hashes_are_salted(self) -> None:
        assert hash_password("same-input") != hash_password("same-input")
