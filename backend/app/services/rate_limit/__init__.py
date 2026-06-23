"""Rate-limiting + login throttle/lockout service (W6-T6).

Exposes the shared fixed-window counter contract and its two implementations,
the typed backend error, and the small key-builder helpers that keep key
construction (and its no-secret-in-key invariant) in one place.
"""

from app.services.rate_limit.keys import (
    api_principal_key,
    api_token_key,
    login_lockout_key,
    login_lockout_state_key,
    login_source_key,
    login_source_lock_key,
    oidc_callback_key,
)
from app.services.rate_limit.limiter import (
    InMemoryRateLimiter,
    RateLimitBackendError,
    RateLimiter,
    RateLimitResult,
    RedisRateLimiter,
)

__all__ = [
    "InMemoryRateLimiter",
    "RateLimitBackendError",
    "RateLimitResult",
    "RateLimiter",
    "RedisRateLimiter",
    "api_principal_key",
    "api_token_key",
    "login_lockout_key",
    "login_lockout_state_key",
    "login_source_key",
    "login_source_lock_key",
    "oidc_callback_key",
]
