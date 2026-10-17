"""Per-OAuth-client token-bucket rate limiting."""

from __future__ import annotations

import json
import logging
import math
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)


@dataclass
class _Bucket:
    tokens: float
    updated: float


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit_per_minute: float
    remaining: int
    retry_after: float


class RateLimiter:
    """Token bucket per key: ``burst`` capacity, refilled at ``per_minute / 60`` tokens per second.

    Buckets are kept in an LRU map bounded by ``max_keys``; an evicted bucket is simply recreated full,
    so eviction can only ever be more lenient, never lock a client out. All operations are synchronous
    and the event loop is single-threaded, so no lock is needed.
    """

    def __init__(
        self,
        *,
        per_minute: float,
        burst: int,
        overrides: Mapping[str, float] | None = None,
        max_keys: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._per_minute = per_minute
        self._burst = burst
        self._overrides = dict(overrides or {})
        self._max_keys = max_keys
        self._clock = clock
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()

    def limit_for(self, key: str) -> float:
        return self._overrides.get(key, self._per_minute)

    def _capacity(self, key: str) -> float:
        # An override that is higher than the default burst also gets a proportionally larger burst.
        limit = self.limit_for(key)
        if key in self._overrides and self._per_minute > 0:
            return max(1.0, self._burst * limit / self._per_minute)
        return float(self._burst)

    def check(self, key: str) -> RateLimitDecision:
        now = self._clock()
        limit = self.limit_for(key)
        rate = limit / 60.0
        capacity = self._capacity(key)
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=capacity, updated=now)
            self._buckets[key] = bucket
            if len(self._buckets) > self._max_keys:
                self._buckets.popitem(last=False)
        else:
            self._buckets.move_to_end(key)
            bucket.tokens = min(capacity, bucket.tokens + (now - bucket.updated) * rate)
            bucket.updated = now
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return RateLimitDecision(True, limit, math.floor(bucket.tokens), 0.0)
        retry_after = (1.0 - bucket.tokens) / rate if rate > 0 else math.inf
        return RateLimitDecision(False, limit, 0, retry_after)


class RateLimitMiddleware:
    """ASGI middleware that rate limits authenticated requests by OAuth client ID.

    Must run *after* the authentication middleware (so ``scope["user"]`` is populated). Requests without
    an authenticated user are passed through untouched; the route-level auth guard rejects them.
    """

    def __init__(self, app: ASGIApp, *, limiter: RateLimiter, path: str) -> None:
        self.app = app
        self.limiter = limiter
        self.path = path.rstrip("/") or "/"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or (scope.get("path", "").rstrip("/") or "/") != self.path:
            await self.app(scope, receive, send)
            return
        user = scope.get("user")
        if not isinstance(user, AuthenticatedUser):
            await self.app(scope, receive, send)
            return
        client_id = user.access_token.client_id
        decision = self.limiter.check(client_id)
        if decision.allowed:
            await self.app(scope, receive, send)
            return
        retry_after = max(1, math.ceil(decision.retry_after)) if math.isfinite(decision.retry_after) else 60
        logger.warning("rate limit exceeded for client %s", client_id)
        body = json.dumps(
            {"error": "rate_limited", "error_description": f"Rate limit exceeded; retry after {retry_after}s"}
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"retry-after", str(retry_after).encode()),
                    (b"x-ratelimit-limit", f"{decision.limit_per_minute:g}".encode()),
                    (b"x-ratelimit-remaining", b"0"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
