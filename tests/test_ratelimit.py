from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from spotmcp.config import Settings
from spotmcp.ratelimit import RateLimiter
from tests.conftest import INIT, MCP_HEADERS, FakeIdP, HarnessContext


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def test_burst_then_reject(clock: FakeClock) -> None:
    limiter = RateLimiter(per_minute=60, burst=3, clock=clock)
    assert [limiter.check("a").allowed for _ in range(4)] == [True, True, True, False]


def test_retry_after_reflects_refill_rate(clock: FakeClock) -> None:
    limiter = RateLimiter(per_minute=30, burst=1, clock=clock)  # one token every 2s
    assert limiter.check("a").allowed
    decision = limiter.check("a")
    assert not decision.allowed
    assert decision.retry_after == pytest.approx(2.0)


def test_refill_over_time(clock: FakeClock) -> None:
    limiter = RateLimiter(per_minute=60, burst=2, clock=clock)
    limiter.check("a")
    limiter.check("a")
    assert not limiter.check("a").allowed
    clock.now += 1.0
    assert limiter.check("a").allowed
    assert not limiter.check("a").allowed
    clock.now += 600  # refill is capped at burst
    assert [limiter.check("a").allowed for _ in range(3)] == [True, True, False]


def test_clients_are_isolated(clock: FakeClock) -> None:
    limiter = RateLimiter(per_minute=60, burst=1, clock=clock)
    assert limiter.check("a").allowed
    assert not limiter.check("a").allowed
    assert limiter.check("b").allowed


def test_remaining_count(clock: FakeClock) -> None:
    limiter = RateLimiter(per_minute=60, burst=3, clock=clock)
    assert [limiter.check("a").remaining for _ in range(3)] == [2, 1, 0]


def test_overrides_change_rate_and_burst(clock: FakeClock) -> None:
    limiter = RateLimiter(per_minute=60, burst=2, overrides={"vip": 120, "slow": 6}, clock=clock)
    assert limiter.limit_for("vip") == 120
    assert sum(limiter.check("vip").allowed for _ in range(10)) == 4
    assert sum(limiter.check("slow").allowed for _ in range(10)) == 1
    assert sum(limiter.check("other").allowed for _ in range(10)) == 2


def test_lru_bounds_memory(clock: FakeClock) -> None:
    limiter = RateLimiter(per_minute=60, burst=1, max_keys=2, clock=clock)
    limiter.check("a")
    limiter.check("b")
    limiter.check("c")
    assert len(limiter._buckets) == 2
    assert "a" not in limiter._buckets


async def test_http_429_per_client(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: Any, clock: FakeClock
) -> None:
    settings = make_settings(rate_limit_per_minute=60, rate_limit_burst=2)
    limiter = RateLimiter(per_minute=60, burst=2, clock=clock)
    async with HarnessContext(settings, idp, upstream, limiter=limiter) as h:
        headers_a = {**MCP_HEADERS, **h.auth(client_id="client-a")}
        statuses = [(await h.http.post("/mcp", json=INIT, headers=headers_a)).status_code for _ in range(3)]
        assert statuses == [200, 200, 429]

        limited = await h.http.post("/mcp", json=INIT, headers=headers_a)
        assert limited.status_code == 429
        assert limited.headers["retry-after"] == "1"
        assert limited.headers["x-ratelimit-limit"] == "60"
        assert limited.json()["error"] == "rate_limited"

        # A different OAuth client has its own budget.
        headers_b = {**MCP_HEADERS, **h.auth(client_id="client-b")}
        assert (await h.http.post("/mcp", json=INIT, headers=headers_b)).status_code == 200

        # A fresh token for the same client shares the client's budget.
        headers_a2 = {**MCP_HEADERS, **h.auth(client_id="client-a", jti="another")}
        assert (await h.http.post("/mcp", json=INIT, headers=headers_a2)).status_code == 429

        clock.now += 1.0
        assert (await h.http.post("/mcp", json=INIT, headers=headers_a)).status_code == 200


async def test_unauthenticated_requests_get_401_not_429(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: Any, clock: FakeClock
) -> None:
    limiter = RateLimiter(per_minute=60, burst=1, clock=clock)
    async with HarnessContext(make_settings(), idp, upstream, limiter=limiter) as h:
        for _ in range(3):
            assert (await h.http.post("/mcp", json=INIT, headers=MCP_HEADERS)).status_code == 401


async def test_healthz_not_rate_limited(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: Any, clock: FakeClock
) -> None:
    limiter = RateLimiter(per_minute=60, burst=1, clock=clock)
    async with HarnessContext(make_settings(), idp, upstream, limiter=limiter) as h:
        for _ in range(5):
            assert (await h.http.get("/healthz", headers=h.auth())).status_code == 200


async def test_rate_limit_from_settings(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: Any
) -> None:
    settings = make_settings(rate_limit_per_minute=1, rate_limit_burst=1, rate_limit_overrides="vip=600")
    async with HarnessContext(settings, idp, upstream) as h:
        a = {**MCP_HEADERS, **h.auth(client_id="client-a")}
        assert (await h.http.post("/mcp", json=INIT, headers=a)).status_code == 200
        limited = await h.http.post("/mcp", json=INIT, headers=a)
        assert limited.status_code == 429
        assert int(limited.headers["retry-after"]) == 60
        vip = {**MCP_HEADERS, **h.auth(client_id="vip")}
        assert all([(await h.http.post("/mcp", json=INIT, headers=vip)).status_code == 200 for _ in range(5)])
