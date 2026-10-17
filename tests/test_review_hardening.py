"""Regression tests for the hardening done in response to PR review."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from typing import Any

import httpx
import jwt
import pytest
from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.middleware import Middleware

from spotmcp.app import _check_middleware_order
from spotmcp.auth import JWKSCache, JWKSError, JWTTokenVerifier
from spotmcp.config import Settings
from spotmcp.ratelimit import RateLimiter, RateLimitMiddleware
from tests.conftest import (
    AUDIENCE,
    INIT,
    ISSUER,
    MCP_HEADERS,
    FakeIdP,
    FakeUpstream,
    Harness,
    HarnessContext,
    SigningKey,
    call_tool,
)


def tool_error(result: dict[str, Any]) -> str:
    assert result["isError"] is True, result
    return str(result["content"][0]["text"])


# --- parameter values never reach any log ------------------------------------------------------


async def test_get_mode_parameters_not_logged_anywhere(
    make_settings: Callable[..., Settings],
    idp: FakeIdP,
    upstream: FakeUpstream,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def execute_get(request: Any) -> Any:
        from starlette.responses import JSONResponse

        return JSONResponse({"rows": [{"ok": True}]})

    from starlette.routing import Route

    upstream.app.router.routes.append(Route("/api/q/{query_id}/run", execute_get, methods=["GET"]))
    settings = make_settings(upstream_run_method="GET", upstream_run_path="/q/{query_id}/run")
    caplog.set_level("DEBUG")  # root at DEBUG: anything any logger emits is captured
    async with HarnessContext(settings, idp, upstream) as h:
        result = await call_tool(
            h, "run_saved_query", {"query_id": "q1", "parameters": {"ssn": "123-45-6789"}}
        )
        assert not result["isError"], result
    assert caplog.records, "expected some log output"
    for record in caplog.records:
        assert "123-45-6789" not in record.getMessage(), (record.name, record.getMessage())
        assert "123-45-6789" not in json.dumps(getattr(record, "audit", {}))


# --- allow-list is mandatory; rejections are audited ---------------------------------------------


def test_allow_list_or_explicit_opt_out_required(make_settings: Callable[..., Settings]) -> None:
    with pytest.raises(ValidationError, match="SPOTMCP_ALLOWED_QUERY_IDS is required"):
        make_settings(allow_any_query=False)
    assert make_settings(allow_any_query=False, allowed_query_ids="q1").allowed_query_ids == ["q1"]


@pytest.mark.parametrize(("query_id", "outcome"), [("../admin", "invalid_id"), ("big-table", "denied")])
@pytest.mark.parametrize("tool", ["run_saved_query", "get_saved_query"])
async def test_rejected_ids_are_audited(
    make_settings: Callable[..., Settings],
    idp: FakeIdP,
    upstream: FakeUpstream,
    caplog: pytest.LogCaptureFixture,
    tool: str,
    query_id: str,
    outcome: str,
) -> None:
    caplog.set_level("INFO", logger="spotmcp.audit")
    async with HarnessContext(make_settings(allowed_query_ids="sales-by-region"), idp, upstream) as h:
        tool_error(await call_tool(h, tool, {"query_id": query_id}))
    audits = [r.audit for r in caplog.records if r.name == "spotmcp.audit"]  # type: ignore[attr-defined]
    assert audits[-1]["outcome"] == outcome
    assert audits[-1]["tool"] == tool
    assert audits[-1]["client_id"] == "client-a"
    assert upstream.requests == []


async def test_invalid_parameters_are_audited(
    make_settings: Callable[..., Settings],
    idp: FakeIdP,
    upstream: FakeUpstream,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO", logger="spotmcp.audit")
    async with HarnessContext(make_settings(upstream_run_method="GET"), idp, upstream) as h:
        tool_error(await call_tool(h, "run_saved_query", {"query_id": "q", "parameters": {"a": {"b": 1}}}))
    assert [r.audit for r in caplog.records][-1]["outcome"] == "invalid_parameters"  # type: ignore[attr-defined]


# --- rate-limit override validation --------------------------------------------------------------


@pytest.mark.parametrize("override", ["c=nan", "c=inf", "c=-inf", "a=0", "b=-5", "d=abc", "=5"])
def test_bad_rate_limit_overrides_rejected(make_settings: Callable[..., Settings], override: str) -> None:
    with pytest.raises(ValidationError):
        make_settings(rate_limit_overrides=override)


def test_nan_override_cannot_bypass_limiter_via_dict(make_settings: Callable[..., Settings]) -> None:
    with pytest.raises(ValidationError):
        make_settings(rate_limit_overrides={"c": float("nan")})


# --- https everywhere ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"oauth_issuer": "http://idp.example.com"},
        {"oauth_jwks_url": "http://idp.example.com/keys"},
        {"upstream_base_url": "http://internal.example.com/api"},
        {"resource_url": "http://spotmcp.example.com/mcp"},
        {
            "upstream_auth_mode": "client_credentials",
            "upstream_token_url": "http://idp.example.com/token",
            "upstream_client_id": "c",
            "upstream_client_secret": "s",
        },
    ],
)
def test_plain_http_rejected(make_settings: Callable[..., Settings], overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="must use https"):
        make_settings(**overrides)
    assert make_settings(allow_insecure_http=True, **overrides)


def test_http_allowed_for_localhost(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(resource_url="http://localhost:8080/mcp", upstream_base_url="http://127.0.0.1:9000/api")
    assert s.resource_url.host == "localhost"


def _jwks_cache(handler: Callable[[httpx.Request], httpx.Response], **kwargs: Any) -> JWKSCache:
    return JWKSCache(httpx.AsyncClient(transport=httpx.MockTransport(handler)), issuer=ISSUER, **kwargs)


async def test_discovery_issuer_must_match() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"issuer": "https://evil.example.com", "jwks_uri": f"{ISSUER}/keys"})

    with pytest.raises(JWKSError, match="does not match"):
        await _jwks_cache(handler).get_key("k")


async def test_discovered_jwks_uri_must_be_https() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": "http://idp.example.com/keys"})

    with pytest.raises(JWKSError, match="non-https"):
        await _jwks_cache(handler).get_key("k")


# --- JWKS failure handling -----------------------------------------------------------------------


async def test_failed_jwks_refresh_is_throttled() -> None:
    calls = []
    now = [0.0]

    def down(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(500)

    jwks = _jwks_cache(down, jwks_url=f"{ISSUER}/keys", min_refresh_seconds=30, clock=lambda: now[0])
    verifier = JWTTokenVerifier(jwks, issuer=ISSUER, audience=[AUDIENCE], algorithms=["RS256"])
    idp = FakeIdP()
    for i in range(25):
        assert await verifier.verify_token(idp.token(key=SigningKey(f"junk-{i}"))) is None
    assert len(calls) == 1
    now[0] += 31
    assert await verifier.verify_token(idp.token()) is None
    assert len(calls) == 2


async def test_stale_keys_served_when_refresh_fails() -> None:
    idp = FakeIdP()
    now = [0.0]
    up = [True]

    def handler(request: httpx.Request) -> httpx.Response:
        return idp.handler(request) if up[0] else httpx.Response(503)

    jwks = _jwks_cache(handler, cache_seconds=60, min_refresh_seconds=5, clock=lambda: now[0])
    verifier = JWTTokenVerifier(jwks, issuer=ISSUER, audience=[AUDIENCE], algorithms=["RS256"])
    assert await verifier.verify_token(idp.token()) is not None
    up[0] = False
    now[0] += 3600  # cache long expired, IdP down
    assert await verifier.verify_token(idp.token()) is not None


async def test_encryption_keys_are_ignored(idp: FakeIdP) -> None:
    original = idp.keys[0].jwk

    def as_enc() -> dict[str, Any]:
        return {**original(), "use": "enc"}

    idp.keys[0].jwk = as_enc  # type: ignore[method-assign]
    jwks = JWKSCache(httpx.AsyncClient(transport=httpx.MockTransport(idp.handler)), issuer=ISSUER)
    with pytest.raises(JWKSError, match="no usable signing keys"):
        await jwks.get_key("key-1")


async def test_long_kid_is_truncated_in_logs(idp: FakeIdP, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO", logger="spotmcp.auth")
    jwks = JWKSCache(httpx.AsyncClient(transport=httpx.MockTransport(idp.handler)), issuer=ISSUER)
    verifier = JWTTokenVerifier(jwks, issuer=ISSUER, audience=[AUDIENCE], algorithms=["RS256"])
    claims = {"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 60, "cid": "x"}
    token = jwt.encode(claims, idp.keys[0].private, algorithm="RS256", headers={"kid": "k" * 5000})
    assert await verifier.verify_token(token) is None
    assert all(len(r.getMessage()) < 300 for r in caplog.records)


# --- concurrency caps ----------------------------------------------------------------------------


async def test_per_client_concurrency_cap(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: FakeUpstream
) -> None:
    upstream.slow_seconds = 0.5
    async with HarnessContext(make_settings(max_concurrent_queries_per_client=1), idp, upstream) as h:
        first = asyncio.create_task(call_tool(h, "run_saved_query", {"query_id": "slow-report"}))
        await asyncio.sleep(0.1)
        second = await call_tool(h, "run_saved_query", {"query_id": "slow-report"})
        assert "too many concurrent queries" in tool_error(second)
        assert not (await first)["isError"]
        # Slot released: the next call goes through.
        upstream.slow_seconds = 0
        assert not (await call_tool(h, "run_saved_query", {"query_id": "slow-report"}))["isError"]


async def test_global_concurrency_cap_waits_within_deadline(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: FakeUpstream
) -> None:
    upstream.slow_seconds = 1.0
    async with HarnessContext(make_settings(max_concurrent_queries=1), idp, upstream) as h:
        other = Harness(h.app, h.http, h.idp, h.upstream)
        holder = asyncio.create_task(call_tool(h, "run_saved_query", {"query_id": "slow-report"}))
        await asyncio.sleep(0.1)
        response = await h.http.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "run_saved_query",
                    "arguments": {"query_id": "big-table", "timeout_seconds": 0.2},
                },
            },
            headers={**MCP_HEADERS, "mcp-protocol-version": "2025-06-18", **other.auth(client_id="client-b")},
        )
        assert "timed out" in tool_error(response.json()["result"])
        assert not (await holder)["isError"]


# --- upstream shape handling ---------------------------------------------------------------------


async def test_row_limit_not_applied_is_reported(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from spotmcp.upstream import UpstreamClient

    async def run(self: Any, *args: Any, **kwargs: Any) -> Any:
        return {"data": [{"n": i} for i in range(5000)]}

    monkeypatch.setattr(UpstreamClient, "run_query", run)
    caplog.set_level("WARNING", logger="spotmcp.tools")
    content = (await call_tool(harness, "run_saved_query", {"query_id": "q"}))["structuredContent"]
    assert content["row_limit_applied"] is False
    assert content["row_count"] is None
    assert any("row limit not applied" in r.getMessage() for r in caplog.records)


async def test_query_id_field_is_configurable(
    make_settings: Callable[..., Settings],
    idp: FakeIdP,
    upstream: FakeUpstream,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from spotmcp.upstream import UpstreamClient

    async def listing(self: Any) -> Any:
        return [{"query_id": "a"}, {"query_id": "b"}]

    monkeypatch.setattr(UpstreamClient, "list_queries", listing)
    settings = make_settings(allowed_query_ids="a", query_id_field="query_id")
    async with HarnessContext(settings, idp, upstream) as h:
        result = await call_tool(h, "list_saved_queries")
    assert result["structuredContent"]["queries"] == [{"query_id": "a"}]


# --- app wiring ----------------------------------------------------------------------------------


def test_middleware_order_guard() -> None:
    limiter = RateLimiter(per_minute=1, burst=1)
    bad = Starlette(middleware=[Middleware(RateLimitMiddleware, limiter=limiter, path="/mcp")])
    with pytest.raises(RuntimeError, match="middleware layout"):
        _check_middleware_order(bad)


async def test_request_body_size_limited(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: FakeUpstream
) -> None:
    async with HarnessContext(make_settings(max_request_body_bytes=2048), idp, upstream) as h:
        big = {**INIT, "params": {**INIT["params"], "pad": "x" * 10_000}}  # type: ignore[dict-item]
        response = await h.http.post("/mcp", json=big, headers={**MCP_HEADERS, **h.auth()})
        assert response.status_code == 413


@pytest.mark.parametrize(
    "document", [{"keys": 5}, {"keys": {"a": 1}}, {"keys": [5, "x", {}]}, [1, 2], "nope"]
)
async def test_malformed_jwks_documents_reject_cleanly(document: Any) -> None:
    jwks = _jwks_cache(lambda r: httpx.Response(200, json=document), jwks_url=f"{ISSUER}/keys")
    verifier = JWTTokenVerifier(jwks, issuer=ISSUER, audience=[AUDIENCE], algorithms=["RS256"])
    assert await verifier.verify_token(FakeIdP().token()) is None
