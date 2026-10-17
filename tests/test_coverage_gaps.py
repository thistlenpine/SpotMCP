"""Tests for the branch-coverage gaps raised in the PR re-review."""

from __future__ import annotations

import asyncio
import json
import runpy
import sys
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import uvicorn

from spotmcp.app import create_app
from spotmcp.auth import JWKSCache, JWTTokenVerifier
from spotmcp.config import Settings
from spotmcp.upstream import ClientCredentialsTokenProvider
from tests.conftest import AUDIENCE, ISSUER, FakeIdP, FakeUpstream, HarnessContext, call_tool


def tool_error(result: dict[str, Any]) -> str:
    assert result["isError"] is True, result
    return str(result["content"][0]["text"])


def last_audit(caplog: pytest.LogCaptureFixture) -> dict[str, Any]:
    return [r.audit for r in caplog.records if r.name == "spotmcp.audit"][-1]  # type: ignore[attr-defined]


# --- JWKSCache ------------------------------------------------------------------------------------


@pytest.mark.parametrize("document", [{"issuer": ISSUER}, {"issuer": ISSUER, "jwks_uri": 123}])
async def test_discovery_without_usable_jwks_uri_rejects_and_throttles(document: dict[str, Any]) -> None:
    calls = []
    now = [0.0]

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json=document)

    jwks = JWKSCache(
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        issuer=ISSUER,
        min_refresh_seconds=30,
        clock=lambda: now[0],
    )
    verifier = JWTTokenVerifier(jwks, issuer=ISSUER, audience=[AUDIENCE], algorithms=["RS256"])
    idp = FakeIdP()
    for _ in range(5):
        assert await verifier.verify_token(idp.token()) is None
    assert len(calls) == 1  # failure throttled like any other refresh failure
    now[0] += 31
    assert await verifier.verify_token(idp.token()) is None
    assert len(calls) == 2


@pytest.mark.parametrize(
    "odd_key",
    [
        {"kid": "weird-kty", "kty": "XYZ", "use": "sig"},
        {"kid": "weird-crv", "kty": "EC", "crv": "P-999", "x": "AA", "y": "AA", "use": "sig"},
        {"kid": "no-kty", "use": "sig"},
    ],
)
async def test_unsupported_key_does_not_break_valid_keys(odd_key: dict[str, Any]) -> None:
    idp = FakeIdP()

    def handler(request: httpx.Request) -> httpx.Response:
        response = idp.handler(request)
        if request.url.path.endswith("/v1/keys"):
            return httpx.Response(200, json={"keys": [odd_key, *response.json()["keys"]]})
        return response

    jwks = JWKSCache(httpx.AsyncClient(transport=httpx.MockTransport(handler)), issuer=ISSUER)
    verifier = JWTTokenVerifier(jwks, issuer=ISSUER, audience=[AUDIENCE], algorithms=["RS256", "ES256"])
    assert await verifier.verify_token(idp.token()) is not None
    assert await jwks.get_key(odd_key["kid"]) is None


# --- _check_parameters: list values ---------------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "GET"])
@pytest.mark.parametrize("value", [["west", "east"], [1, 2.5, True, None], []])
async def test_list_of_scalars_accepted_in_both_modes(
    make_settings: Callable[..., Settings],
    idp: FakeIdP,
    upstream: FakeUpstream,
    method: str,
    value: list[Any],
) -> None:
    settings = make_settings(upstream_run_method=method, upstream_run_path="/huge/{query_id}")
    async with HarnessContext(settings, idp, upstream) as h:
        result = await call_tool(h, "run_saved_query", {"query_id": "q", "parameters": {"regions": value}})
    assert not result["isError"], result
    _, _, _, body = upstream.requests[-1]
    if method == "POST":
        assert json.loads(body)["parameters"] == {"regions": value}


async def test_list_of_scalars_encoded_as_repeated_query_keys(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: FakeUpstream
) -> None:
    seen: list[str] = []
    original = upstream._record

    async def record(request: Any) -> None:
        seen.append(str(request.url))
        await original(request)

    upstream._record = record  # type: ignore[method-assign]
    settings = make_settings(upstream_run_method="GET", upstream_run_path="/huge/{query_id}")
    async with HarnessContext(settings, idp, upstream) as h:
        await call_tool(h, "run_saved_query", {"query_id": "q", "parameters": {"r": ["a", "b"]}})
    query = httpx.URL(seen[-1]).params
    assert query.get_list("r") == ["a", "b"]
    assert query["read_only"] == "true"


@pytest.mark.parametrize("value", [[{"a": 1}], [[1, 2]], ["ok", {"nested": True}]])
async def test_non_scalar_lists_rejected_in_get_accepted_in_post(
    make_settings: Callable[..., Settings],
    idp: FakeIdP,
    upstream: FakeUpstream,
    value: list[Any],
) -> None:
    get = make_settings(upstream_run_method="GET", upstream_run_path="/huge/{query_id}")
    async with HarnessContext(get, idp, upstream) as h:
        result = await call_tool(h, "run_saved_query", {"query_id": "q", "parameters": {"p": value}})
        assert "scalar" in tool_error(result)
    assert upstream.requests == []
    post = make_settings(upstream_run_path="/huge/{query_id}")
    async with HarnessContext(post, idp, upstream) as h:
        result = await call_tool(h, "run_saved_query", {"query_id": "q", "parameters": {"p": value}})
    assert not result["isError"], result
    assert json.loads(upstream.requests[-1][3])["parameters"] == {"p": value}


# --- client_slot ---------------------------------------------------------------------------------


async def test_per_client_cap_holds_while_other_calls_still_in_flight(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: FakeUpstream
) -> None:
    def run(h: Any, delay: float) -> Any:
        return asyncio.create_task(
            call_tool(h, "run_saved_query", {"query_id": "slow-report", "parameters": {"delay": delay}})
        )

    async with HarnessContext(make_settings(max_concurrent_queries_per_client=2), idp, upstream) as h:
        short, long = run(h, 0.2), run(h, 1.5)
        assert not (await short)["isError"]  # count 2 -> 1: entry must survive, not reset to zero
        third = run(h, 1.0)  # count back to 2
        await asyncio.sleep(0.1)
        rejected = await call_tool(
            h, "run_saved_query", {"query_id": "slow-report", "parameters": {"delay": 0}}
        )
        assert "too many concurrent queries" in tool_error(rejected)
        assert not (await long)["isError"]
        assert not (await third)["isError"]
        # All released: the client may run again.
        ok = await call_tool(h, "run_saved_query", {"query_id": "slow-report", "parameters": {"delay": 0}})
        assert not ok["isError"]


async def test_slot_released_after_timeout(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: FakeUpstream
) -> None:
    async with HarnessContext(make_settings(max_concurrent_queries_per_client=1), idp, upstream) as h:
        timed_out = await call_tool(h, "run_saved_query", {"query_id": "slow-report", "timeout_seconds": 0.1})
        assert "timed out" in tool_error(timed_out)
        ok = await call_tool(h, "run_saved_query", {"query_id": "slow-report", "parameters": {"delay": 0}})
        assert not ok["isError"]


# --- ClientCredentialsTokenProvider --------------------------------------------------------------


async def test_concurrent_token_requests_are_coalesced() -> None:
    posts = []

    async def slow_token(request: httpx.Request) -> httpx.Response:
        posts.append(request)
        await asyncio.sleep(0.1)
        return httpx.Response(200, json={"access_token": f"t{len(posts)}", "expires_in": 3600})

    provider = ClientCredentialsTokenProvider(
        httpx.AsyncClient(transport=httpx.MockTransport(slow_token)),
        token_url="https://idp/token",
        client_id="c",
        client_secret="s",
    )
    tokens = await asyncio.gather(*(provider.get_token() for _ in range(10)))
    assert len(posts) == 1
    assert set(tokens) == {"t1"}
    provider.invalidate()
    tokens = await asyncio.gather(*(provider.get_token() for _ in range(10)))
    assert len(posts) == 2
    assert set(tokens) == {"t2"}


# --- generic upstream errors across tools --------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args", "path_setting"),
    [
        ("list_saved_queries", {}, "upstream_list_path"),
        ("get_saved_query", {"query_id": "q"}, "upstream_get_path"),
        ("run_saved_query", {"query_id": "q"}, "upstream_run_path"),
    ],
)
@pytest.mark.parametrize(
    ("route", "expected"),
    [("boom", "upstream returned HTTP 500"), ("huge", "upstream response exceeded 2048 bytes")],
)
async def test_upstream_errors_per_tool(
    make_settings: Callable[..., Settings],
    idp: FakeIdP,
    upstream: FakeUpstream,
    caplog: pytest.LogCaptureFixture,
    tool: str,
    args: dict[str, Any],
    path_setting: str,
    route: str,
    expected: str,
) -> None:
    caplog.set_level("INFO", logger="spotmcp.audit")
    settings = make_settings(**{path_setting: f"/{route}/{{query_id}}"}, max_response_bytes=2048)
    async with HarnessContext(settings, idp, upstream) as h:
        message = tool_error(await call_tool(h, tool, args))
    assert message == f"Error executing tool {tool}: {expected}"
    assert "internal-secret-detail" not in message
    audit = last_audit(caplog)
    assert (audit["tool"], audit["outcome"]) == (tool, "error")


# --- app lifespan: client ownership -------------------------------------------------------------


async def test_lifespan_closes_owned_clients_only(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    created: list[httpx.AsyncClient] = []
    original_init = httpx.AsyncClient.__init__

    def tracking_init(self: httpx.AsyncClient, *args: Any, **kwargs: Any) -> None:
        original_init(self, *args, **kwargs)
        created.append(self)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", tracking_init)

    # Production wiring: the app creates (and so must close) its own IdP and upstream clients.
    app = create_app(make_settings())
    owned = list(created)
    assert len(owned) == 2
    async with app.router.lifespan_context(app):
        assert not any(c.is_closed for c in owned)
    assert all(c.is_closed for c in owned)

    # Injected clients belong to the caller and are left open.
    idp_http, upstream_http = httpx.AsyncClient(), httpx.AsyncClient()
    app = create_app(make_settings(), idp_http=idp_http, upstream_http=upstream_http)
    async with app.router.lifespan_context(app):
        pass
    assert not idp_http.is_closed and not upstream_http.is_closed
    await idp_http.aclose()
    await upstream_http.aclose()


# --- entry points -------------------------------------------------------------------------------


@pytest.mark.parametrize("module", ["spotmcp", "spotmcp.main"])
def test_module_entry_points_start_server(monkeypatch: pytest.MonkeyPatch, module: str) -> None:
    import logging

    for key, value in {
        "SPOTMCP_RESOURCE_URL": "https://spot.example.com/mcp",
        "SPOTMCP_OAUTH_ISSUER": "https://idp.example.com",
        "SPOTMCP_OAUTH_AUDIENCE": "api://spot",
        "SPOTMCP_UPSTREAM_BASE_URL": "https://internal/api",
        "SPOTMCP_ALLOWED_QUERY_IDS": "q1",
    }.items():
        monkeypatch.setenv(key, value)
    calls: list[Any] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    # Execute the module fresh, as `python -m` would, rather than reusing an imported copy.
    monkeypatch.delitem(sys.modules, module, raising=False)
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    try:
        runpy.run_module(module, run_name="__main__", alter_sys=True)
    finally:
        root.handlers[:], root.level = saved[0], saved[1]
    assert calls and calls[0]["port"] == 8080
