from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from spotmcp.config import Settings
from spotmcp.upstream import (
    ClientCredentialsTokenProvider,
    UpstreamClient,
    UpstreamError,
    UpstreamTimeoutError,
    validate_query_id,
)
from tests.conftest import UPSTREAM


def client_for(settings: Settings, handler: Callable[[httpx.Request], Any]) -> UpstreamClient:
    return UpstreamClient(
        settings, http=httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=UPSTREAM)
    )


@pytest.fixture
def seen() -> list[httpx.Request]:
    return []


def recorder(seen: list[httpx.Request], response: httpx.Response | None = None) -> Callable[..., Any]:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": f"tok-{len(seen)}", "expires_in": 3600})
        return response or httpx.Response(200, json={"ok": True})

    return handler


async def test_static_bearer(make_settings: Callable[..., Settings], seen: list[httpx.Request]) -> None:
    s = make_settings(upstream_auth_mode="static_bearer", upstream_bearer_token="abc")
    await client_for(s, recorder(seen)).list_queries()
    assert seen[0].headers["authorization"] == "Bearer abc"
    assert seen[0].method == "GET"


async def test_api_key(make_settings: Callable[..., Settings], seen: list[httpx.Request]) -> None:
    s = make_settings(upstream_auth_mode="api_key", upstream_api_key="k", upstream_api_key_header="X-Key")
    await client_for(s, recorder(seen)).health()
    assert seen[0].headers["x-key"] == "k"


async def test_no_auth(make_settings: Callable[..., Settings], seen: list[httpx.Request]) -> None:
    await client_for(make_settings(), recorder(seen)).health()
    assert "authorization" not in seen[0].headers


async def test_client_credentials_token_cached(
    make_settings: Callable[..., Settings], seen: list[httpx.Request]
) -> None:
    s = make_settings(
        upstream_auth_mode="client_credentials",
        upstream_token_url="https://idp.example.com/token",
        upstream_client_id="spotmcp",
        upstream_client_secret="shh",
        upstream_scope="queries.read",
        upstream_audience="api://internal",
    )
    client = client_for(s, recorder(seen))
    await client.list_queries()
    await client.get_query("q1")
    token_requests = [r for r in seen if r.url.path == "/token"]
    assert len(token_requests) == 1
    body = token_requests[0].content.decode()
    assert "grant_type=client_credentials" in body
    assert "scope=queries.read" in body
    assert "audience=api%3A%2F%2Finternal" in body
    assert token_requests[0].headers["authorization"].startswith("Basic ")
    api_requests = [r for r in seen if r.url.path != "/token"]
    assert all(r.headers["authorization"] == "Bearer tok-1" for r in api_requests)


async def test_client_credentials_refresh_on_expiry() -> None:
    now = [0.0]
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"access_token": f"t{len(calls)}", "expires_in": 60})

    provider = ClientCredentialsTokenProvider(
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        token_url="https://idp/token",
        client_id="c",
        client_secret="s",
        clock=lambda: now[0],
    )
    assert await provider.get_token() == "t1"
    now[0] = 29
    assert await provider.get_token() == "t1"
    now[0] = 31  # refreshed 30s early
    assert await provider.get_token() == "t2"


async def test_client_credentials_failure() -> None:
    provider = ClientCredentialsTokenProvider(
        httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(401))),
        token_url="https://idp/token",
        client_id="c",
        client_secret="s",
    )
    with pytest.raises(UpstreamError, match="access token"):
        await provider.get_token()


async def test_response_size_cap(make_settings: Callable[..., Settings], seen: list[httpx.Request]) -> None:
    s = make_settings(max_response_bytes=1024)
    big = httpx.Response(200, content=b"[" + b"1," * 2000 + b"1]")
    with pytest.raises(UpstreamError, match="exceeded 1024 bytes"):
        await client_for(s, recorder(seen, big)).list_queries()


async def test_invalid_json(make_settings: Callable[..., Settings], seen: list[httpx.Request]) -> None:
    with pytest.raises(UpstreamError, match="invalid JSON"):
        await client_for(make_settings(), recorder(seen, httpx.Response(200, content=b"<html>"))).health()


async def test_empty_body(make_settings: Callable[..., Settings], seen: list[httpx.Request]) -> None:
    assert await client_for(make_settings(), recorder(seen, httpx.Response(204))).health() is None


async def test_transport_error(make_settings: Callable[..., Settings]) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(UpstreamError, match="request failed"):
        await client_for(make_settings(), boom).health()


async def test_httpx_timeout_maps_to_timeout_error(make_settings: Callable[..., Settings]) -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(UpstreamTimeoutError):
        await client_for(make_settings(), slow).run_query("q", {}, timeout=1)


async def test_wall_clock_deadline(make_settings: Callable[..., Settings]) -> None:
    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200)

    with pytest.raises(UpstreamTimeoutError, match=r"0\.1s"):
        await client_for(make_settings(), slow).run_query("q", {}, timeout=0.1)


async def test_get_run_method_uses_query_params(
    make_settings: Callable[..., Settings], seen: list[httpx.Request]
) -> None:
    s = make_settings(upstream_run_method="get", upstream_run_path="/q/{query_id}/run")
    await client_for(s, recorder(seen)).run_query("abc", {"region": "west", "ids": [1, 2]}, timeout=1)
    assert seen[0].method == "GET"
    assert seen[0].url.path == "/api/q/abc/run"
    assert seen[0].url.params.get_list("ids") == ["1", "2"]


async def test_query_id_is_url_encoded(
    make_settings: Callable[..., Settings], seen: list[httpx.Request]
) -> None:
    await client_for(make_settings(), recorder(seen)).get_query("ns:report.v1")
    assert seen[0].url.raw_path == b"/api/saved-queries/ns%3Areport.v1"


async def test_redirects_not_followed(make_settings: Callable[..., Settings]) -> None:
    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example.com/"})

    client = UpstreamClient(make_settings())
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(redirect), base_url=UPSTREAM)
    # Default client must not follow redirects; a 3xx is not a success.
    assert client._http.follow_redirects is False
    with pytest.raises(UpstreamError, match="HTTP 302"):
        await client.health()
    await client.aclose()


@pytest.mark.parametrize("bad", ["", "../x", "a/b", "a..b", "-start", "a b", "a" * 129, "é"])
def test_validate_query_id_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_query_id(bad)


@pytest.mark.parametrize("good", ["a", "sales-by-region", "ns:report.v1", "Q_123", "a" * 128])
def test_validate_query_id_accepts(good: str) -> None:
    assert validate_query_id(good) == good


async def test_default_client(make_settings: Callable[..., Settings]) -> None:
    client = UpstreamClient(make_settings(upstream_ca_bundle="/etc/ssl/certs/ca-certificates.crt"))
    assert str(client._http.base_url).rstrip("/") == UPSTREAM
    await client.aclose()


async def test_upstream_401_invalidates_cached_token(make_settings: Callable[..., Settings]) -> None:
    seen: list[httpx.Request] = []
    api_status = [401]

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": f"tok-{len(seen)}", "expires_in": 3600})
        return httpx.Response(api_status[0], json={})

    s = make_settings(
        upstream_auth_mode="client_credentials",
        upstream_token_url="https://idp.example.com/token",
        upstream_client_id="spotmcp",
        upstream_client_secret="shh",
    )
    client = client_for(s, handler)
    with pytest.raises(UpstreamError, match="HTTP 401"):
        await client.health()
    api_status[0] = 200
    await client.health()
    assert [r.url.path for r in seen].count("/token") == 2
    assert seen[-1].headers["authorization"] == "Bearer tok-3"


async def test_upstream_401_retried_once_with_fresh_token(make_settings: Callable[..., Settings]) -> None:
    seen: list[httpx.Request] = []
    statuses = iter([401, 200])

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": f"tok-{len(seen)}", "expires_in": 3600})
        return httpx.Response(next(statuses), json={"ok": True})

    s = make_settings(
        upstream_auth_mode="client_credentials",
        upstream_token_url="https://idp.example.com/token",
        upstream_client_id="spotmcp",
        upstream_client_secret="shh",
    )
    assert await client_for(s, handler).health() == {"ok": True}
    paths = [r.url.path for r in seen]
    assert paths == ["/token", "/api/health", "/token", "/api/health"]
    assert seen[1].headers["authorization"] != seen[3].headers["authorization"]


async def test_verify_tls_disabled_warns(
    make_settings: Callable[..., Settings], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("WARNING", logger="spotmcp.upstream")
    client = UpstreamClient(make_settings(upstream_verify_tls=False))
    assert any("DISABLED" in r.getMessage() for r in caplog.records)
    await client.aclose()
