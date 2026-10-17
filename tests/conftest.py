from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from spotmcp.app import create_app
from spotmcp.config import Settings

ISSUER = "https://idp.example.com/oauth2/default"
AUDIENCE = "api://spotmcp"
RESOURCE_URL = "https://spotmcp.example.com/mcp"
UPSTREAM = "https://internal.example.com/api"


@dataclass
class SigningKey:
    kid: str
    private: rsa.RSAPrivateKey = field(
        default_factory=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )

    def jwk(self) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(RSAAlgorithm.to_jwk(self.private.public_key()))
        data.update({"kid": self.kid, "alg": "RS256", "use": "sig"})
        return data


class FakeIdP:
    """Serves OIDC discovery + JWKS and mints tokens."""

    def __init__(self) -> None:
        self.keys = [SigningKey("key-1")]
        self.jwks_requests = 0
        self.discovery_requests = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            self.discovery_requests += 1
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": f"{ISSUER}/v1/keys"})
        if request.url.path.endswith("/v1/keys"):
            self.jwks_requests += 1
            return httpx.Response(200, json={"keys": [k.jwk() for k in self.keys]})
        return httpx.Response(404)

    def token(
        self,
        *,
        client_id: str = "client-a",
        key: SigningKey | None = None,
        lifetime: int = 300,
        headers: dict[str, Any] | None = None,
        **overrides: Any,
    ) -> str:
        key = key or self.keys[0]
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": client_id,
            "cid": client_id,
            "iat": now,
            "exp": now + lifetime,
            "scp": ["spotmcp.read"],
        }
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, key.private, algorithm="RS256", headers={"kid": key.kid, **(headers or {})})


class FakeUpstream:
    """A stand-in for the internal saved-query REST API."""

    def __init__(self) -> None:
        self.queries = {
            "sales-by-region": {"id": "sales-by-region", "name": "Sales by region", "parameters": ["region"]},
            "slow-report": {"id": "slow-report", "name": "Slow report", "parameters": []},
            "big-table": {"id": "big-table", "name": "Big table", "parameters": []},
        }
        self.requests: list[tuple[str, str, dict[str, str], bytes]] = []
        self.slow_seconds = 5.0
        self.cancelled = asyncio.Event()
        self.healthy = True
        self.app = Starlette(
            routes=[
                Route("/api/saved-queries", self.list_queries, methods=["GET"]),
                Route("/api/saved-queries/{query_id}", self.get_query, methods=["GET"]),
                Route("/api/saved-queries/{query_id}/execute", self.execute, methods=["POST"]),
                Route("/api/health", self.health, methods=["GET"]),
                Route("/api/oauth/token", self.token, methods=["POST"]),
            ]
        )

    async def _record(self, request: Request) -> None:
        self.requests.append((request.method, request.url.path, dict(request.headers), await request.body()))

    async def list_queries(self, request: Request) -> Response:
        await self._record(request)
        return JSONResponse({"queries": list(self.queries.values())})

    async def get_query(self, request: Request) -> Response:
        await self._record(request)
        query = self.queries.get(request.path_params["query_id"])
        return JSONResponse(query) if query else JSONResponse({"error": "nope"}, status_code=404)

    async def execute(self, request: Request) -> Response:
        await self._record(request)
        query_id = request.path_params["query_id"]
        body = await request.json()
        if query_id not in self.queries:
            return JSONResponse({"error": "nope"}, status_code=404)
        if query_id == "slow-report":
            try:
                await asyncio.sleep(self.slow_seconds)
            except asyncio.CancelledError:
                self.cancelled.set()
                raise
            return JSONResponse({"rows": [{"done": True}]})
        if query_id == "big-table":
            return JSONResponse({"columns": ["n"], "rows": [{"n": i} for i in range(2500)]})
        region = body.get("parameters", {}).get("region", "all")
        return JSONResponse({"columns": ["region", "total"], "rows": [{"region": region, "total": 42}]})

    async def health(self, request: Request) -> Response:
        await self._record(request)
        if not self.healthy:
            return JSONResponse({"status": "down"}, status_code=503)
        return JSONResponse({"status": "ok"})

    async def token(self, request: Request) -> Response:
        await self._record(request)
        return JSONResponse({"access_token": "upstream-token", "expires_in": 3600, "token_type": "Bearer"})


@pytest.fixture
def idp() -> FakeIdP:
    return FakeIdP()


@pytest.fixture
def upstream() -> FakeUpstream:
    return FakeUpstream()


@pytest.fixture
def make_settings() -> Callable[..., Settings]:
    def factory(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "resource_url": RESOURCE_URL,
            "oauth_issuer": ISSUER,
            "oauth_audience": [AUDIENCE],
            "upstream_base_url": UPSTREAM,
            "rate_limit_per_minute": 600,
            "rate_limit_burst": 100,
            "query_default_timeout_seconds": 2,
            "query_max_timeout_seconds": 3,
        }
        values.update(overrides)
        return Settings(_env_file=None, **values)  # type: ignore[call-arg]

    return factory


@pytest.fixture
def settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings()


@dataclass
class Harness:
    app: Starlette
    http: httpx.AsyncClient
    idp: FakeIdP
    upstream: FakeUpstream

    def auth(self, token: str | None = None, **kwargs: Any) -> dict[str, str]:
        return {"Authorization": f"Bearer {token or self.idp.token(**kwargs)}"}


class HarnessContext:
    def __init__(self, settings: Settings, idp: FakeIdP, upstream: FakeUpstream, **app_kwargs: Any) -> None:
        self.settings = settings
        self.idp = idp
        self.upstream = upstream
        self.app_kwargs = app_kwargs

    async def __aenter__(self) -> Harness:
        upstream_http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.upstream.app), base_url=UPSTREAM
        )
        idp_http = httpx.AsyncClient(transport=httpx.MockTransport(self.idp.handler))
        self.app = create_app(
            self.settings, upstream_http=upstream_http, idp_http=idp_http, **self.app_kwargs
        )
        # Run the lifespan in its own task: anyio cancel scopes must be exited by the task that entered
        # them, and pytest-asyncio may tear fixtures down from a different task.
        started, self._stop = asyncio.Event(), asyncio.Event()

        async def run_lifespan() -> None:
            async with self.app.router.lifespan_context(self.app):
                started.set()
                await self._stop.wait()

        self._lifespan_task = asyncio.create_task(run_lifespan())
        await started.wait()
        self.http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="https://spotmcp.example.com"
        )
        self._idp_http = idp_http
        return Harness(self.app, self.http, self.idp, self.upstream)

    async def __aexit__(self, *exc: object) -> None:
        await self.http.aclose()
        self._stop.set()
        await self._lifespan_task
        await self._idp_http.aclose()


@pytest.fixture
async def harness(settings: Settings, idp: FakeIdP, upstream: FakeUpstream) -> AsyncIterator[Harness]:
    async with HarnessContext(settings, idp, upstream) as h:
        yield h


INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}

MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


async def rpc(
    harness: Harness,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return await harness.http.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        headers={
            **MCP_HEADERS,
            "mcp-protocol-version": "2025-06-18",
            **(harness.auth() if headers is None else headers),
        },
    )


async def call_tool(harness: Harness, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    response = await rpc(harness, "tools/call", {"name": name, "arguments": arguments or {}})
    assert response.status_code == 200, response.text
    result: dict[str, Any] = response.json()["result"]
    return result
