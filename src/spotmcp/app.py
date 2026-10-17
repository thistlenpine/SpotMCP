"""ASGI application factory."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator

import httpx
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from spotmcp import __version__
from spotmcp.auth import JWKSCache, JWTTokenVerifier
from spotmcp.config import Settings
from spotmcp.logging_config import quiet_transport_loggers
from spotmcp.ratelimit import RateLimiter, RateLimitMiddleware
from spotmcp.tools import register_tools
from spotmcp.upstream import UpstreamClient

INSTRUCTIONS = (
    "SpotMCP exposes read-only access to saved queries on an internal host. Use list_saved_queries to "
    "discover queries, get_saved_query to inspect parameters, and run_saved_query to execute one."
)


def _check_middleware_order(app: Starlette) -> None:
    """Fail fast if an SDK/Starlette change would make the rate limiter run before authentication.

    Rate limiting is keyed on the authenticated client, so it must sit inside AuthenticationMiddleware, and
    the middleware stack must not have been built yet (Starlette builds it lazily on first request).
    """
    classes: list[object] = [m.cls for m in app.user_middleware]
    if (
        app.middleware_stack is not None
        or AuthenticationMiddleware not in classes
        or classes.index(AuthenticationMiddleware) > classes.index(RateLimitMiddleware)
    ):
        raise RuntimeError("unexpected middleware layout: rate limiting would not run after authentication")


def create_app(
    settings: Settings,
    *,
    upstream_http: httpx.AsyncClient | None = None,
    idp_http: httpx.AsyncClient | None = None,
    limiter: RateLimiter | None = None,
) -> Starlette:
    quiet_transport_loggers()
    idp_client = idp_http or httpx.AsyncClient(timeout=httpx.Timeout(10.0), follow_redirects=False)
    jwks = JWKSCache(
        idp_client,
        issuer=settings.oauth_issuer,
        jwks_url=str(settings.oauth_jwks_url) if settings.oauth_jwks_url else None,
        cache_seconds=settings.oauth_jwks_cache_seconds,
        min_refresh_seconds=settings.oauth_jwks_min_refresh_seconds,
        allow_insecure_http=settings.allow_insecure_http,
    )
    verifier = JWTTokenVerifier(
        jwks,
        issuer=settings.oauth_issuer,
        audience=settings.oauth_audience,
        algorithms=settings.oauth_algorithms,
        client_id_claims=settings.oauth_client_id_claims,
        leeway_seconds=settings.oauth_leeway_seconds,
    )
    upstream = UpstreamClient(settings, http=upstream_http)

    server: MCPServer = MCPServer(
        name=settings.server_name,
        title=settings.server_title,
        version=__version__,
        instructions=INSTRUCTIONS,
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=settings.oauth_issuer,  # type: ignore[arg-type]
            resource_server_url=settings.resource_url,
            required_scopes=settings.oauth_required_scopes or None,
            # Audience is validated by the JWT verifier itself.
            validate_token_resource=False,
        ),
        log_level=settings.log_level.upper(),  # type: ignore[arg-type]
    )
    register_tools(server, settings, upstream)

    @server.custom_route("/healthz", methods=["GET"], include_in_schema=False)  # type: ignore[untyped-decorator]
    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok", "version": __version__})

    security = (
        TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=settings.allowed_hosts,
            allowed_origins=[],
        )
        if settings.allowed_hosts
        else TransportSecuritySettings(enable_dns_rebinding_protection=False)
    )
    app = server.streamable_http_app(
        streamable_http_path=settings.mcp_path,
        stateless_http=True,
        json_response=True,
        transport_security=security,
        host=settings.host,
        max_request_body_size=settings.max_request_body_bytes,
    )
    # Appended last => innermost, i.e. after the SDK's AuthenticationMiddleware has set scope["user"],
    # so requests are limited per authenticated OAuth client.
    app.user_middleware.append(
        Middleware(
            RateLimitMiddleware,
            limiter=limiter
            or RateLimiter(
                per_minute=settings.rate_limit_per_minute,
                burst=settings.rate_limit_burst,
                overrides=settings.rate_limit_overrides,
                max_keys=settings.rate_limit_max_clients,
            ),
            path=settings.mcp_path,
        )
    )

    _check_middleware_order(app)

    sdk_lifespan = app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def lifespan(a: Starlette) -> AsyncIterator[None]:
        try:
            async with sdk_lifespan(a):
                yield
        finally:
            await upstream.aclose()
            if idp_http is None:
                await idp_client.aclose()

    app.router.lifespan_context = lifespan
    return app
