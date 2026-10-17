"""Read-only client for the internal saved-query REST API."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import ssl
import time
from typing import Any
from urllib.parse import quote

import httpx

from spotmcp.config import Settings, UpstreamAuthMode

logger = logging.getLogger(__name__)

QUERY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class UpstreamError(Exception):
    """A failure talking to the upstream API, safe to show to the caller."""


class UpstreamTimeoutError(UpstreamError):
    pass


class UpstreamNotFoundError(UpstreamError):
    pass


def validate_query_id(query_id: str) -> str:
    if not QUERY_ID_RE.fullmatch(query_id) or ".." in query_id:
        raise ValueError("invalid query_id: use 1-128 letters, digits, '_', '-', '.', ':'")
    return query_id


class ClientCredentialsTokenProvider:
    """Fetches and caches an M2M access token for calling the upstream API."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        *,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
        audience: str | None = None,
        clock: Any = time.monotonic,
    ) -> None:
        self._http = http
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._audience = audience
        self._clock = clock
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = asyncio.Lock()

    def invalidate(self) -> None:
        self._token = None
        self._expires_at = 0.0

    async def get_token(self) -> str:
        if self._token and self._clock() < self._expires_at:
            return self._token
        async with self._lock:
            if self._token and self._clock() < self._expires_at:
                return self._token
            data = {"grant_type": "client_credentials"}
            if self._scope:
                data["scope"] = self._scope
            if self._audience:
                data["audience"] = self._audience
            try:
                response = await self._http.post(
                    self._token_url, data=data, auth=(self._client_id, self._client_secret)
                )
                response.raise_for_status()
                payload = response.json()
                token = payload["access_token"]
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                raise UpstreamError("failed to obtain upstream access token") from exc
            expires_in = float(payload.get("expires_in", 300))
            # Refresh a little early to avoid using a token that expires in flight.
            self._expires_at = self._clock() + max(0.0, expires_in - 30)
            self._token = str(token)
            return self._token


class UpstreamClient:
    """Thin wrapper over httpx that only ever issues the configured, read-only calls."""

    def __init__(self, settings: Settings, http: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        verify: bool | ssl.SSLContext = settings.upstream_verify_tls
        if settings.upstream_verify_tls and settings.upstream_ca_bundle:
            verify = ssl.create_default_context(cafile=settings.upstream_ca_bundle)
        self._http = http or httpx.AsyncClient(
            base_url=str(settings.upstream_base_url).rstrip("/"),
            verify=verify,
            follow_redirects=False,
            timeout=httpx.Timeout(settings.query_max_timeout_seconds),
        )
        if not settings.upstream_verify_tls:
            logger.warning("TLS certificate verification for the upstream API is DISABLED")
        self._query_slots = asyncio.Semaphore(settings.max_concurrent_queries)
        self._token_provider: ClientCredentialsTokenProvider | None = None
        if settings.upstream_auth_mode is UpstreamAuthMode.CLIENT_CREDENTIALS:
            assert settings.upstream_token_url and settings.upstream_client_id
            assert settings.upstream_client_secret
            self._token_provider = ClientCredentialsTokenProvider(
                self._http,
                token_url=str(settings.upstream_token_url),
                client_id=settings.upstream_client_id,
                client_secret=settings.upstream_client_secret.get_secret_value(),
                scope=settings.upstream_scope,
                audience=settings.upstream_audience,
            )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _auth_headers(self) -> dict[str, str]:
        s = self._settings
        match s.upstream_auth_mode:
            case UpstreamAuthMode.STATIC_BEARER:
                assert s.upstream_bearer_token
                return {"Authorization": f"Bearer {s.upstream_bearer_token.get_secret_value()}"}
            case UpstreamAuthMode.API_KEY:
                assert s.upstream_api_key
                return {s.upstream_api_key_header: s.upstream_api_key.get_secret_value()}
            case UpstreamAuthMode.CLIENT_CREDENTIALS:
                assert self._token_provider
                return {"Authorization": f"Bearer {await self._token_provider.get_token()}"}
            case _:
                return {}

    @staticmethod
    def _path(template: str, query_id: str | None = None) -> str:
        if query_id is None:
            return template
        return template.replace("{query_id}", quote(validate_query_id(query_id), safe=""))

    async def _send_once(
        self, method: str, path: str, *, timeout: float, params: dict[str, Any] | None, body: Any
    ) -> tuple[int, bytes]:
        """Send one request and read at most ``max_response_bytes`` of the body."""
        headers = {"Accept": "application/json", **await self._auth_headers()}
        request = self._http.build_request(
            method, path, params=params, json=body, headers=headers, timeout=httpx.Timeout(timeout)
        )
        response = await self._http.send(request, stream=True)
        try:
            if not 200 <= response.status_code < 300:
                return response.status_code, b""
            max_bytes = self._settings.max_response_bytes
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > max_bytes:
                    raise UpstreamError(f"upstream response exceeded {max_bytes} bytes")
                chunks.append(chunk)
            return response.status_code, b"".join(chunks)
        finally:
            await response.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        timeout: float,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        slot: asyncio.Semaphore | None = None,
    ) -> Any:
        """Issue a request under a hard wall-clock deadline, which also covers waiting for a ``slot``.

        The deadline is enforced on this side: on expiry the HTTP request is cancelled and the connection
        dropped. Whether the upstream then stops its own work depends on it honouring client disconnects.
        """
        try:
            async with asyncio.timeout(timeout), slot or contextlib.nullcontext():
                status, raw = await self._send_once(method, path, timeout=timeout, params=params, body=body)
                if status == 401 and self._token_provider:
                    # Our M2M token was revoked or rotated upstream: retry once with a fresh one.
                    self._token_provider.invalidate()
                    status, raw = await self._send_once(
                        method, path, timeout=timeout, params=params, body=body
                    )
        except TimeoutError as exc:
            raise UpstreamTimeoutError(f"upstream call timed out after {timeout:g}s") from exc
        except httpx.TimeoutException as exc:
            raise UpstreamTimeoutError(f"upstream call timed out after {timeout:g}s") from exc
        except httpx.HTTPError as exc:
            logger.warning("upstream transport error: %s", type(exc).__name__)
            raise UpstreamError("upstream request failed") from exc
        if status == 404:
            raise UpstreamNotFoundError("not found")
        if not 200 <= status < 300:
            raise UpstreamError(f"upstream returned HTTP {status}")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise UpstreamError("upstream returned invalid JSON") from exc

    async def list_queries(self) -> Any:
        return await self._request(
            "GET",
            self._path(self._settings.upstream_list_path),
            timeout=self._settings.metadata_timeout_seconds,
        )

    async def get_query(self, query_id: str) -> Any:
        return await self._request(
            "GET",
            self._path(self._settings.upstream_get_path, query_id),
            timeout=self._settings.metadata_timeout_seconds,
        )

    async def run_query(self, query_id: str, parameters: dict[str, Any], *, timeout: float) -> Any:
        s = self._settings
        path = self._path(s.upstream_run_path, query_id)
        if s.upstream_run_method == "GET":
            return await self._request(
                "GET", path, timeout=timeout, params=parameters, slot=self._query_slots
            )
        return await self._request(
            "POST", path, timeout=timeout, body={"parameters": parameters}, slot=self._query_slots
        )

    async def health(self) -> Any:
        return await self._request(
            "GET",
            self._path(self._settings.upstream_health_path),
            timeout=self._settings.metadata_timeout_seconds,
        )
