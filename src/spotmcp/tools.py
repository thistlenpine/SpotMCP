"""Read-only MCP tools exposed by SpotMCP."""

from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import Iterator
from typing import Annotated, Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from spotmcp.config import Settings
from spotmcp.upstream import (
    UpstreamClient,
    UpstreamError,
    UpstreamNotFoundError,
    UpstreamTimeoutError,
    validate_query_id,
)

audit = logging.getLogger("spotmcp.audit")
logger = logging.getLogger(__name__)

READ_ONLY = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)

_SCALARS = (str, int, float, bool, type(None))


def _caller() -> str:
    token = get_access_token()
    return token.client_id if token else "anonymous"


def _audit(tool: str, outcome: str, started: float, **fields: Any) -> None:
    audit.info(
        "tool call",
        extra={
            "audit": {
                "tool": tool,
                "client_id": _caller(),
                "outcome": outcome,
                "duration_ms": round((time.monotonic() - started) * 1000, 1),
                **fields,
            }
        },
    )


def effective_timeout(settings: Settings, requested: float | None) -> float:
    """The per-call deadline: the requested value (or default), never above the configured maximum."""
    timeout = settings.query_default_timeout_seconds if requested is None else requested
    return min(timeout, settings.query_max_timeout_seconds)


def truncate_rows(result: Any, rows_field: str, max_rows: int) -> tuple[Any, int | None, bool]:
    """Cap the number of rows returned. Returns (result, row_count_before_truncation, truncated)."""
    if isinstance(result, list):
        return result[:max_rows], len(result), len(result) > max_rows
    if isinstance(result, dict) and isinstance(result.get(rows_field), list):
        rows = result[rows_field]
        if len(rows) > max_rows:
            return {**result, rows_field: rows[:max_rows]}, len(rows), True
        return result, len(rows), False
    return result, None, False


def _check_parameters(parameters: dict[str, Any], *, allow_nested: bool, reserved: str) -> None:
    if reserved in parameters:
        # The read-only flag is controlled by the server; callers cannot set or override it.
        raise ToolError(f"parameter {reserved!r} is reserved")
    for name, value in parameters.items():
        if isinstance(value, _SCALARS):
            continue
        if isinstance(value, list) and all(isinstance(v, _SCALARS) for v in value):
            continue
        if not allow_nested:
            raise ToolError(f"parameter {name!r} must be a scalar or a list of scalars")


def register_tools(server: MCPServer, settings: Settings, upstream: UpstreamClient) -> None:
    # Empty only when SPOTMCP_ALLOW_ANY_QUERY is set (enforced by Settings).
    allowed = set(settings.allowed_query_ids)
    id_field = settings.query_id_field
    in_flight: dict[str, int] = {}

    def check_id(tool: str, query_id: str, started: float) -> None:
        """Validate and authorise a query ID; rejections are audited before raising."""
        try:
            validate_query_id(query_id)
        except ValueError as exc:
            _audit(tool, "invalid_id", started, query_id=query_id[:128])
            raise ToolError(str(exc)) from exc
        if allowed and query_id not in allowed:
            _audit(tool, "denied", started, query_id=query_id)
            raise ToolError(f"saved query {query_id!r} is not available")

    def filter_listing(listing: Any) -> Any:
        if not allowed:
            return listing
        items = listing
        if isinstance(listing, dict):
            key = next(
                (k for k in ("queries", "items", "data", "results") if isinstance(listing.get(k), list)), None
            )
            items = listing[key] if key else None
        if not isinstance(items, list):
            # Unrecognised shape: fail closed rather than reveal queries outside the allow-list.
            logger.warning("unrecognised upstream listing shape; returning no queries")
            return []
        # Only the filtered items are returned: sibling metadata such as totals or pagination cursors
        # would reveal queries outside the allow-list.
        return [q for q in items if isinstance(q, dict) and str(q.get(id_field)) in allowed]

    @contextlib.contextmanager
    def client_slot(started: float, query_id: str) -> Iterator[None]:
        client = _caller()
        limit = settings.max_concurrent_queries_per_client
        if in_flight.get(client, 0) >= limit:
            _audit("run_saved_query", "throttled", started, query_id=query_id)
            raise ToolError(f"too many concurrent queries for this client (max {limit})")
        in_flight[client] = in_flight.get(client, 0) + 1
        try:
            yield
        finally:
            in_flight[client] -= 1
            if not in_flight[client]:
                del in_flight[client]

    @server.tool(
        title="List saved queries",
        description="List the saved queries available on the internal host, with their IDs, "
        "descriptions and parameters.",
        annotations=READ_ONLY,
    )
    async def list_saved_queries() -> dict[str, Any]:
        started = time.monotonic()
        try:
            listing = await upstream.list_queries()
        except UpstreamError as exc:
            _audit("list_saved_queries", "error", started, error=str(exc))
            raise ToolError(str(exc)) from exc
        _audit("list_saved_queries", "ok", started)
        return {"queries": filter_listing(listing)}

    @server.tool(
        title="Describe a saved query",
        description="Get the definition and parameter schema of one saved query by its ID.",
        annotations=READ_ONLY,
    )
    async def get_saved_query(
        query_id: Annotated[str, Field(description="ID of the saved query")],
    ) -> dict[str, Any]:
        started = time.monotonic()
        check_id("get_saved_query", query_id, started)
        try:
            query = await upstream.get_query(query_id)
        except UpstreamNotFoundError as exc:
            _audit("get_saved_query", "not_found", started, query_id=query_id)
            raise ToolError(f"saved query {query_id!r} not found") from exc
        except UpstreamError as exc:
            _audit("get_saved_query", "error", started, query_id=query_id, error=str(exc))
            raise ToolError(str(exc)) from exc
        _audit("get_saved_query", "ok", started, query_id=query_id)
        return {"query": query}

    @server.tool(
        title="Run a saved query",
        description="Execute a saved query by ID with optional parameters and return its results. "
        f"Calls are cancelled after timeout_seconds (default {settings.query_default_timeout_seconds:g}s, "
        f"max {settings.query_max_timeout_seconds:g}s); at most {settings.max_rows} rows are returned.",
        annotations=READ_ONLY,
    )
    async def run_saved_query(
        query_id: Annotated[str, Field(description="ID of the saved query to execute")],
        parameters: Annotated[
            dict[str, Any] | None, Field(description="Named parameter values for the saved query")
        ] = None,
        timeout_seconds: Annotated[
            float | None,
            Field(gt=0, description="Optional deadline in seconds; capped by the server maximum"),
        ] = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        check_id("run_saved_query", query_id, started)
        params = parameters or {}
        try:
            _check_parameters(
                params,
                allow_nested=settings.upstream_run_method == "POST",
                reserved=settings.upstream_read_only_field,
            )
        except ToolError:
            _audit("run_saved_query", "invalid_parameters", started, query_id=query_id)
            raise
        timeout = effective_timeout(settings, timeout_seconds)
        try:
            with client_slot(started, query_id):
                result = await upstream.run_query(query_id, params, timeout=timeout)
        except UpstreamTimeoutError as exc:
            _audit("run_saved_query", "timeout", started, query_id=query_id, timeout_s=timeout)
            raise ToolError(f"saved query {query_id!r} timed out after {timeout:g}s") from exc
        except UpstreamNotFoundError as exc:
            _audit("run_saved_query", "not_found", started, query_id=query_id)
            raise ToolError(f"saved query {query_id!r} not found") from exc
        except UpstreamError as exc:
            _audit("run_saved_query", "error", started, query_id=query_id, error=str(exc))
            raise ToolError(str(exc)) from exc
        result, row_count, truncated = truncate_rows(result, settings.rows_field, settings.max_rows)
        if row_count is None and result is not None:
            logger.warning(
                "query %s: no row array found (expected a list or %r); row limit not applied",
                query_id,
                settings.rows_field,
            )
        duration_ms = round((time.monotonic() - started) * 1000, 1)
        _audit("run_saved_query", "ok", started, query_id=query_id, row_count=row_count, truncated=truncated)
        return {
            "query_id": query_id,
            "duration_ms": duration_ms,
            "row_count": row_count,
            "truncated": truncated,
            "row_limit_applied": row_count is not None,
            "result": result,
        }

    @server.tool(
        title="Check internal host health",
        description="Check whether the internal saved-query API is reachable and healthy.",
        annotations=READ_ONLY,
    )
    async def check_upstream_health() -> dict[str, Any]:
        started = time.monotonic()
        try:
            detail = await upstream.health()
        except UpstreamError as exc:
            _audit("check_upstream_health", "unhealthy", started)
            return {"healthy": False, "error": str(exc)}
        _audit("check_upstream_health", "ok", started)
        return {"healthy": True, "detail": detail}
