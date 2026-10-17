from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from typing import Any

import pytest

from spotmcp.config import Settings
from spotmcp.tools import effective_timeout, truncate_rows
from spotmcp.upstream import UpstreamClient
from tests.conftest import FakeIdP, FakeUpstream, Harness, HarnessContext, call_tool, rpc


def error_text(result: dict[str, Any]) -> str:
    assert result["isError"] is True, result
    return str(result["content"][0]["text"])


async def test_tools_are_all_read_only(harness: Harness) -> None:
    response = await rpc(harness, "tools/list")
    tools = response.json()["result"]["tools"]
    assert {t["name"] for t in tools} == {
        "list_saved_queries",
        "get_saved_query",
        "run_saved_query",
        "check_upstream_health",
    }
    for tool in tools:
        assert tool["annotations"]["readOnlyHint"] is True
        assert tool["annotations"]["destructiveHint"] is False


async def test_list_saved_queries(harness: Harness) -> None:
    result = await call_tool(harness, "list_saved_queries")
    assert not result["isError"]
    ids = {q["id"] for q in result["structuredContent"]["queries"]["queries"]}
    assert ids == {"sales-by-region", "slow-report", "big-table"}


async def test_get_saved_query(harness: Harness) -> None:
    result = await call_tool(harness, "get_saved_query", {"query_id": "sales-by-region"})
    assert result["structuredContent"]["query"]["name"] == "Sales by region"


async def test_get_unknown_query(harness: Harness) -> None:
    result = await call_tool(harness, "get_saved_query", {"query_id": "nope"})
    assert "not found" in error_text(result)


async def test_run_saved_query_passes_parameters(harness: Harness) -> None:
    result = await call_tool(
        harness, "run_saved_query", {"query_id": "sales-by-region", "parameters": {"region": "west"}}
    )
    content = result["structuredContent"]
    assert content["query_id"] == "sales-by-region"
    assert content["row_count"] == 1
    assert content["truncated"] is False
    assert content["result"]["rows"] == [{"region": "west", "total": 42}]
    method, path, _, body = harness.upstream.requests[-1]
    assert (method, path) == ("POST", "/api/saved-queries/sales-by-region/execute")
    assert json.loads(body) == {"parameters": {"region": "west"}}


async def test_run_unknown_query(harness: Harness) -> None:
    result = await call_tool(harness, "run_saved_query", {"query_id": "nope"})
    assert "not found" in error_text(result)


async def test_run_saved_query_times_out_and_cancels_upstream(harness: Harness) -> None:
    started = time.monotonic()
    result = await call_tool(harness, "run_saved_query", {"query_id": "slow-report", "timeout_seconds": 0.3})
    elapsed = time.monotonic() - started
    assert "timed out after 0.3s" in error_text(result)
    assert elapsed < 2.0
    await asyncio.wait_for(harness.upstream.cancelled.wait(), timeout=2)


async def test_default_timeout_applies(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: FakeUpstream
) -> None:
    settings = make_settings(query_default_timeout_seconds=0.2, query_max_timeout_seconds=1)
    async with HarnessContext(settings, idp, upstream) as h:
        result = await call_tool(h, "run_saved_query", {"query_id": "slow-report"})
        assert "timed out after 0.2s" in error_text(result)


async def test_requested_timeout_is_capped_at_max(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: FakeUpstream
) -> None:
    settings = make_settings(query_default_timeout_seconds=0.1, query_max_timeout_seconds=0.3)
    async with HarnessContext(settings, idp, upstream) as h:
        started = time.monotonic()
        result = await call_tool(h, "run_saved_query", {"query_id": "slow-report", "timeout_seconds": 60})
        assert "timed out after 0.3s" in error_text(result)
        assert time.monotonic() - started < 2.0


async def test_query_finishing_within_timeout_succeeds(harness: Harness) -> None:
    harness.upstream.slow_seconds = 0.05
    result = await call_tool(harness, "run_saved_query", {"query_id": "slow-report", "timeout_seconds": 2})
    assert result["structuredContent"]["result"]["rows"] == [{"done": True}]


@pytest.mark.parametrize("timeout", [0, -1])
async def test_non_positive_timeout_rejected(harness: Harness, timeout: float) -> None:
    result = await call_tool(
        harness, "run_saved_query", {"query_id": "slow-report", "timeout_seconds": timeout}
    )
    assert result["isError"]
    assert not any(r[1].endswith("/execute") for r in harness.upstream.requests)


async def test_rows_are_truncated(harness: Harness) -> None:
    result = await call_tool(harness, "run_saved_query", {"query_id": "big-table"})
    content = result["structuredContent"]
    assert content["truncated"] is True
    assert content["row_count"] == 2500
    assert len(content["result"]["rows"]) == 1000


@pytest.mark.parametrize("query_id", ["../admin", "a/b", "x?y=1", "..", "", "a" * 200, "%2e%2e"])
async def test_invalid_query_ids_never_reach_upstream(harness: Harness, query_id: str) -> None:
    result = await call_tool(harness, "run_saved_query", {"query_id": query_id})
    assert "invalid query_id" in error_text(result)
    assert harness.upstream.requests == []


async def test_allow_list_restricts_queries(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: FakeUpstream
) -> None:
    settings = make_settings(allowed_query_ids="sales-by-region")
    async with HarnessContext(settings, idp, upstream) as h:
        listing = await call_tool(h, "list_saved_queries")
        assert [q["id"] for q in listing["structuredContent"]["queries"]] == ["sales-by-region"]
        denied = await call_tool(h, "run_saved_query", {"query_id": "big-table"})
        assert "not available" in error_text(denied)
        denied = await call_tool(h, "get_saved_query", {"query_id": "big-table"})
        assert "not available" in error_text(denied)
        ok = await call_tool(h, "run_saved_query", {"query_id": "sales-by-region"})
        assert not ok["isError"]


async def test_health_tool(harness: Harness) -> None:
    result = await call_tool(harness, "check_upstream_health")
    assert result["structuredContent"] == {"healthy": True, "detail": {"status": "ok"}}
    harness.upstream.healthy = False
    result = await call_tool(harness, "check_upstream_health")
    assert result["structuredContent"]["healthy"] is False
    assert "503" in result["structuredContent"]["error"]


async def test_upstream_errors_surface_as_tool_errors(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: FakeUpstream
) -> None:
    settings = make_settings(upstream_list_path="/missing", upstream_run_path="/health")
    async with HarnessContext(settings, idp, upstream) as h:
        result = await call_tool(h, "list_saved_queries")
        assert "not found" in error_text(result) or "HTTP" in error_text(result)
        result = await call_tool(h, "run_saved_query", {"query_id": "x"})
        assert "HTTP 405" in error_text(result)
        upstream.queries.clear()
        result = await call_tool(h, "get_saved_query", {"query_id": "gone"})
        assert "not found" in error_text(result)


async def test_get_mode_rejects_nested_parameters(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: FakeUpstream
) -> None:
    settings = make_settings(upstream_run_method="GET")
    async with HarnessContext(settings, idp, upstream) as h:
        result = await call_tool(h, "run_saved_query", {"query_id": "q", "parameters": {"a": {"b": 1}}})
        assert "scalar" in error_text(result)
        assert upstream.requests == []


async def test_audit_log_records_client(harness: Harness, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO", logger="spotmcp.audit")
    await call_tool(
        harness, "run_saved_query", {"query_id": "sales-by-region", "parameters": {"region": "secret-value"}}
    )
    records = [r for r in caplog.records if r.name == "spotmcp.audit"]
    audit = records[-1].audit  # type: ignore[attr-defined]
    assert audit["client_id"] == "client-a"
    assert audit["tool"] == "run_saved_query"
    assert audit["outcome"] == "ok"
    assert "secret-value" not in json.dumps(audit)  # parameter values are not logged


def test_effective_timeout(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(query_default_timeout_seconds=5, query_max_timeout_seconds=10)
    assert effective_timeout(s, None) == 5
    assert effective_timeout(s, 7) == 7
    assert effective_timeout(s, 70) == 10


def test_truncate_rows_shapes() -> None:
    assert truncate_rows([1, 2, 3], "rows", 2) == ([1, 2], 3, True)
    assert truncate_rows({"rows": [1]}, "rows", 2) == ({"rows": [1]}, 1, False)
    assert truncate_rows({"data": 1}, "rows", 2) == ({"data": 1}, None, False)
    assert truncate_rows("scalar", "rows", 2) == ("scalar", None, False)


@pytest.mark.parametrize(
    ("listing", "expected"),
    [
        ([{"id": "a"}, {"id": "b"}], [{"id": "a"}]),
        # Sibling metadata (counts, cursors) is dropped: it would reveal queries outside the allow-list.
        ({"items": [{"id": "a"}, {"id": "b"}], "total": 2}, [{"id": "a"}]),
        ({"weird": "shape", "secret": "b"}, []),
        ("text", []),
    ],
)
async def test_allow_list_listing_shapes_fail_closed(
    make_settings: Callable[..., Settings],
    idp: FakeIdP,
    upstream: FakeUpstream,
    listing: Any,
    expected: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_list(self: UpstreamClient) -> Any:
        return listing

    monkeypatch.setattr(UpstreamClient, "list_queries", fake_list)
    async with HarnessContext(make_settings(allowed_query_ids="a"), idp, upstream) as h:
        result = await call_tool(h, "list_saved_queries")
        assert result["structuredContent"]["queries"] == expected


async def test_post_mode_allows_nested_parameters(harness: Harness) -> None:
    result = await call_tool(
        harness, "run_saved_query", {"query_id": "sales-by-region", "parameters": {"filter": {"region": "x"}}}
    )
    assert not result["isError"]


async def test_max_rows_is_configurable(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: FakeUpstream
) -> None:
    async with HarnessContext(make_settings(max_rows=25), idp, upstream) as h:
        content = (await call_tool(h, "run_saved_query", {"query_id": "big-table"}))["structuredContent"]
        assert content["truncated"] is True
        assert len(content["result"]["rows"]) == 25
