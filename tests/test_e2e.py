"""End-to-end: real uvicorn server, official MCP client over Streamable HTTP."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import httpx2
import pytest
import uvicorn
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client

from spotmcp.app import create_app
from spotmcp.config import Settings
from tests.conftest import UPSTREAM, FakeIdP, FakeUpstream


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
async def server_url(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: FakeUpstream
) -> AsyncIterator[str]:
    port = free_port()
    settings = make_settings(
        host="127.0.0.1",
        port=port,
        allowed_hosts=f"127.0.0.1:{port}",
        rate_limit_per_minute=60,
        rate_limit_burst=8,
    )
    app = create_app(
        settings,
        upstream_http=httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream.app), base_url=UPSTREAM),
        idp_http=httpx.AsyncClient(transport=httpx.MockTransport(idp.handler)),
    )
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True
    await task


def connect(url: str, token: str) -> Any:
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=10)
    return Client(streamable_http_client(url, http_client=http))  # type: ignore[arg-type]


async def test_mcp_client_session(server_url: str, idp: FakeIdP) -> None:
    async with connect(server_url, idp.token(client_id="e2e")) as client:
        tools = await client.list_tools()
        assert {t.name for t in tools.tools} >= {"list_saved_queries", "run_saved_query"}

        result = await client.call_tool(
            "run_saved_query", {"query_id": "sales-by-region", "parameters": {"region": "emea"}}
        )
        assert not result.is_error
        assert result.structured_content["result"]["rows"][0]["region"] == "emea"

        timed_out = await client.call_tool(
            "run_saved_query", {"query_id": "slow-report", "timeout_seconds": 0.2}
        )
        assert timed_out.is_error
        assert "timed out" in timed_out.content[0].text


async def test_rejects_unauthenticated_and_wrong_host(server_url: str, idp: FakeIdP) -> None:
    async with httpx.AsyncClient() as http:
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        assert (await http.post(server_url, json=body, headers=headers)).status_code == 401
        spoofed = {**headers, "Host": "evil.example.com", "Authorization": f"Bearer {idp.token()}"}
        assert (await http.post(server_url, json=body, headers=spoofed)).status_code == 421


async def test_rate_limit_end_to_end(server_url: str, idp: FakeIdP) -> None:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {idp.token(client_id='greedy')}",
        "mcp-protocol-version": "2025-06-18",
    }
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    async with httpx.AsyncClient() as http:
        statuses = [(await http.post(server_url, json=body, headers=headers)).status_code for _ in range(10)]
    assert statuses.count(200) == 8
    assert statuses[-1] == 429
