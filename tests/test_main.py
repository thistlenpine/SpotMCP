from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from spotmcp import main as main_module
from spotmcp.logging_config import JSONFormatter, configure_logging


def test_main_runs_uvicorn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPOTMCP_RESOURCE_URL", "https://spot.example.com/mcp")
    monkeypatch.setenv("SPOTMCP_OAUTH_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("SPOTMCP_OAUTH_AUDIENCE", "api://spot")
    monkeypatch.setenv("SPOTMCP_UPSTREAM_BASE_URL", "https://internal/api")
    monkeypatch.setenv("SPOTMCP_PORT", "9999")
    calls: dict[str, Any] = {}
    monkeypatch.setattr(main_module.uvicorn, "run", lambda app, **kw: calls.update(app=app, **kw))
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    try:
        main_module.main()
    finally:
        root.handlers[:], root.level = saved[0], saved[1]
    assert calls["port"] == 9999
    assert calls["host"] == "0.0.0.0"
    assert calls["server_header"] is False


def test_json_formatter_includes_audit_fields() -> None:
    record = logging.LogRecord("spotmcp.audit", logging.INFO, __file__, 1, "tool call", None, None)
    record.audit = {"client_id": "c1", "tool": "t"}
    out = json.loads(JSONFormatter().format(record))
    assert out["msg"] == "tool call"
    assert out["client_id"] == "c1"
    assert out["level"] == "INFO"


def test_json_formatter_exceptions() -> None:
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        import sys

        record = logging.LogRecord("x", logging.ERROR, __file__, 1, "failed", None, sys.exc_info())
    assert "RuntimeError: boom" in json.loads(JSONFormatter().format(record))["exc"]


def test_configure_logging_sets_level() -> None:
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    try:
        configure_logging("warning")
        assert root.level == logging.WARNING
        assert isinstance(root.handlers[0].formatter, JSONFormatter)
    finally:
        root.handlers[:], root.level = saved[0], saved[1]
