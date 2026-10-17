from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError

from spotmcp.config import Settings, UpstreamAuthMode


def test_defaults(settings: Settings) -> None:
    assert settings.rate_limit_burst == 100
    assert settings.oauth_algorithms[0] == "RS256"
    assert settings.upstream_auth_mode is UpstreamAuthMode.NONE
    assert settings.max_rows == 1000


def test_env_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    env = {
        "SPOTMCP_RESOURCE_URL": "https://spot.example.com/mcp",
        "SPOTMCP_OAUTH_ISSUER": "https://idp.example.com/",
        "SPOTMCP_OAUTH_AUDIENCE": "api://a, api://b",
        "SPOTMCP_OAUTH_REQUIRED_SCOPES": "spot.read",
        "SPOTMCP_UPSTREAM_BASE_URL": "https://internal/api",
        "SPOTMCP_RATE_LIMIT_OVERRIDES": "svc-a=120, svc-b=5",
        "SPOTMCP_ALLOWED_QUERY_IDS": "q1,q2",
        "SPOTMCP_ALLOWED_HOSTS": "spot.example.com",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.oauth_issuer == "https://idp.example.com/"  # exact, trailing slash preserved
    assert s.oauth_audience == ["api://a", "api://b"]
    assert s.oauth_required_scopes == ["spot.read"]
    assert s.rate_limit_overrides == {"svc-a": 120.0, "svc-b": 5.0}
    assert s.allowed_query_ids == ["q1", "q2"]
    assert s.allowed_hosts == ["spot.example.com"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"oauth_audience": ""},
        {"oauth_algorithms": "HS256"},
        {"oauth_algorithms": "none"},
        {"oauth_algorithms": ""},
        {"oauth_issuer": "idp.example.com"},
        {"rate_limit_overrides": "novalue"},
        {"rate_limit_per_minute": 0},
        {"upstream_run_method": "DELETE"},
        {"upstream_run_path": "https://evil.example.com/x"},
        {"upstream_list_path": "relative"},
        {"query_default_timeout_seconds": 10, "query_max_timeout_seconds": 5},
        {"upstream_auth_mode": "static_bearer"},
        {"upstream_auth_mode": "api_key"},
        {"upstream_auth_mode": "client_credentials", "upstream_client_id": "x"},
    ],
)
def test_invalid_settings(make_settings: Callable[..., Settings], overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_settings(**overrides)


def test_secrets_not_in_repr(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(upstream_auth_mode="static_bearer", upstream_bearer_token="super-secret")
    assert "super-secret" not in repr(s)
