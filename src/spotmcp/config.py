"""Runtime configuration, loaded from ``SPOTMCP_*`` environment variables."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class UpstreamAuthMode(StrEnum):
    NONE = "none"
    STATIC_BEARER = "static_bearer"
    API_KEY = "api_key"
    CLIENT_CREDENTIALS = "client_credentials"


CsvList = Annotated[list[str], NoDecode]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SPOTMCP_", env_file=".env", extra="ignore")

    # --- HTTP server -------------------------------------------------------
    host: str = "0.0.0.0"  # noqa: S104 - container default; bind address is configurable
    port: int = 8080
    mcp_path: str = "/mcp"
    # Public URL of this server (the OAuth protected resource identifier), e.g. https://spotmcp.example.com/mcp
    resource_url: AnyHttpUrl
    # Accepted Host headers (DNS-rebinding protection). Empty disables the check, e.g. behind a proxy.
    allowed_hosts: CsvList = Field(default_factory=list)
    log_level: str = "INFO"

    # --- OAuth / IdP (incoming requests) ------------------------------------
    # Compared exactly against the token's `iss` claim (mind trailing slashes).
    oauth_issuer: str
    # Expected `aud` claim(s). At least one must match.
    oauth_audience: CsvList
    # If unset, discovered from {issuer}/.well-known/openid-configuration.
    oauth_jwks_url: AnyHttpUrl | None = None
    oauth_algorithms: CsvList = Field(default_factory=lambda: ["RS256", "RS384", "RS512", "ES256", "PS256"])
    oauth_required_scopes: CsvList = Field(default_factory=list)
    # Claims checked (in order) to identify the OAuth client. Falls back to `sub`.
    oauth_client_id_claims: CsvList = Field(default_factory=lambda: ["client_id", "azp", "cid", "appid"])
    oauth_leeway_seconds: int = Field(default=30, ge=0, le=300)
    oauth_jwks_cache_seconds: int = Field(default=3600, ge=60)
    # Minimum seconds between forced JWKS refreshes triggered by an unknown `kid`.
    oauth_jwks_min_refresh_seconds: int = Field(default=30, ge=1)

    # --- Rate limiting (per OAuth client) -----------------------------------
    rate_limit_per_minute: float = Field(default=60, gt=0)
    rate_limit_burst: int = Field(default=10, ge=1)
    # Per-client overrides, e.g. "svc-a=120,svc-b=10" (requests per minute).
    rate_limit_overrides: Annotated[dict[str, float], NoDecode] = Field(default_factory=dict)
    rate_limit_max_clients: int = Field(default=10_000, ge=1)

    # --- Upstream internal REST API -----------------------------------------
    upstream_base_url: AnyHttpUrl
    upstream_list_path: str = "/saved-queries"
    upstream_get_path: str = "/saved-queries/{query_id}"
    upstream_run_path: str = "/saved-queries/{query_id}/execute"
    upstream_run_method: str = "POST"
    upstream_health_path: str = "/health"
    upstream_auth_mode: UpstreamAuthMode = UpstreamAuthMode.NONE
    upstream_bearer_token: SecretStr | None = None
    upstream_api_key: SecretStr | None = None
    upstream_api_key_header: str = "X-API-Key"
    upstream_token_url: AnyHttpUrl | None = None
    upstream_client_id: str | None = None
    upstream_client_secret: SecretStr | None = None
    upstream_scope: str | None = None
    upstream_audience: str | None = None
    upstream_verify_tls: bool = True
    upstream_ca_bundle: str | None = None

    # --- Saved query execution ----------------------------------------------
    query_default_timeout_seconds: float = Field(default=30, gt=0)
    query_max_timeout_seconds: float = Field(default=120, gt=0)
    # Timeout for metadata calls (list/describe/health).
    metadata_timeout_seconds: float = Field(default=10, gt=0)
    max_rows: int = Field(default=1000, ge=1)
    max_response_bytes: int = Field(default=5 * 1024 * 1024, ge=1024)
    # Key in the upstream run response holding the result rows (used for row truncation).
    rows_field: str = "rows"
    # Optional allow-list of query IDs. Empty allows any ID the upstream exposes.
    allowed_query_ids: CsvList = Field(default_factory=list)

    @field_validator(
        "allowed_hosts",
        "oauth_audience",
        "oauth_algorithms",
        "oauth_required_scopes",
        "oauth_client_id_claims",
        "allowed_query_ids",
        mode="before",
    )
    @classmethod
    def _csv(cls, value: object) -> object:
        return _split_csv(value)

    @field_validator("rate_limit_overrides", mode="before")
    @classmethod
    def _overrides(cls, value: object) -> object:
        if isinstance(value, str):
            result: dict[str, float] = {}
            items: list[str] = _split_csv(value)  # type: ignore[assignment]
            for item in items:
                client, sep, rate = item.rpartition("=")
                if not sep or not client:
                    raise ValueError(f"invalid rate limit override {item!r}; expected client=rate")
                result[client.strip()] = float(rate)
            return result
        return value

    @field_validator("oauth_algorithms")
    @classmethod
    def _asymmetric_only(cls, value: list[str]) -> list[str]:
        allowed = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
        bad = [alg for alg in value if alg not in allowed]
        if bad:
            raise ValueError(f"unsupported or symmetric JWT algorithms: {bad}")
        if not value:
            raise ValueError("at least one JWT algorithm is required")
        return value

    @field_validator("oauth_issuer")
    @classmethod
    def _issuer(cls, value: str) -> str:
        if not value.startswith(("https://", "http://")):
            raise ValueError("oauth_issuer must be an http(s) URL")
        return value

    @field_validator("oauth_audience")
    @classmethod
    def _audience_required(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("SPOTMCP_OAUTH_AUDIENCE is required")
        return value

    @field_validator("upstream_run_method")
    @classmethod
    def _run_method(cls, value: str) -> str:
        value = value.upper()
        if value not in {"GET", "POST"}:
            raise ValueError("upstream_run_method must be GET or POST")
        return value

    @field_validator("upstream_list_path", "upstream_get_path", "upstream_run_path", "upstream_health_path")
    @classmethod
    def _path(cls, value: str) -> str:
        if not value.startswith("/") or "://" in value:
            raise ValueError("upstream paths must be relative paths starting with '/'")
        return value

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.query_default_timeout_seconds > self.query_max_timeout_seconds:
            raise ValueError("query_default_timeout_seconds must not exceed query_max_timeout_seconds")
        mode = self.upstream_auth_mode
        if mode is UpstreamAuthMode.STATIC_BEARER and not self.upstream_bearer_token:
            raise ValueError("upstream_bearer_token is required for static_bearer auth")
        if mode is UpstreamAuthMode.API_KEY and not self.upstream_api_key:
            raise ValueError("upstream_api_key is required for api_key auth")
        if mode is UpstreamAuthMode.CLIENT_CREDENTIALS and not (
            self.upstream_token_url and self.upstream_client_id and self.upstream_client_secret
        ):
            raise ValueError(
                "upstream_token_url, upstream_client_id and upstream_client_secret are required "
                "for client_credentials auth"
            )
        return self
