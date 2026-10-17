"""OAuth 2.0 bearer-token (JWT) verification against the configured IdP."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from typing import Any

import httpx
import jwt
from jwt import PyJWK, PyJWKSet
from mcp.server.auth.provider import AccessToken

logger = logging.getLogger(__name__)


class JWKSError(Exception):
    """The signing keys could not be retrieved from the IdP."""


class JWKSCache:
    """Async, cached JWKS fetcher with throttled refresh on unknown key IDs."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        *,
        issuer: str,
        jwks_url: str | None = None,
        cache_seconds: float = 3600,
        min_refresh_seconds: float = 30,
    ) -> None:
        self._http = http
        self._issuer = issuer.rstrip("/")
        self._jwks_url = jwks_url
        self._cache_seconds = cache_seconds
        self._min_refresh_seconds = min_refresh_seconds
        self._keys: dict[str, PyJWK] = {}
        self._fetched_at: float | None = None
        self._lock = asyncio.Lock()

    async def _resolve_jwks_url(self) -> str:
        if self._jwks_url:
            return self._jwks_url
        url = f"{self._issuer}/.well-known/openid-configuration"
        response = await self._http.get(url)
        response.raise_for_status()
        jwks_uri = response.json().get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri:
            raise JWKSError("OIDC discovery document has no jwks_uri")
        self._jwks_url = jwks_uri
        return jwks_uri

    async def _refresh(self) -> None:
        try:
            url = await self._resolve_jwks_url()
            response = await self._http.get(url)
            response.raise_for_status()
            jwk_set = PyJWKSet.from_dict(response.json())
        except (httpx.HTTPError, ValueError, jwt.PyJWTError) as exc:
            raise JWKSError(f"failed to load JWKS: {exc}") from exc
        self._keys = {key.key_id: key for key in jwk_set.keys if key.key_id}
        self._fetched_at = time.monotonic()
        logger.info("loaded %d signing keys from JWKS", len(self._keys))

    def _age(self) -> float | None:
        return None if self._fetched_at is None else time.monotonic() - self._fetched_at

    async def get_key(self, kid: str) -> PyJWK | None:
        age = self._age()
        if age is not None and age < self._cache_seconds and kid in self._keys:
            return self._keys[kid]
        async with self._lock:
            age = self._age()
            stale = age is None or age >= self._cache_seconds
            # Unknown kid may mean key rotation; refresh, but not more often than min_refresh_seconds
            # so that tokens with garbage kids cannot be used to hammer the IdP.
            may_force = age is None or age >= self._min_refresh_seconds
            if stale or (kid not in self._keys and may_force):
                await self._refresh()
            return self._keys.get(kid)


_KTY_FOR_ALG_PREFIX = {"RS": "RSA", "PS": "RSA", "ES": "EC", "Ed": "OKP"}


def _key_allows(key: PyJWK, alg: str) -> bool:
    """The token's alg must fit the key type, and match the key's declared ``alg`` if it has one."""
    declared = key._jwk_data.get("alg")
    if declared:
        return bool(declared == alg)
    return _KTY_FOR_ALG_PREFIX.get(alg[:2]) == key._jwk_data.get("kty")


def _scopes(claims: dict[str, Any]) -> list[str]:
    raw = claims.get("scope", claims.get("scp"))
    if isinstance(raw, str):
        return raw.split()
    if isinstance(raw, list):
        return [str(s) for s in raw]
    return []


class JWTTokenVerifier:
    """Implements the MCP SDK ``TokenVerifier`` protocol for IdP-issued JWT access tokens."""

    def __init__(
        self,
        jwks: JWKSCache,
        *,
        issuer: str,
        audience: Sequence[str],
        algorithms: Sequence[str],
        client_id_claims: Sequence[str] = ("client_id", "azp", "cid", "appid"),
        leeway_seconds: int = 30,
    ) -> None:
        self._jwks = jwks
        self._issuer = issuer
        self._audience = list(audience)
        self._algorithms = list(algorithms)
        self._client_id_claims = list(client_id_claims)
        self._leeway = leeway_seconds

    def client_id_from_claims(self, claims: dict[str, Any]) -> str | None:
        for claim in [*self._client_id_claims, "sub"]:
            value = claims.get(claim)
            if isinstance(value, str) and value:
                return value
        return None

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            logger.info("rejected token: malformed header")
            return None
        alg = header.get("alg")
        kid = header.get("kid")
        if alg not in self._algorithms:
            logger.info("rejected token: algorithm %r not allowed", alg)
            return None
        if not isinstance(kid, str) or not kid:
            logger.info("rejected token: missing kid")
            return None
        try:
            key = await self._jwks.get_key(kid)
        except JWKSError:
            logger.exception("could not load JWKS")
            return None
        if key is None:
            logger.info("rejected token: unknown kid %r", kid)
            return None
        if not _key_allows(key, alg):
            logger.info("rejected token: alg %r not usable with key %r", alg, kid)
            return None
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key.key,
                algorithms=[alg],
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iss", "aud"], "verify_signature": True},
            )
        except (jwt.PyJWTError, TypeError, ValueError) as exc:
            logger.info("rejected token: %s", exc)
            return None

        client_id = self.client_id_from_claims(claims)
        if client_id is None:
            logger.info("rejected token: no client identifier claim")
            return None
        aud = claims.get("aud")
        resource = aud if isinstance(aud, str) else next((a for a in aud or [] if a in self._audience), None)
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=_scopes(claims),
            expires_at=int(claims["exp"]),
            resource=resource,
            subject=claims.get("sub"),
            claims=claims,
        )
