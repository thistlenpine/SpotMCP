"""OAuth 2.0 bearer-token (JWT) verification against the configured IdP."""

from __future__ import annotations

import asyncio
import logging
import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from jwt import PyJWK
from mcp.server.auth.provider import AccessToken

from spotmcp.config import is_https_or_local

logger = logging.getLogger(__name__)


class JWKSError(Exception):
    """The signing keys could not be retrieved from the IdP."""


@dataclass(frozen=True)
class SigningKey:
    """A verification key plus the JWK metadata used to check it against a token's ``alg``."""

    kid: str
    kty: str
    alg: str | None
    key: Any

    def allows(self, alg: str) -> bool:
        """The token's alg must match the key's declared ``alg`` if it has one, else fit the key type."""
        if self.alg:
            return self.alg == alg
        return _KTY_FOR_ALG_PREFIX.get(alg[:2]) == self.kty


_KTY_FOR_ALG_PREFIX = {"RS": "RSA", "PS": "RSA", "ES": "EC", "Ed": "OKP"}


class JWKSCache:
    """Async, cached JWKS fetcher.

    * Keys are cached for ``cache_seconds``.
    * An unknown ``kid`` (key rotation) triggers a refresh, but refresh *attempts* - successful or not - are
      throttled to one per ``min_refresh_seconds``, so neither junk tokens nor an IdP outage can make every
      request hit the IdP.
    * If a refresh fails, previously loaded keys keep being served (stale-if-error).
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        *,
        issuer: str,
        jwks_url: str | None = None,
        cache_seconds: float = 3600,
        min_refresh_seconds: float = 30,
        allow_insecure_http: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._http = http
        self._issuer = issuer
        self._jwks_url = jwks_url
        self._cache_seconds = cache_seconds
        self._min_refresh_seconds = min_refresh_seconds
        self._allow_insecure_http = allow_insecure_http
        self._clock = clock
        self._keys: dict[str, SigningKey] = {}
        self._fetched_at: float | None = None
        self._last_attempt: float | None = None
        self._lock = asyncio.Lock()

    def _check_url(self, url: str) -> None:
        if not self._allow_insecure_http and not is_https_or_local(url):
            raise JWKSError(f"refusing non-https JWKS URL {url!r}")

    async def _resolve_jwks_url(self) -> str:
        if self._jwks_url:
            return self._jwks_url
        url = f"{self._issuer.rstrip('/')}/.well-known/openid-configuration"
        response = await self._http.get(url)
        response.raise_for_status()
        document = response.json()
        # OIDC Discovery 1.0 section 4.3: the document's issuer must be the one we asked for.
        if document.get("issuer") != self._issuer:
            raise JWKSError(f"discovery issuer {document.get('issuer')!r} does not match {self._issuer!r}")
        jwks_uri = document.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri:
            raise JWKSError("OIDC discovery document has no jwks_uri")
        self._check_url(jwks_uri)
        self._jwks_url = jwks_uri
        return jwks_uri

    @staticmethod
    def _parse(document: Any) -> dict[str, SigningKey]:
        keys: dict[str, SigningKey] = {}
        entries = document.get("keys") if isinstance(document, dict) else None
        for data in entries if isinstance(entries, list) else []:
            if not isinstance(data, dict) or data.get("use") == "enc":
                continue
            kid, kty = data.get("kid"), data.get("kty")
            if not isinstance(kid, str) or not kid or not isinstance(kty, str):
                continue
            try:
                jwk = PyJWK(data)
            except jwt.PyJWTError:
                continue  # unsupported key type / curve
            alg = data.get("alg")
            keys[kid] = SigningKey(kid=kid, kty=kty, alg=alg if isinstance(alg, str) else None, key=jwk.key)
        return keys

    async def _refresh(self) -> None:
        try:
            url = await self._resolve_jwks_url()
            self._check_url(url)
            response = await self._http.get(url)
            response.raise_for_status()
            keys = self._parse(response.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise JWKSError(f"failed to load JWKS: {exc}") from exc
        if not keys:
            raise JWKSError("JWKS contains no usable signing keys")
        self._keys = keys
        self._fetched_at = self._clock()
        logger.info("loaded %d signing keys from JWKS", len(keys))

    def _since(self, moment: float | None) -> float:
        return math.inf if moment is None else self._clock() - moment

    async def get_key(self, kid: str) -> SigningKey | None:
        if self._since(self._fetched_at) < self._cache_seconds and kid in self._keys:
            return self._keys[kid]
        async with self._lock:
            needs_refresh = self._since(self._fetched_at) >= self._cache_seconds or kid not in self._keys
            if needs_refresh and self._since(self._last_attempt) >= self._min_refresh_seconds:
                self._last_attempt = self._clock()
                try:
                    await self._refresh()
                except JWKSError:
                    if not self._keys:
                        raise
                    logger.warning("JWKS refresh failed; continuing with %d cached keys", len(self._keys))
            return self._keys.get(kid)


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
            logger.info("rejected token: algorithm %r not allowed", str(alg)[:32])
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
            logger.info("rejected token: unknown kid %r", kid[:64])
            return None
        if not key.allows(alg):
            logger.info("rejected token: alg %r not usable with key %r", alg, kid[:64])
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
