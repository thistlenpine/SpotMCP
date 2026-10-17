from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx
import jwt
import pytest

from spotmcp.auth import JWKSCache, JWKSError, JWTTokenVerifier
from spotmcp.config import Settings
from tests.conftest import AUDIENCE, INIT, ISSUER, MCP_HEADERS, FakeIdP, Harness, HarnessContext, SigningKey


def make_verifier(idp: FakeIdP, **kwargs: Any) -> JWTTokenVerifier:
    jwks = JWKSCache(
        httpx.AsyncClient(transport=httpx.MockTransport(idp.handler)),
        issuer=ISSUER,
        min_refresh_seconds=kwargs.pop("min_refresh_seconds", 30),
    )
    return JWTTokenVerifier(
        jwks,
        issuer=kwargs.pop("issuer", ISSUER),
        audience=kwargs.pop("audience", [AUDIENCE]),
        algorithms=kwargs.pop("algorithms", ["RS256"]),
        **kwargs,
    )


# --- verifier unit tests ------------------------------------------------------


async def test_valid_token_is_accepted(idp: FakeIdP) -> None:
    verifier = make_verifier(idp)
    token = await verifier.verify_token(idp.token(client_id="svc-1"))
    assert token is not None
    assert token.client_id == "svc-1"
    assert token.scopes == ["spotmcp.read"]
    assert token.resource == AUDIENCE
    assert token.subject == "svc-1"
    assert idp.discovery_requests == 1


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"iss": "https://evil.example.com"}, "wrong issuer"),
        ({"aud": "api://other"}, "wrong audience"),
        ({"aud": None}, "missing audience"),
        ({"exp": int(time.time()) - 3600}, "expired"),
        ({"exp": None}, "missing exp"),
        ({"nbf": int(time.time()) + 3600}, "not yet valid"),
        ({"cid": None, "sub": None}, "no client identifier"),
    ],
)
async def test_invalid_claims_are_rejected(idp: FakeIdP, overrides: dict[str, Any], reason: str) -> None:
    verifier = make_verifier(idp)
    assert await verifier.verify_token(idp.token(**overrides)) is None, reason


async def test_leeway_allows_small_clock_skew(idp: FakeIdP) -> None:
    verifier = make_verifier(idp, leeway_seconds=30)
    assert await verifier.verify_token(idp.token(exp=int(time.time()) - 10)) is not None


async def test_audience_list_is_accepted(idp: FakeIdP) -> None:
    verifier = make_verifier(idp)
    token = await verifier.verify_token(idp.token(aud=["api://other", AUDIENCE]))
    assert token is not None and token.resource == AUDIENCE


async def test_bad_signature_is_rejected(idp: FakeIdP) -> None:
    impostor = SigningKey("key-1")  # same kid, different key material
    verifier = make_verifier(idp)
    assert await verifier.verify_token(idp.token(key=impostor)) is None


async def test_tampered_payload_is_rejected(idp: FakeIdP) -> None:
    verifier = make_verifier(idp)
    header, _, signature = idp.token(client_id="a").split(".")
    forged = jwt.utils.base64url_encode(
        b'{"iss":"%s","aud":"%s","exp":9999999999,"cid":"admin"}' % (ISSUER.encode(), AUDIENCE.encode())
    ).decode()
    assert await verifier.verify_token(f"{header}.{forged}.{signature}") is None


async def test_alg_none_is_rejected(idp: FakeIdP) -> None:
    verifier = make_verifier(idp)
    claims = {"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 60, "cid": "x"}
    token = jwt.encode(claims, key=None, algorithm="none", headers={"kid": "key-1"})
    assert await verifier.verify_token(token) is None


async def test_hs256_key_confusion_is_rejected(idp: FakeIdP) -> None:
    verifier = make_verifier(idp, algorithms=["RS256"])
    claims = {"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 60, "cid": "x"}
    token = jwt.encode(
        claims, key="secret-secret-secret-secret-secret!", algorithm="HS256", headers={"kid": "key-1"}
    )
    assert await verifier.verify_token(token) is None


async def test_alg_must_match_key_alg(idp: FakeIdP) -> None:
    verifier = make_verifier(idp, algorithms=["RS256", "PS256"])
    claims = {"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 60, "cid": "x"}
    token = jwt.encode(claims, idp.keys[0].private, algorithm="PS256", headers={"kid": "key-1"})
    assert await verifier.verify_token(token) is None


@pytest.mark.parametrize("token", ["", "garbage", "a.b.c", "Bearer x"])
async def test_malformed_tokens_are_rejected(idp: FakeIdP, token: str) -> None:
    assert await make_verifier(idp).verify_token(token) is None


async def test_missing_kid_is_rejected(idp: FakeIdP) -> None:
    claims = {"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 60, "cid": "x"}
    token = jwt.encode(claims, idp.keys[0].private, algorithm="RS256")
    assert await make_verifier(idp).verify_token(token) is None


async def test_key_rotation_triggers_jwks_refresh(idp: FakeIdP) -> None:
    verifier = make_verifier(idp, min_refresh_seconds=1)
    assert await verifier.verify_token(idp.token()) is not None
    new_key = SigningKey("key-2")
    idp.keys.append(new_key)
    # Within min_refresh_seconds an unknown kid does not trigger a refresh...
    assert await verifier.verify_token(idp.token(key=new_key)) is None
    assert idp.jwks_requests == 1
    verifier._jwks._fetched_at -= 2  # type: ignore[operator]
    # ...after it, the JWKS is re-fetched and the rotated key is accepted.
    assert await verifier.verify_token(idp.token(key=new_key)) is not None
    assert idp.jwks_requests == 2


async def test_unknown_kid_cannot_hammer_idp(idp: FakeIdP) -> None:
    verifier = make_verifier(idp)
    rogue = SigningKey("rogue")
    for _ in range(20):
        assert await verifier.verify_token(idp.token(key=rogue)) is None
    assert idp.jwks_requests == 1


async def test_jwks_cached_between_calls(idp: FakeIdP) -> None:
    verifier = make_verifier(idp)
    for _ in range(5):
        assert await verifier.verify_token(idp.token()) is not None
    assert idp.jwks_requests == 1


async def test_jwks_unavailable_rejects_token() -> None:
    idp = FakeIdP()
    jwks = JWKSCache(
        httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500))), issuer=ISSUER
    )
    verifier = JWTTokenVerifier(jwks, issuer=ISSUER, audience=[AUDIENCE], algorithms=["RS256"])
    assert await verifier.verify_token(idp.token()) is None


async def test_discovery_without_jwks_uri_errors() -> None:
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    with pytest.raises(JWKSError):
        await JWKSCache(http, issuer=ISSUER).get_key("k")


async def test_explicit_jwks_url_skips_discovery(idp: FakeIdP) -> None:
    jwks = JWKSCache(
        httpx.AsyncClient(transport=httpx.MockTransport(idp.handler)),
        issuer=ISSUER,
        jwks_url=f"{ISSUER}/v1/keys",
    )
    assert await jwks.get_key("key-1") is not None
    assert idp.discovery_requests == 0


@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        ({"client_id": "a", "azp": "b", "cid": "c", "sub": "d"}, "a"),
        ({"azp": "b", "cid": "c", "sub": "d"}, "b"),
        ({"cid": "c", "sub": "d"}, "c"),
        ({"appid": "e", "sub": "d"}, "e"),
        ({"sub": "d"}, "d"),
        ({}, None),
    ],
)
def test_client_id_claim_precedence(idp: FakeIdP, claims: dict[str, Any], expected: str | None) -> None:
    assert make_verifier(idp).client_id_from_claims(claims) == expected


async def test_scope_string_claim(idp: FakeIdP) -> None:
    token = await make_verifier(idp).verify_token(idp.token(scp=None, scope="a b"))
    assert token is not None and token.scopes == ["a", "b"]


# --- HTTP-level tests ---------------------------------------------------------


async def test_missing_token_returns_401_with_resource_metadata(harness: Harness) -> None:
    response = await harness.http.post("/mcp", json=INIT, headers=MCP_HEADERS)
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith("Bearer ")
    assert (
        'resource_metadata="https://spotmcp.example.com/.well-known/oauth-protected-resource/mcp"'
        in challenge
    )


async def test_invalid_token_returns_401(harness: Harness) -> None:
    response = await harness.http.post(
        "/mcp", json=INIT, headers={**MCP_HEADERS, **harness.auth(harness.idp.token(aud="api://other"))}
    )
    assert response.status_code == 401


async def test_non_bearer_scheme_returns_401(harness: Harness) -> None:
    response = await harness.http.post(
        "/mcp", json=INIT, headers={**MCP_HEADERS, "Authorization": "Basic dXNlcjpwYXNz"}
    )
    assert response.status_code == 401


async def test_valid_token_initializes(harness: Harness) -> None:
    response = await harness.http.post("/mcp", json=INIT, headers={**MCP_HEADERS, **harness.auth()})
    assert response.status_code == 200
    assert response.json()["result"]["serverInfo"]["name"] == "spotmcp"


async def test_protected_resource_metadata(harness: Harness) -> None:
    response = await harness.http.get("/.well-known/oauth-protected-resource/mcp")
    assert response.status_code == 200
    body = response.json()
    assert body["resource"] == "https://spotmcp.example.com/mcp"
    assert body["authorization_servers"] == [ISSUER]


async def test_healthz_does_not_require_auth(harness: Harness) -> None:
    response = await harness.http.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_required_scope_enforced(
    make_settings: Callable[..., Settings], idp: FakeIdP, upstream: Any
) -> None:
    settings = make_settings(oauth_required_scopes=["spotmcp.read"])
    async with HarnessContext(settings, idp, upstream) as h:
        ok = await h.http.post("/mcp", json=INIT, headers={**MCP_HEADERS, **h.auth()})
        assert ok.status_code == 200
        denied = await h.http.post(
            "/mcp", json=INIT, headers={**MCP_HEADERS, **h.auth(h.idp.token(scp=["other"]))}
        )
        assert denied.status_code == 403
        assert 'error="insufficient_scope"' in denied.headers["www-authenticate"]


async def test_ps256_accepted_for_rsa_key_without_declared_alg(idp: FakeIdP) -> None:
    key = idp.keys[0]
    original = key.jwk

    def jwk_without_alg() -> dict[str, Any]:
        data = original()
        data.pop("alg")
        return data

    key.jwk = jwk_without_alg  # type: ignore[method-assign]
    verifier = make_verifier(idp, algorithms=["RS256", "PS256", "ES256"])
    claims = {"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 60, "cid": "x"}
    ps = jwt.encode(claims, key.private, algorithm="PS256", headers={"kid": "key-1"})
    assert await verifier.verify_token(ps) is not None
    # An EC algorithm can never be used with an RSA key.
    from cryptography.hazmat.primitives.asymmetric import ec

    es = jwt.encode(
        claims, ec.generate_private_key(ec.SECP256R1()), algorithm="ES256", headers={"kid": "key-1"}
    )
    assert await verifier.verify_token(es) is None


async def test_unexpected_decode_errors_reject_instead_of_crashing(
    idp: FakeIdP, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = make_verifier(idp)

    def explode(*args: Any, **kwargs: Any) -> Any:
        raise TypeError("Expecting a PEM-formatted key.")

    monkeypatch.setattr(jwt, "decode", explode)
    assert await verifier.verify_token(idp.token()) is None
