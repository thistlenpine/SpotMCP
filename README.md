# SpotMCP

An MCP server that lets agents run **saved queries** and other **read-only** actions on an internal REST
API. It is secured with OAuth 2.0 (M2M JWTs from your IdP), rate-limited per OAuth client, and
enforces a timeout on every saved-query call.

```
MCP client ──HTTPS + Bearer JWT──▶ SpotMCP (Streamable HTTP, /mcp)
                                    │ 1. JWT validation against the IdP's JWKS (iss, aud, exp, signature)
                                    │ 2. Per-OAuth-client token-bucket rate limit → 429 + Retry-After
                                    │ 3. Read-only MCP tools
                                    │ 4. Hard per-call deadline (default 30s, max 120s), row & size caps
                                    ▼
                           Internal saved-query REST API (GET list/describe/health, run by ID)
```

## MCP tools

All tools are annotated `readOnlyHint=true`, `destructiveHint=false`.

| Tool | Description |
| --- | --- |
| `list_saved_queries` | List saved queries exposed by the internal API (filtered by `SPOTMCP_ALLOWED_QUERY_IDS` if set). |
| `get_saved_query(query_id)` | Describe a saved query, including its parameters. |
| `run_saved_query(query_id, parameters?, timeout_seconds?)` | Execute a saved query by ID. Returns `{query_id, duration_ms, row_count, truncated, result}`. |
| `check_upstream_health` | Report whether the internal API is reachable. |

SpotMCP never sends SQL or arbitrary requests upstream. It only calls the four configured endpoints. Query
IDs are validated (`[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}`, no `..`) and URL-encoded, so a caller cannot
traverse to other upstream paths. Redirects are not followed.

## Security model

**Authentication (incoming).** Every request to `/mcp` must carry `Authorization: Bearer <JWT>`.
SpotMCP acts as an OAuth 2.0 resource server, following the MCP authorization spec:

- Signature verified with keys from the IdP's JWKS (discovered from `{issuer}/.well-known/openid-configuration`
  or set via `SPOTMCP_OAUTH_JWKS_URL`). Keys are cached; an unknown `kid` triggers a refresh at most once
  every `SPOTMCP_OAUTH_JWKS_MIN_REFRESH_SECONDS` (key rotation without letting junk tokens hammer the IdP).
- Only asymmetric algorithms are accepted (`alg=none` and HS* are rejected). The token's `alg` must match the key's.
- `iss` must equal `SPOTMCP_OAUTH_ISSUER` exactly. `aud` must contain one of `SPOTMCP_OAUTH_AUDIENCE`.
  `exp` is required. `nbf` and `exp` are checked with `SPOTMCP_OAUTH_LEEWAY_SECONDS` of clock-skew allowance.
- Optional `SPOTMCP_OAUTH_REQUIRED_SCOPES` (read from `scope` or `scp`). A missing scope returns 403 `insufficient_scope`.
- A failure returns 401 with `WWW-Authenticate: Bearer ..., resource_metadata="…/.well-known/oauth-protected-resource/mcp"`.
  Protected Resource Metadata (RFC 9728) is served at that URL.

**Rate limiting.** A token bucket per OAuth client ID, which is the first of
`SPOTMCP_OAUTH_CLIENT_ID_CLAIMS` (`client_id, azp, cid, appid`) present in the token, falling back to `sub`.
This covers Okta (`cid`), Auth0/Entra/Keycloak (`azp`) and RFC 9068 (`client_id`). All tokens issued to the
same client share one budget. Over-limit requests get `429` with `Retry-After`. Overrides are set per client
(`SPOTMCP_RATE_LIMIT_OVERRIDES=svc-a=240,svc-b=10`). State is in-memory, so with several replicas each one
enforces its own limit.

**Timeouts.** Every `run_saved_query` call runs under a wall-clock deadline (`asyncio.timeout`) that covers
the whole upstream call: obtaining the upstream token, connecting, and streaming the response. The httpx
timeout is set to the same value. The deadline is `timeout_seconds` if given, otherwise
`SPOTMCP_QUERY_DEFAULT_TIMEOUT_SECONDS`, and is always capped at `SPOTMCP_QUERY_MAX_TIMEOUT_SECONDS`. When it
expires, the in-flight upstream request is cancelled and the tool returns an error. Metadata calls use
`SPOTMCP_METADATA_TIMEOUT_SECONDS`.

**Result limits.** Responses over `SPOTMCP_MAX_RESPONSE_BYTES` are aborted while streaming. Row arrays (a
top-level list, or the `SPOTMCP_ROWS_FIELD` key) are truncated to `SPOTMCP_MAX_ROWS`, and the result is
flagged `truncated: true`.

**Upstream credentials.** `SPOTMCP_UPSTREAM_AUTH_MODE` is one of `none`, `static_bearer`, `api_key`, or
`client_credentials`. With `client_credentials`, SpotMCP fetches its own M2M token from the IdP and caches
it until 30s before expiry. Caller tokens are **never** forwarded upstream.

**Audit logging.** Logs are JSON lines on stdout. Each tool call logs `tool`, `client_id`, `outcome`,
`duration_ms` and `query_id`. Parameter values and tokens are not logged.

**Other protections.** DNS-rebinding/Host-header checks (`SPOTMCP_ALLOWED_HOSTS`), and the container runs
as non-root user 10001.

## Configuration

All settings are environment variables prefixed `SPOTMCP_` (a `.env` file is also read). See
[`.env.example`](.env.example) for the full list. These are required:

| Variable | Example |
| --- | --- |
| `SPOTMCP_RESOURCE_URL` | `https://spotmcp.example.com/mcp` |
| `SPOTMCP_OAUTH_ISSUER` | `https://idp.example.com/oauth2/default` |
| `SPOTMCP_OAUTH_AUDIENCE` | `api://spotmcp` |
| `SPOTMCP_UPSTREAM_BASE_URL` | `https://internal.example.com/api` |

The upstream endpoints default to these, and you can change them to match your API:

| Purpose | Default | Variable |
| --- | --- | --- |
| List | `GET /saved-queries` | `SPOTMCP_UPSTREAM_LIST_PATH` |
| Describe | `GET /saved-queries/{query_id}` | `SPOTMCP_UPSTREAM_GET_PATH` |
| Run | `POST /saved-queries/{query_id}/execute` with body `{"parameters": {...}}` | `SPOTMCP_UPSTREAM_RUN_PATH`, `SPOTMCP_UPSTREAM_RUN_METHOD` (`POST`/`GET`; `GET` sends parameters as query string) |
| Health | `GET /health` | `SPOTMCP_UPSTREAM_HEALTH_PATH` |

## Running

```bash
# Local
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # edit
spotmcp                # serves http://0.0.0.0:8080/mcp

# Container
docker build -t spotmcp .
docker run --rm -p 8080:8080 --env-file .env spotmcp
```

`GET /healthz` is an unauthenticated liveness endpoint, used by the container `HEALTHCHECK`. Terminate
TLS at your ingress or load balancer.

### Connecting a client

Clients obtain a token with the client-credentials grant and send it on every request:

```python
import httpx2
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client

http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"})
async with Client(streamable_http_client("https://spotmcp.example.com/mcp", http_client=http)) as client:
    result = await client.call_tool(
        "run_saved_query", {"query_id": "sales-by-region", "parameters": {"region": "emea"}}
    )
```

## Development

```bash
ruff check . && ruff format --check . && mypy && pytest --cov
```

The tests use an in-process fake IdP (RSA-signed JWTs, JWKS, discovery) and a fake upstream API. They cover
token validation, key rotation, rate limiting, timeouts and cancellation, truncation, and input validation.
An end-to-end test runs uvicorn and drives the server with the official MCP client.

## CI/CD

`.github/workflows/ci.yml` runs on every push and pull request:

1. **test**: ruff lint and format checks, mypy (strict), and pytest with coverage (at least 90% required).
2. **container**: builds the image, smoke-tests it (healthz returns 200, unauthenticated `/mcp` returns 401,
   runs as non-root), then on pushes to `main` or `v*` tags publishes to `ghcr.io/<owner>/spotmcp`.
   Pull requests build and test the image but do not push it.
