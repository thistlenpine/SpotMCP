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

| Tool | Description |
| --- | --- |
| `list_saved_queries` | List the allow-listed saved queries exposed by the internal API. |
| `get_saved_query(query_id)` | Describe a saved query, including its parameters. |
| `run_saved_query(query_id, parameters?, timeout_seconds?)` | Execute a saved query by ID. Returns `{query_id, duration_ms, row_count, truncated, row_limit_applied, result}`. |
| `check_upstream_health` | Report whether the internal API is reachable. |

SpotMCP never sends SQL or arbitrary requests upstream. It only calls the four configured endpoints. Query
IDs are validated (`[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}`, no `..`) and URL-encoded, so a caller cannot
traverse to other upstream paths. Redirects are not followed.

## Security model

**What "read-only" means here.** The tools carry `readOnlyHint=true`, but that is an advisory annotation
for MCP clients, **not a safety control**. SpotMCP cannot know whether a saved query only reads: running one
is a `POST .../execute` made with SpotMCP's own upstream credential, and the upstream never sees the
caller's identity. Read-only behaviour is enforced by:

1. **A mandatory allow-list.** `SPOTMCP_ALLOWED_QUERY_IDS` must list the saved queries callers may describe
   and run, and the server refuses to start without it. **Only list queries that are read-only upstream.**
   Exposing every upstream query takes an explicit `SPOTMCP_ALLOW_ANY_QUERY=true`, which is only safe if
   the upstream itself guarantees that every query it exposes is read-only.
2. **A least-privilege upstream credential.** Give SpotMCP's upstream identity read-only access on the
   internal API.

Any client holding a valid token can run any allow-listed query. To restrict which clients may connect at
all, set `SPOTMCP_OAUTH_REQUIRED_SCOPES` (optional; by default any valid token for the configured issuer and
audience is accepted).

**Authentication (incoming).** Every request to `/mcp` must carry `Authorization: Bearer <JWT>`.
SpotMCP acts as an OAuth 2.0 resource server, following the MCP authorization spec:

- Signature verified with keys from the IdP's JWKS (discovered from `{issuer}/.well-known/openid-configuration`,
  whose `issuer` must match, or set via `SPOTMCP_OAUTH_JWKS_URL`). Keys are cached for
  `SPOTMCP_OAUTH_JWKS_CACHE_SECONDS`. An unknown `kid` triggers a refresh, but refresh *attempts*, failed ones
  included, happen at most once every `SPOTMCP_OAUTH_JWKS_MIN_REFRESH_SECONDS`. Neither junk tokens nor an
  IdP outage can make every request hit the IdP. If a refresh fails, the cached keys keep being used.
  Encryption keys (`use=enc`) are ignored.
- Only asymmetric algorithms are accepted (`alg=none` and HS* are rejected). The token's `alg` must match the
  key's declared `alg`, or fit its key type.
- `iss` must equal `SPOTMCP_OAUTH_ISSUER` exactly. `aud` must contain one of `SPOTMCP_OAUTH_AUDIENCE`.
  `exp` is required. `nbf` and `exp` are checked with `SPOTMCP_OAUTH_LEEWAY_SECONDS` of clock-skew allowance.
- Optional `SPOTMCP_OAUTH_REQUIRED_SCOPES` (read from `scope` or `scp`). A missing scope returns 403 `insufficient_scope`.
- A failure returns 401 with `WWW-Authenticate: Bearer ..., resource_metadata="…/.well-known/oauth-protected-resource/mcp"`.
  Protected Resource Metadata (RFC 9728) is served at that URL. The uvicorn access log records the client
  address of every rejected request.

**HTTPS.** The issuer, JWKS URL, upstream base and token URLs and the resource URL must be `https`.
Plain `http` is only accepted for `localhost`/`127.0.0.1`, or with `SPOTMCP_ALLOW_INSECURE_HTTP=true`
(development only). Disabling upstream TLS verification (`SPOTMCP_UPSTREAM_VERIFY_TLS=false`) logs a warning
at startup.

**Rate limiting.** A token bucket per OAuth client ID, which is the first of
`SPOTMCP_OAUTH_CLIENT_ID_CLAIMS` (`client_id, azp, cid, appid`) present in the token, falling back to `sub`.
This covers Okta (`cid`), Auth0/Entra/Keycloak (`azp`) and RFC 9068 (`client_id`). All tokens issued to the
same client share one budget. Over-limit requests get `429` with `Retry-After`. Overrides are set per client
(`SPOTMCP_RATE_LIMIT_OVERRIDES=svc-a=240,svc-b=10`; values must be positive and finite). State is
in-memory, so with several replicas each one enforces its own limit.

**Concurrency.** The rate limit bounds how often requests *start*. In-flight query executions are capped
separately: `SPOTMCP_MAX_CONCURRENT_QUERIES_PER_CLIENT` (default 4) per client, where an extra call is
rejected immediately, and `SPOTMCP_MAX_CONCURRENT_QUERIES` (default 20) server-wide, where an extra call
waits for a slot within its own deadline.

**Timeouts.** Every `run_saved_query` call runs under a wall-clock deadline (`asyncio.timeout`) that covers
the whole upstream call: waiting for a concurrency slot, obtaining the upstream token, connecting, and
streaming the response. The deadline is `timeout_seconds` if given, otherwise
`SPOTMCP_QUERY_DEFAULT_TIMEOUT_SECONDS`, and is always capped at `SPOTMCP_QUERY_MAX_TIMEOUT_SECONDS`. When it
expires, SpotMCP cancels its HTTP request, drops the connection and returns an error. **The deadline is
enforced by SpotMCP.** Whether the upstream stops executing the query depends on it honouring client
disconnects, so configure matching timeouts on the internal API too. Metadata calls use
`SPOTMCP_METADATA_TIMEOUT_SECONDS`.

**Result limits.** Responses over `SPOTMCP_MAX_RESPONSE_BYTES` fail while streaming (they are not
truncated). Row arrays (a top-level list, or the `SPOTMCP_ROWS_FIELD` key) are truncated to
`SPOTMCP_MAX_ROWS` and flagged `truncated: true`. If the response has neither, the row limit cannot be
applied: the result says `row_limit_applied: false` and a warning is logged. Incoming MCP request bodies are
limited to `SPOTMCP_MAX_REQUEST_BODY_BYTES` (default 256 KiB).

**Listing.** With the allow-list, `list_saved_queries` returns only the matching items: entries whose
`SPOTMCP_QUERY_ID_FIELD` (default `id`) is allow-listed, taken from a top-level list or from the first of
`queries`/`items`/`data`/`results`. Sibling metadata such as totals or cursors is dropped so that queries
outside the allow-list can't be inferred, and an unrecognised shape returns an empty list. Only the first
page of a paginated upstream listing is read.

**Upstream credentials.** `SPOTMCP_UPSTREAM_AUTH_MODE` is one of `none`, `static_bearer`, `api_key`, or
`client_credentials`. With `client_credentials`, SpotMCP fetches its own M2M token from the IdP and caches
it until 30s before expiry. If the upstream answers 401, the token is refreshed and the call retried once.
Caller tokens are **never** forwarded upstream.

**Logging.** Logs are JSON lines on stdout. Each tool call writes an audit record with `tool`, `client_id`,
`outcome` and `duration_ms`, and `query_id` where one applies. Outcomes are `ok`, `error`, `not_found`,
`timeout`, `denied`, `invalid_id`, `invalid_parameters` and `throttled`, so rejected calls are audited too.
Parameter values and tokens are never logged. The `httpx`/`httpcore` transport loggers, which would log
full request URLs including GET query strings, are held at WARNING.

**Other protections.** The container runs as non-root user 10001. Host-header (DNS-rebinding) checks are
enabled by setting `SPOTMCP_ALLOWED_HOSTS`. Leaving it empty disables the check, which is intended for
deployment behind a reverse proxy that routes only your hostname to the server.

## Configuration

All settings are environment variables prefixed `SPOTMCP_` (a `.env` file is also read). See
[`.env.example`](.env.example) for the full list. These are required:

| Variable | Example |
| --- | --- |
| `SPOTMCP_RESOURCE_URL` | `https://spotmcp.example.com/mcp` |
| `SPOTMCP_OAUTH_ISSUER` | `https://idp.example.com/oauth2/default` |
| `SPOTMCP_OAUTH_AUDIENCE` | `api://spotmcp` |
| `SPOTMCP_UPSTREAM_BASE_URL` | `https://internal.example.com/api` |
| `SPOTMCP_ALLOWED_QUERY_IDS` | `sales-by-region,inventory-summary` (or `SPOTMCP_ALLOW_ANY_QUERY=true`) |

Limits (all optional):

| Variable | Default | Meaning |
| --- | --- | --- |
| `SPOTMCP_RATE_LIMIT_PER_MINUTE` | `60` | Sustained requests per minute per OAuth client |
| `SPOTMCP_RATE_LIMIT_BURST` | `10` | Bucket size (requests allowed back-to-back) |
| `SPOTMCP_RATE_LIMIT_OVERRIDES` | _(none)_ | Per-client requests/minute, e.g. `svc-a=240,svc-b=10` |
| `SPOTMCP_MAX_ROWS` | `1000` | Max rows returned per `run_saved_query` call |
| `SPOTMCP_MAX_RESPONSE_BYTES` | `5242880` | Max upstream response size |
| `SPOTMCP_MAX_CONCURRENT_QUERIES_PER_CLIENT` | `4` | In-flight query executions per OAuth client |
| `SPOTMCP_MAX_CONCURRENT_QUERIES` | `20` | In-flight query executions server-wide |
| `SPOTMCP_QUERY_DEFAULT_TIMEOUT_SECONDS` | `30` | Deadline when the caller doesn't specify one |
| `SPOTMCP_QUERY_MAX_TIMEOUT_SECONDS` | `120` | Upper bound on any requested deadline |

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
   runs as non-root), then on pushes to `main` or `v*` tags pushes **that same tested image** to
   `ghcr.io/<owner>/spotmcp`. Pull requests build and test the image but do not push it.

Actions are pinned to commit SHAs. Only superseded pull-request runs are cancelled, never release runs.
