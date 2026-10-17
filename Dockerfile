ARG BASE_IMAGE=python:3.13-slim

FROM ${BASE_IMAGE} AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --wheel-dir /wheels .

FROM ${BASE_IMAGE} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SPOTMCP_HOST=0.0.0.0 \
    SPOTMCP_PORT=8080
RUN groupadd --system --gid 10001 spotmcp \
    && useradd --system --uid 10001 --gid spotmcp --no-create-home --shell /usr/sbin/nologin spotmcp
COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links /wheels spotmcp && rm -rf /wheels
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"SPOTMCP_PORT\", \"8080\")}/healthz', timeout=2)"]
ENTRYPOINT ["spotmcp"]
