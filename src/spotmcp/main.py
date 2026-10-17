"""Command-line entrypoint: ``spotmcp`` / ``python -m spotmcp``."""

from __future__ import annotations

import uvicorn

from spotmcp.app import create_app
from spotmcp.config import Settings
from spotmcp.logging_config import configure_logging


def main() -> None:
    settings = Settings()  # type: ignore[call-arg]  # populated from the environment
    configure_logging(settings.log_level)
    app = create_app(settings)
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_config=None,
        proxy_headers=True,
        server_header=False,
    )


if __name__ == "__main__":
    main()
