"""ASGI application: operator API, dashboard, and the MCP gateway at /mcp."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agentguard import __version__
from agentguard.api import build_router
from agentguard.config import Settings
from agentguard.gateway import Gateway
from agentguard.notify import Notifier
from agentguard.services import Services, build_services

SECURITY_HEADERS = [
    (
        b"content-security-policy",
        b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        b"connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    ),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
]


class SecurityHeaders:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                message["headers"] = [
                    *message.get("headers", []),
                    *((k, v) for k, v in SECURITY_HEADERS if k not in existing),
                ]
            await send(message)

        await self.app(scope, receive, send_with_headers)


def allowed_hosts(settings: Settings) -> list[str]:
    """Host headers the MCP endpoint accepts (DNS-rebinding protection)."""
    hosts = {f"{settings.internal_host}:*", "127.0.0.1:*", "localhost:*"}
    if settings.public_url:
        parsed = urlsplit(settings.public_url)
        if parsed.hostname:
            hosts |= {parsed.hostname, f"{parsed.hostname}:*"}
    return sorted(hosts)


def create_app(settings: Settings | None = None, services: Services | None = None, **kwargs: Any) -> FastAPI:
    settings = settings or Settings.from_env()
    services = services or build_services(settings, **kwargs)
    gateway = Gateway(
        gate=services.gate,
        store=services.store,
        registry=services.registry,
        allowed_hosts=allowed_hosts(settings),
    )

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        services.gate.recover_after_restart()
        if services.upstreams is not None:
            await services.upstreams.open()
        notifier = None
        if settings.notify_webhook:
            notifier = Notifier(
                url=settings.notify_webhook,
                fmt=settings.notify_format,
                dashboard_url=settings.public_base_url,
                bus=services.bus,
                recorder=services.recorder,
            )
            notifier.start()
        try:
            async with gateway.session_manager.run():
                try:
                    yield
                finally:
                    await services.runs.shutdown()
        finally:
            if notifier is not None:
                await notifier.stop()
            if services.upstreams is not None:
                await services.upstreams.close()

    app = FastAPI(title="AgentGuard", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.services = services
    app.include_router(build_router(services))
    app.router.routes.append(Route("/mcp", endpoint=gateway.asgi, methods=["GET", "POST", "DELETE"]))

    web = settings.web_dir

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(web / "index.html", headers={"Cache-Control": "no-store"})

    app.mount("/static", StaticFiles(directory=web), name="static")
    app.add_middleware(SecurityHeaders)  # type: ignore[arg-type]
    return app
