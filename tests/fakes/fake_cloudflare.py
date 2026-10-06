"""In-memory stand-in for Cloudflare's account IP Access Rules API.

Usable as an httpx2 transport (unit tests) or a real HTTP server (end-to-end
tests, where the Cloudflare MCP server runs as a separate process).
"""

from __future__ import annotations

import json
import re
import secrets
import threading
from typing import Any

import httpx2
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from tests.liveserver import free_port

PATH = re.compile(r"^/client/v4/accounts/(?P<account>[^/]+)/firewall/access_rules/rules(?:/(?P<id>[^/]+))?$")


class FakeCloudflare:
    def __init__(self, account: str = "acct", token: str = "cf-token") -> None:  # noqa: S107 - test double
        self.account = account
        self.token = token
        self.rules: dict[str, dict[str, Any]] = {}
        self.calls: list[tuple[str, str]] = []
        self._lock = threading.Lock()

    def add_human_rule(self, ip: str, note: str = "added by the network team") -> str:
        rule_id = secrets.token_hex(16)
        self.rules[rule_id] = {
            "id": rule_id,
            "mode": "block",
            "notes": note,
            "configuration": {"target": "ip", "value": ip},
        }
        return rule_id

    def handle(
        self, method: str, path: str, params: dict[str, str], body: Any, auth: str | None
    ) -> tuple[int, Any]:
        with self._lock:
            self.calls.append((method, path))
            if auth != f"Bearer {self.token}":
                return 403, {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]}
            m = PATH.match(path)
            if not m or m.group("account") != self.account:
                return 404, {"success": False, "errors": [{"message": "not found"}]}
            rule_id = m.group("id")
            if method == "GET" and rule_id is None:
                found = [
                    r
                    for r in self.rules.values()
                    if params.get("notes", "") in r["notes"] and params.get("mode", r["mode"]) == r["mode"]
                ]
                page, per_page = int(params.get("page", 1)), int(params.get("per_page", 20))
                return 200, {"success": True, "result": found[(page - 1) * per_page : page * per_page]}
            if method == "POST" and rule_id is None:
                if body.get("mode") != "block" or body["configuration"]["target"] not in ("ip", "ip6"):
                    return 400, {"success": False, "errors": [{"message": "bad rule"}]}
                new_id = secrets.token_hex(16)
                self.rules[new_id] = {"id": new_id, **body}
                return 200, {"success": True, "result": self.rules[new_id]}
            if rule_id not in self.rules:
                return 404, {"success": False, "errors": [{"message": "no such rule"}]}
            if method == "PATCH":
                self.rules[rule_id]["notes"] = body["notes"]
                return 200, {"success": True, "result": self.rules[rule_id]}
            if method == "DELETE":
                del self.rules[rule_id]
                return 200, {"success": True, "result": {"id": rule_id}}
            return 405, {"success": False, "errors": [{"message": "method not allowed"}]}

    # --- as an httpx2 transport --------------------------------------------------------------

    def transport(self) -> httpx2.MockTransport:
        def handler(request: httpx2.Request) -> httpx2.Response:
            body = json.loads(request.content) if request.content else None
            status, payload = self.handle(
                request.method,
                request.url.path,
                dict(request.url.params),
                body,
                request.headers.get("authorization"),
            )
            return httpx2.Response(status, json=payload)

        return httpx2.MockTransport(handler)

    # --- as a real HTTP server ----------------------------------------------------------------

    def serve(self) -> RunningFake:
        async def endpoint(request: Request) -> JSONResponse:
            raw = await request.body()
            status, payload = self.handle(
                request.method,
                request.url.path,
                dict(request.query_params),
                json.loads(raw) if raw else None,
                request.headers.get("authorization"),
            )
            return JSONResponse(payload, status_code=status)

        app = Starlette(
            routes=[
                Route(
                    "/client/v4/accounts/{account}/firewall/access_rules/rules",
                    endpoint,
                    methods=["GET", "POST"],
                ),
                Route(
                    "/client/v4/accounts/{account}/firewall/access_rules/rules/{id}",
                    endpoint,
                    methods=["PATCH", "DELETE"],
                ),
            ]
        )
        return RunningFake(app)


class RunningFake:
    def __init__(self, app: Starlette) -> None:
        self.port = free_port()
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}/client/v4"

    def __enter__(self) -> RunningFake:
        import time

        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started:
            if time.time() > deadline:
                raise RuntimeError("fake Cloudflare did not start")
            time.sleep(0.02)
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(10)
