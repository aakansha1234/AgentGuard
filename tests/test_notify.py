"""Webhook alerts when a human is needed."""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from agentguard.config import ConfigError, Settings
from tests.liveserver import LiveServer, free_port


class Receiver:
    """A local webhook endpoint that records what it receives."""

    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.bodies: list[dict[str, Any]] = []
        received = self.bodies
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                received.append(json.loads(self.rfile.read(length)))
                self.send_response(outer.status)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                pass

        self.port = free_port()
        self.server = HTTPServer(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/hook/secret-path"

    def __enter__(self) -> Receiver:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()


def notified_srv(tmp_path: Path, receiver: Receiver, fmt: str = "slack") -> LiveServer:
    def configure(s: Settings) -> None:
        s.notify_webhook = receiver.url
        s.notify_format = fmt
        s.public_url = "https://guard.example.test:8787"

    return LiveServer(tmp_path, configure=configure)


@pytest.fixture
def receiver() -> Iterator[Receiver]:
    with Receiver() as r:
        yield r


BLOCK = {"ip": "203.0.113.42", "reason": "EVT-0004..EVT-0022", "duration_minutes": 60}


async def request_block(srv: LiveServer) -> tuple[str, asyncio.Task[Any], Any]:
    created = srv.create_run(subject="alice")
    run_id = created["run"]["id"]
    ctx = srv.mcp(created["token"])
    client = await ctx.__aenter__()
    await client.call_tool("get_user_logins", {"user": "alice"})
    call = asyncio.create_task(client.call_tool("block_ip", BLOCK))
    await asyncio.to_thread(srv.wait_action, run_id, "pending_approval")
    return run_id, call, ctx


async def wait_for(predicate: Any, timeout: float = 10) -> None:
    for _ in range(int(timeout / 0.05)):
        if predicate():
            return
        await asyncio.sleep(0.05)
    raise AssertionError("timed out")


async def test_approval_request_sends_a_slack_message(tmp_path: Path, receiver: Receiver) -> None:
    with notified_srv(tmp_path, receiver) as srv:
        run_id, call, ctx = await request_block(srv)
        await wait_for(lambda: receiver.bodies)
        [body] = receiver.bodies
        assert set(body) == {"text"}
        text = body["text"]
        assert "block_ip(" in text and "203.0.113.42" in text and "R-13-block-needs-human" in text
        assert f"https://guard.example.test:8787/#run={run_id}" in text
        srv.services.gate.cancel_run(run_id, "test")
        await call
        await ctx.__aexit__(None, None, None)
        types = [e.type for e in srv.services.store.events_after(run_id)]
        assert "notify.sent" in types
        assert all(
            "secret-path" not in json.dumps(e.payload) for e in srv.services.store.events_after(run_id)
        )


async def test_failed_delivery_is_recorded(tmp_path: Path) -> None:
    with Receiver(status=500) as broken, notified_srv(tmp_path, broken, fmt="json") as srv:
        run_id, call, ctx = await request_block(srv)
        await wait_for(
            lambda: any(e.type == "notify.failed" for e in srv.services.store.events_after(run_id))
        )
        assert len(broken.bodies) == 3, "retried"
        assert broken.bodies[0]["type"] == "approval.requested" and broken.bodies[0]["run_id"] == run_id
        srv.services.gate.cancel_run(run_id, "test")
        await call
        await ctx.__aexit__(None, None, None)


def test_bad_format_stops_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTGUARD_NOTIFY_FORMAT", "teams")
    with pytest.raises(ConfigError, match="slack or json"):
        Settings.from_env()
