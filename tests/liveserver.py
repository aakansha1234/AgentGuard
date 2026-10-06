"""A real AgentGuard server on a random port, in a background thread."""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx
import httpx2
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from agentguard.app import create_app
from agentguard.config import Settings
from agentguard.reviewers.base import Reviewer
from agentguard.services import Services, build_services
from tests.conftest import POLICY_PATH

OPERATOR_TOKEN = "op-test-token-0123456789"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LiveServer:
    def __init__(
        self,
        tmp_path: Path,
        *,
        reviewer: Reviewer | None = None,
        configure: Callable[[Settings], None] | None = None,
    ) -> None:
        self.settings = Settings()
        self.settings.data_dir = tmp_path / "data"
        self.settings.port = free_port()
        self.settings.operator_token = OPERATOR_TOKEN
        self.settings.reviewer = "human"  # tests choose reviewers explicitly
        self.settings.policy_path = tmp_path / "policy.yaml"
        self.settings.policy_path.write_text(POLICY_PATH.read_text())
        if configure is not None:
            configure(self.settings)
        self.services: Services = build_services(self.settings, reviewer=reviewer, approval_poll_seconds=0.05)
        self.app = create_app(self.settings, services=self.services)
        self.server = uvicorn.Server(
            uvicorn.Config(self.app, host="127.0.0.1", port=self.settings.port, log_level="warning")
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> LiveServer:
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started:
            if time.time() > deadline or not self.thread.is_alive():
                raise RuntimeError("server did not start")
            time.sleep(0.02)
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(15)
        self.services.store.close()

    @property
    def url(self) -> str:
        return self.settings.base_url

    def api(self, token: str | None = OPERATOR_TOKEN) -> httpx.Client:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return httpx.Client(base_url=self.url, headers=headers, timeout=30)

    def create_run(self, **body: Any) -> dict[str, Any]:
        payload = {"task": "Investigate Alice's failed logins.", "mode": "external", **body}
        with self.api() as c:
            r = c.post("/api/runs", json=payload)
        assert r.status_code == 201, r.text
        return r.json()

    @contextlib.asynccontextmanager
    async def mcp(self, token: str) -> AsyncIterator[Client]:
        async with (
            httpx2.AsyncClient(
                headers={"Authorization": f"Bearer {token}"}, timeout=httpx2.Timeout(30, read=120)
            ) as http,
            Client(streamable_http_client(self.settings.mcp_url, http_client=http)) as client,
        ):
            yield client

    def wait_run(self, run_id: str, states: set[str], timeout: float = 20) -> dict[str, Any]:
        deadline = time.time() + timeout
        with self.api() as c:
            while True:
                data = c.get(f"/api/runs/{run_id}").json()
                if data["run"]["state"] in states:
                    return data
                if time.time() > deadline:
                    raise AssertionError(f"run {run_id} stuck in {data['run']['state']}")
                time.sleep(0.05)

    def wait_action(self, run_id: str, state: str, timeout: float = 20) -> dict[str, Any]:
        deadline = time.time() + timeout
        with self.api() as c:
            while True:
                actions = c.get(f"/api/runs/{run_id}").json()["actions"]
                found = [a for a in actions if a["state"] == state]
                if found:
                    return found[-1]
                if time.time() > deadline:
                    raise AssertionError(f"no action reached {state}: {[a['state'] for a in actions]}")
                time.sleep(0.05)
