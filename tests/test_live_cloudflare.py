"""A real Cloudflare block through the whole stack: agent, AgentGuard, Cloudflare MCP server, Cloudflare.

Enable with: AGENTGUARD_LIVE_TESTS=1 uv run pytest -m live -s tests/test_live_cloudflare.py
Needs CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_FIREWALL_TOKEN (environment or .env). It blocks
203.0.113.42 (a documentation address, never a real host) and removes the rule afterwards.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from agentguard.config import PROJECT_ROOT, Settings, load_dotenv
from agentguard.integrations.cloudflare_firewall import Firewall
from tests.liveserver import LiveServer

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("AGENTGUARD_LIVE_TESTS") != "1", reason="set AGENTGUARD_LIVE_TESTS=1"),
]

IP = "203.0.113.42"


def firewall() -> Firewall:
    return Firewall(os.environ["CLOUDFLARE_ACCOUNT_ID"], os.environ["CLOUDFLARE_FIREWALL_TOKEN"])


@pytest.fixture
def srv(tmp_path: Path) -> Iterator[LiveServer]:
    load_dotenv(PROJECT_ROOT / ".env")
    missing = [k for k in ("CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_FIREWALL_TOKEN") if not os.environ.get(k)]
    if missing:
        pytest.skip(f"{', '.join(missing)} not available")
    upstreams = tmp_path / "upstreams.yaml"
    upstreams.write_text(
        "servers:\n  cloudflare:\n"
        f"    command: {json.dumps(sys.executable)}\n"
        "    args: [-m, agentguard.integrations.cloudflare_firewall]\n"
        "    env:\n"
        "      CLOUDFLARE_ACCOUNT_ID: ${CLOUDFLARE_ACCOUNT_ID}\n"
        "      CLOUDFLARE_API_TOKEN: ${CLOUDFLARE_FIREWALL_TOKEN}\n"
    )

    def configure(s: Settings) -> None:
        s.upstreams_path = upstreams

    try:
        with LiveServer(tmp_path, configure=configure) as s:
            yield s
    finally:
        asyncio.run(_cleanup())


async def _cleanup() -> None:
    fw = firewall()
    try:
        await fw.unblock(IP)
    finally:
        await fw.aclose()


async def _blocked() -> list[str]:
    fw = firewall()
    try:
        return [b["ip"] for b in await fw.list()]
    finally:
        await fw.aclose()


async def test_approved_block_reaches_cloudflare_and_nothing_before(srv: LiveServer) -> None:
    created = srv.create_run(mode="replay", scenario="cloudflare")
    run_id = created["run"]["id"]
    pending = await asyncio.to_thread(srv.wait_action, run_id, "pending_approval", 60)
    assert pending["tool"] == "cloudflare__block_ip" and pending["args"]["ip"] == IP
    assert IP not in await _blocked(), "nothing at Cloudflare before a human approves"
    with srv.api() as c:
        r = c.post(
            f"/api/approvals/{pending['id']}/resolve",
            json={"decision": "approve", "args_hash": pending["args_hash"]},
        )
        assert r.status_code == 200, r.text
    data = await asyncio.to_thread(srv.wait_run, run_id, {"completed", "failed", "halted"}, 60)
    assert data["run"]["state"] == "completed", data["run"]["state_reason"]
    assert IP in await _blocked()
    print(f"\n  real Cloudflare rule created for {IP}; removed in cleanup")
