"""Claude Code launcher tests, using a fake `claude` binary (no model calls)."""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agentguard.config import Settings
from agentguard.launcher.claude_code import build_command, check_init, mcp_config
from agentguard.tools import soc_registry
from tests.liveserver import LiveServer

FAKE = Path(__file__).parent / "fakes" / "fake_claude.py"
GATEWAY_TOOLS = [
    f"mcp__agentguard__{t}" for t in ("block_ip", "get_ip_activity", "get_user_logins", "http_post")
]


# --- pure functions ------------------------------------------------------------------


def test_command_removes_every_builtin_tool_and_foreign_config() -> None:
    s = Settings()
    cmd = build_command(s, mcp_config=Path("/x/mcp.json"), prompt_file=Path("/x/worker.md"))

    def value(flag: str) -> str:
        return cmd[cmd.index(flag) + 1]

    assert cmd[0] == "claude" and "-p" in cmd
    assert value("--tools") == ""
    assert value("--permission-mode") == "dontAsk"
    assert value("--setting-sources") == ""
    assert value("--allowedTools") == "mcp__agentguard__*"
    assert value("--model") == "claude-opus-5-5"
    assert value("--output-format") == "stream-json"
    assert "--strict-mcp-config" in cmd
    assert "--dangerously-skip-permissions" not in cmd and "bypassPermissions" not in cmd


def test_mcp_config_shape() -> None:
    cfg = mcp_config("http://127.0.0.1:1/mcp", "agr_x")
    assert cfg == {
        "mcpServers": {
            "agentguard": {
                "type": "http",
                "url": "http://127.0.0.1:1/mcp",
                "headers": {"Authorization": "Bearer agr_x"},
            }
        }
    }


def init(tools: list[str], servers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "type": "system",
        "subtype": "init",
        "tools": tools,
        "mcp_servers": servers if servers is not None else [{"name": "agentguard", "status": "connected"}],
    }


@pytest.mark.parametrize(
    "event,problem",
    [
        (init([*GATEWAY_TOOLS, "Bash"]), "unexpected tools"),
        (init(["WebFetch"]), "unexpected tools"),
        (init([]), "no tool list"),
        (init(GATEWAY_TOOLS, [{"name": "agentguard", "status": "failed"}]), "not connected"),
        (
            init(
                GATEWAY_TOOLS,
                [{"name": "agentguard", "status": "connected"}, {"name": "github", "status": "connected"}],
            ),
            "other MCP servers",
        ),
    ],
)
def test_lockdown_check_fails_closed(event: dict[str, Any], problem: str) -> None:
    problems = check_init(event, soc_registry().names())
    assert any(problem in p for p in problems), problems


def test_lockdown_check_passes_for_gateway_tools_only() -> None:
    assert check_init(init(GATEWAY_TOOLS), soc_registry().names()) == []
    assert check_init(init(GATEWAY_TOOLS[:2]), soc_registry().names()) == []


# --- with the fake binary through the real server ----------------------------------------


def make_fake_bin(tmp_path: Path) -> Path:
    wrapper = tmp_path / "claude"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" "$@"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    return wrapper


@pytest.fixture
def live_srv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[LiveServer]:
    fake = make_fake_bin(tmp_path)
    monkeypatch.setenv("CLAUDE_FAKE_LOG", str(tmp_path / "fake.log"))

    def configure(s: Settings) -> None:
        s.claude_bin = str(fake)

    with LiveServer(tmp_path, configure=configure) as s:
        yield s


def script(monkeypatch: pytest.MonkeyPatch, steps: list[dict[str, Any]], **env: str) -> None:
    monkeypatch.setenv("CLAUDE_FAKE_SCRIPT", json.dumps(steps))
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def start_live(srv: LiveServer, task: str = "Investigate Alice's failed logins.") -> str:
    return srv.create_run(task=task, mode="live")["run"]["id"]


def test_live_run_happy_path(live_srv: LiveServer, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    script(monkeypatch, [{"tool": "get_user_logins", "args": {"user": "alice"}}])
    # AgentGuard's own secrets must not reach the agent process.
    for secret in ("CLOUDFLARE_API_TOKEN", "TYPESAFE_API_KEY", "AGENTGUARD_OPERATOR_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.setenv(secret, "must-not-leak")
    run_id = start_live(live_srv, task="--dangerous-looking task text starting with dashes")
    data = live_srv.wait_run(run_id, {"completed", "failed", "halted"})
    assert data["run"]["state"] == "completed", data["run"]["state_reason"]
    agent = data["run"]["agent"]
    assert agent["kind"] == "claude-code" and agent["lockdown_verified"] is True
    assert agent["model"] == "claude-opus-5-5"
    assert [a["state"] for a in data["actions"]] == ["succeeded"]
    assert "EVT-0022" in data["run"]["summary"]
    log = [json.loads(line) for line in (tmp_path / "fake.log").read_text().splitlines()]
    assert "--dangerous-looking task" in log[0]["prompt"], "the task goes in via stdin, not argv"
    assert all("--dangerous-looking" not in a for a in log[0]["argv"])
    assert log[0]["env_idle"] == "600000"
    leaked = {"CLOUDFLARE_API_TOKEN", "TYPESAFE_API_KEY", "AGENTGUARD_OPERATOR_TOKEN", "GITHUB_TOKEN"}
    assert leaked.isdisjoint(log[0]["env_keys"]), "agent got AgentGuard's secrets"
    assert {"PATH", "HOME"} <= set(log[0]["env_keys"])
    types = [e.type for e in live_srv.services.store.events_after(run_id)]
    assert "agent.message" in types and "agent.finished" in types
    assert not list((live_srv.settings.data_dir / "runs" / run_id).glob("mcp.json")), "token file removed"


def test_live_run_with_extra_tools_is_killed_before_any_call_runs(
    live_srv: LiveServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    script(
        monkeypatch,
        [{"tool": "get_user_logins", "args": {"user": "alice"}}],
        CLAUDE_FAKE_TOOLS=json.dumps([*GATEWAY_TOOLS, "Bash", "WebFetch"]),
    )
    run_id = start_live(live_srv)
    data = live_srv.wait_run(run_id, {"completed", "failed", "halted"})
    assert data["run"]["state"] == "failed"
    assert "lockdown check failed" in data["run"]["state_reason"]
    assert "Bash" in data["run"]["state_reason"]
    assert live_srv.services.store.executions(run_id) == []
    assert all(a["state"] == "denied" for a in data["actions"])


def test_live_run_approval(live_srv: LiveServer, monkeypatch: pytest.MonkeyPatch) -> None:
    script(
        monkeypatch,
        [
            {"tool": "get_user_logins", "args": {"user": "alice"}},
            {
                "tool": "block_ip",
                "args": {"ip": "203.0.113.42", "reason": "EVT-0004..0022", "duration_minutes": 60},
            },
        ],
    )
    run_id = start_live(live_srv)
    pending = live_srv.wait_action(run_id, "pending_approval")
    with live_srv.api() as c:
        r = c.post(
            f"/api/approvals/{pending['id']}/resolve",
            json={"decision": "approve", "args_hash": pending["args_hash"]},
        )
        assert r.status_code == 200
    data = live_srv.wait_run(run_id, {"completed", "failed", "halted"})
    assert data["run"]["state"] == "completed"
    assert "block_ip=ok" in data["run"]["summary"]
    assert len(live_srv.services.store.executions(run_id, "block_ip")) == 1


def test_cancel_kills_the_agent_process(live_srv: LiveServer, monkeypatch: pytest.MonkeyPatch) -> None:
    script(monkeypatch, [], CLAUDE_FAKE_SLEEP="60")
    run_id = start_live(live_srv)
    live_srv.wait_run(run_id, {"running"})
    proc = live_srv.services.runs._procs[run_id]
    with live_srv.api() as c:
        assert c.post(f"/api/runs/{run_id}/cancel").json()["run"]["state"] == "cancelled"
    deadline = time.time() + 10
    while proc.returncode is None and time.time() < deadline:
        time.sleep(0.05)
    assert proc.returncode is not None, "agent process was not killed"
    assert live_srv.services.store.get_run(run_id).state == "cancelled"  # type: ignore[union-attr]


def test_agent_crash_marks_run_failed(live_srv: LiveServer, monkeypatch: pytest.MonkeyPatch) -> None:
    script(monkeypatch, [], CLAUDE_FAKE_CRASH="1")
    run_id = start_live(live_srv)
    data = live_srv.wait_run(run_id, {"completed", "failed", "halted"})
    assert data["run"]["state"] == "failed"
    assert "simulated crash" in data["run"]["state_reason"]


async def test_time_limit_halts_and_kills(live_srv: LiveServer, monkeypatch: pytest.MonkeyPatch) -> None:
    from agentguard.launcher.claude_code import run_claude_code
    from agentguard.models import RunMode

    script(monkeypatch, [], CLAUDE_FAKE_SLEEP="60")
    svc = live_srv.services
    run, token = svc.gate.create_run(
        owner="t", task="t", mode=RunMode.LIVE, dataset_id="baseline", subject="alice"
    )
    procs: list[Any] = []
    started = time.time()
    await run_claude_code(
        settings=live_srv.settings,
        registry=svc.registry,
        recorder=svc.recorder,
        gate=svc.gate,
        run=run,
        token=token,
        register_process=procs.append,
        time_limit=1.5,
    )
    assert time.time() - started < 10
    assert procs[0].returncode is not None
    fresh = svc.store.get_run(run.id)
    assert fresh is not None and fresh.state == "halted" and "time limit" in (fresh.state_reason or "")


def test_live_mode_requires_the_cli(tmp_path: Path) -> None:
    def configure(s: Settings) -> None:
        s.claude_bin = str(tmp_path / "does-not-exist")

    with LiveServer(tmp_path, configure=configure) as srv, srv.api() as c:
        r = c.post("/api/runs", json={"task": "x", "mode": "live"})
    assert r.status_code == 409 and "not found" in r.json()["detail"]


def test_fake_binary_is_executable() -> None:
    assert os.access(FAKE, os.R_OK)
