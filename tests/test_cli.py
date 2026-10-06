"""CLI: policy check, starting the server as a real process, and `connect`."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from agentguard.cli import main
from tests.conftest import POLICY_PATH
from tests.liveserver import OPERATOR_TOKEN, LiveServer, free_port


def test_check_policy(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main(["check-policy", str(POLICY_PATH)]) == 0
    assert "OK, version p-" in capsys.readouterr().out
    bad = tmp_path / "bad.yaml"
    bad.write_text("schema_version: 1\nname: x\nrules: []\n")
    assert main(["check-policy", str(bad)]) == 1


def test_serve_starts_a_working_server(tmp_path: Path) -> None:
    port = free_port()
    env = {
        **os.environ,
        "AGENTGUARD_PORT": str(port),
        "AGENTGUARD_DATA_DIR": str(tmp_path / "data"),
        "AGENTGUARD_OPERATOR_TOKEN": "",
        "AGENTGUARD_REVIEWER": "human",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "agentguard.cli", "serve"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.time() + 20
        while True:
            try:
                if httpx.get(f"http://127.0.0.1:{port}/api/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            assert proc.poll() is None, proc.stdout.read() if proc.stdout else ""
            assert time.time() < deadline, "server did not start"
            time.sleep(0.2)
        token_file = tmp_path / "data" / "operator_token"
        assert token_file.exists() and oct(token_file.stat().st_mode & 0o777) == "0o600"
        token = token_file.read_text().strip()
        r = httpx.get(f"http://127.0.0.1:{port}/api/config", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200 and r.json()["tools_mode"] == "mock"
    finally:
        proc.terminate()
        out, _ = proc.communicate(timeout=10)
    assert "AgentGuard dashboard" in out and token not in out, "the token itself is never printed"


def test_connect_prints_instructions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with LiveServer(tmp_path) as srv:
        monkeypatch.setenv("AGENTGUARD_PORT", str(srv.settings.port))
        monkeypatch.setenv("AGENTGUARD_OPERATOR_TOKEN", OPERATOR_TOKEN)
        assert main(["connect", "--task", "Look at alice", "--shadow"]) == 0
        out = capsys.readouterr().out
        assert "claude mcp add --transport http agentguard" in out and '--tools ""' in out
        runs = srv.services.store.list_runs()
        assert len(runs) == 1 and runs[0].mode == "external" and runs[0].enforcement == "shadow"
        assert f"#run={runs[0].id}" in out

        assert main(["connect", "--task", "t", "--client", "codex", "--tools", "get_user_logins"]) == 0
        out = capsys.readouterr().out
        assert "--disable shell_tool" in out and 'default_tools_approval_mode="approve"' in out
        assert "(1 tools: get_user_logins)" in out
        assert main(["connect", "--task", "t", "--client", "api"]) == 0
        out = capsys.readouterr().out
        assert "AGENTGUARD_RUN_TOKEN=agr_" in out and "examples/claude_api_agent.py" in out


def _cli(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agentguard.cli", *args], env=env, capture_output=True, text=True, timeout=60
    )


def test_start_status_stop_run_the_server_in_the_background(tmp_path: Path) -> None:
    port = free_port()
    env = {
        **os.environ,
        "AGENTGUARD_PORT": str(port),
        "AGENTGUARD_DATA_DIR": str(tmp_path / "data"),
        "AGENTGUARD_REVIEWER": "human",
        "AGENTGUARD_DOTENV": "",
    }
    try:
        started = _cli(env, "start")
        assert started.returncode == 0, started.stderr
        assert "AgentGuard is running" in started.stdout
        assert httpx.get(f"http://127.0.0.1:{port}/api/health", timeout=2).status_code == 200
        pid = int((tmp_path / "data" / "server.pid").read_text())
        again = _cli(env, "start")
        assert again.returncode == 0 and "already running" in again.stdout
        assert _cli(env, "status").returncode == 0
        restarted = _cli(env, "restart")
        assert restarted.returncode == 0, restarted.stderr
        assert int((tmp_path / "data" / "server.pid").read_text()) != pid
    finally:
        stopped = _cli(env, "stop")
    assert stopped.returncode == 0 and "stopped" in stopped.stdout
    assert not (tmp_path / "data" / "server.pid").exists()
    status = _cli(env, "status")
    assert status.returncode == 1 and "not running" in status.stdout
    with pytest.raises(httpx.HTTPError):
        httpx.get(f"http://127.0.0.1:{port}/api/health", timeout=1)


def test_start_reports_a_configuration_error(tmp_path: Path) -> None:
    env = {
        **os.environ,
        "AGENTGUARD_PORT": str(free_port()),
        "AGENTGUARD_DATA_DIR": str(tmp_path / "data"),
        "AGENTGUARD_DOTENV": "",
    }
    env.pop("AGENTGUARD_REVIEWER", None)
    result = _cli(env, "start")
    assert result.returncode == 2
    assert "AGENTGUARD_REVIEWER is not set" in result.stderr
    assert not (tmp_path / "data" / "server.pid").exists()
