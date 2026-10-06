"""Run `agentguard serve` in the background: `agentguard start | stop | restart | status`.

The server runs in its own process group, so it outlives the terminal and a stop
also ends the live agents it launched. The group id is kept in
<data dir>/server.pid and output goes to <data dir>/server.log.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx2

from agentguard.config import Settings

START_TIMEOUT = 30.0
STOP_TIMEOUT = 15.0


def pid_file(settings: Settings) -> Path:
    return settings.data_dir / "server.pid"


def log_file(settings: Settings) -> Path:
    return settings.data_dir / "server.log"


def running_pid(settings: Settings) -> int | None:
    try:
        pid = int(pid_file(settings).read_text().strip())
        os.killpg(pid, 0)
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        return None
    return pid


def healthy(settings: Settings) -> bool:
    try:
        return httpx2.get(f"{settings.base_url}/api/health", timeout=1).status_code == 200
    except httpx2.HTTPError:
        return False


def _tail(path: Path, lines: int = 20) -> str:
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-lines:])
    except FileNotFoundError:
        return ""


def start(settings: Settings) -> int:
    if (pid := running_pid(settings)) is not None:
        print(f"AgentGuard is already running (process group {pid}): {settings.public_base_url}/")
        return 0
    if healthy(settings):
        print(f"Port {settings.port} is taken by a server `agentguard start` did not start.", file=sys.stderr)
        return 1
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    log = log_file(settings)
    with log.open("ab") as out:
        proc = subprocess.Popen(
            [sys.executable, "-m", "agentguard.cli", "serve"],
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=subprocess.STDOUT,
            start_new_session=True,  # own process group: survives the terminal, stops as a unit
        )
    pid_file(settings).write_text(f"{proc.pid}\n")
    deadline = time.monotonic() + START_TIMEOUT
    while time.monotonic() < deadline:
        if (code := proc.poll()) is not None:
            pid_file(settings).unlink(missing_ok=True)
            print(f"AgentGuard exited during startup (status {code}):\n{_tail(log)}", file=sys.stderr)
            return code or 1
        if healthy(settings):
            print(f"AgentGuard is running: {settings.public_base_url}/  (log: {log})")
            return 0
        time.sleep(0.3)
    print(f"AgentGuard did not become healthy in {START_TIMEOUT:.0f}s:\n{_tail(log)}", file=sys.stderr)
    return 1


def stop(settings: Settings) -> int:
    pid = running_pid(settings)
    if pid is None:
        pid_file(settings).unlink(missing_ok=True)
        print("AgentGuard is not running.")
        return 0
    os.killpg(pid, signal.SIGTERM)
    deadline = time.monotonic() + STOP_TIMEOUT
    while time.monotonic() < deadline and running_pid(settings) is not None:
        time.sleep(0.2)
    if running_pid(settings) is not None:
        os.killpg(pid, signal.SIGKILL)
    pid_file(settings).unlink(missing_ok=True)
    print("AgentGuard stopped.")
    return 0


def status(settings: Settings) -> int:
    pid = running_pid(settings)
    if pid is not None and healthy(settings):
        print(f"running (process group {pid}): {settings.public_base_url}/")
        return 0
    print("not running")
    return 1
