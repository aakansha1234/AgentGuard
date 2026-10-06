"""Launch Claude Code as the guarded agent.

Claude Code runs headless with every built-in tool removed and only the
AgentGuard MCP server loaded, so the gateway is its only way to act. Before
any tool call is accepted, the launcher checks the tool list Claude Code
reports in its init event and fails closed on anything unexpected.

`--bare` is not used: it only accepts ANTHROPIC_API_KEY, while this setup
reuses the local Claude Code login.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agentguard.config import Settings
from agentguard.events import Recorder
from agentguard.gate import Gatekeeper
from agentguard.gateway import SERVER_NAME
from agentguard.launcher.agent_env import agent_env
from agentguard.models import ACTIVE_RUN_STATES
from agentguard.store import RunRecord
from agentguard.tools.base import ToolRegistry

TOOL_PREFIX = f"mcp__{SERVER_NAME}__"
STDOUT_LINE_LIMIT = 32 * 1024 * 1024


def build_command(settings: Settings, *, mcp_config: Path, prompt_file: Path) -> list[str]:
    return [
        settings.claude_bin,
        "-p",
        "--model",
        settings.claude_model,
        "--tools",
        "",  # no built-in tools at all: no Bash, file, web or subagent tools
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
        "--allowedTools",
        f"{TOOL_PREFIX}*",
        "--permission-mode",
        "dontAsk",  # anything not pre-allowed is refused, never prompted
        "--setting-sources",
        "",  # ignore user/project/local settings (hooks, permissions, MCP servers)
        "--system-prompt-file",
        str(prompt_file),
        "--max-turns",
        str(settings.claude_max_turns),
        "--output-format",
        "stream-json",
        "--verbose",
    ]


def mcp_config(url: str, token: str) -> dict[str, Any]:
    return {
        "mcpServers": {
            SERVER_NAME: {"type": "http", "url": url, "headers": {"Authorization": f"Bearer {token}"}}
        }
    }


def user_prompt(run: RunRecord) -> str:
    return f"Task: {run.task}\n\nAssigned subject (user ID): {run.subject}\n"


def check_init(event: dict[str, Any], run_tools: list[str]) -> list[str]:
    """Return the problems with the agent's reported environment; empty means locked down.

    `run_tools` is the run's allowlist: the agent may hold those AgentGuard tools and nothing else.
    """
    problems: list[str] = []
    expected = {TOOL_PREFIX + name for name in run_tools}
    tools = event.get("tools")
    if not isinstance(tools, list) or not tools:
        problems.append("agent reported no tool list")
        tools = []
    unexpected = sorted(t for t in tools if t not in expected)
    if unexpected:
        problems.append(f"unexpected tools available to the agent: {unexpected}")
    servers = {s.get("name"): s.get("status") for s in event.get("mcp_servers") or [] if isinstance(s, dict)}
    if servers.get(SERVER_NAME) != "connected":
        problems.append(f"AgentGuard MCP server not connected (status: {servers.get(SERVER_NAME)})")
    others = sorted(str(n) for n in servers if n != SERVER_NAME)
    if others:
        problems.append(f"other MCP servers loaded: {others}")
    return problems


def _kill(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError):
        proc.kill()


async def _tail(stream: asyncio.StreamReader | None, keep: int = 4000) -> str:
    if stream is None:
        return ""
    buf = b""
    while chunk := await stream.read(65536):
        buf = (buf + chunk)[-keep:]
    return buf.decode("utf-8", "replace")


async def run_claude_code(
    *,
    settings: Settings,
    registry: ToolRegistry,
    recorder: Recorder,
    gate: Gatekeeper,
    run: RunRecord,
    token: str,
    register_process: Callable[[asyncio.subprocess.Process], None],
    time_limit: float,
) -> None:
    work = settings.data_dir / "runs" / run.id
    cwd = work / "cwd"
    cwd.mkdir(parents=True, exist_ok=True)
    config_path = work / "mcp.json"
    config_path.touch(mode=0o600)
    config_path.write_text(json.dumps(mcp_config(settings.mcp_url, token)))

    cmd = build_command(settings, mcp_config=config_path, prompt_file=settings.worker_prompt_path)
    env = agent_env(
        allow_prefixes=("CLAUDE_", "ANTHROPIC_"),
        extra={"CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT": str(settings.claude_mcp_idle_timeout_ms)},
    )
    recorder.emit(run.id, "agent.launching", {"agent": "claude-code", "model": settings.claude_model})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
            limit=STDOUT_LINE_LIMIT,
            start_new_session=True,
        )
    except OSError as exc:
        config_path.unlink(missing_ok=True)
        gate.fail_run(run.id, f"could not start Claude Code: {exc}")
        return
    register_process(proc)
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(user_prompt(run).encode())
    await proc.stdin.drain()
    proc.stdin.close()
    stderr_task = asyncio.create_task(_tail(proc.stderr))

    verified = False
    result_event: dict[str, Any] | None = None
    timed_out = False

    async def consume() -> None:
        nonlocal verified, result_event
        assert proc.stdout is not None
        async for raw in proc.stdout:
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue
            kind = event.get("type")
            if kind == "system" and event.get("subtype") == "init" and not verified:
                problems = check_init(event, gate.run_tools(run))
                info = {
                    "kind": "claude-code",
                    "model": event.get("model"),
                    "claude_code_version": event.get("claude_code_version"),
                    "tools": event.get("tools"),
                    "permission_mode": event.get("permissionMode"),
                    "session_id": event.get("session_id"),
                    "lockdown_verified": not problems,
                }
                if problems:
                    _kill(proc)
                    recorder.emit(run.id, "agent.lockdown_failed", {"problems": problems, "agent": info})
                    gate.set_agent_info(run.id, info)
                    gate.fail_run(run.id, "lockdown check failed: " + "; ".join(problems))
                    return
                verified = True
                gate.start_run(run.id, agent=info)
            elif kind == "assistant":
                for block in (event.get("message") or {}).get("content") or []:
                    if block.get("type") == "text" and str(block.get("text", "")).strip():
                        recorder.emit(run.id, "agent.message", {"text": str(block["text"])[:4000]})
            elif kind == "result":
                result_event = event

    try:
        await asyncio.wait_for(consume(), timeout=time_limit)
    except TimeoutError:
        timed_out = True
        _kill(proc)
    finally:
        returncode = await proc.wait()
        stderr = await stderr_task
        config_path.unlink(missing_ok=True)

    if result_event is not None:
        recorder.emit(
            run.id,
            "agent.finished",
            {
                "is_error": result_event.get("is_error"),
                "subtype": result_event.get("subtype"),
                "num_turns": result_event.get("num_turns"),
                "duration_ms": result_event.get("duration_ms"),
                "total_cost_usd": result_event.get("total_cost_usd"),
                "returncode": returncode,
            },
        )

    current = gate.store.get_run(run.id)
    if current is None or current.state not in ACTIVE_RUN_STATES:
        if result_event is not None and result_event.get("result"):
            gate.complete_run(run.id, str(result_event["result"]))  # keeps the summary on stopped runs
        return
    if timed_out:
        gate.halt_run(run.id, f"agent exceeded the {int(time_limit)}s time limit")
    elif not verified:
        gate.fail_run(run.id, f"agent exited before initializing (exit {returncode}): {stderr[-500:]}")
    elif result_event is None or result_event.get("is_error") or returncode != 0:
        detail = (result_event or {}).get("result") or stderr[-500:]
        gate.fail_run(run.id, f"agent failed (exit {returncode}): {detail}")
    else:
        gate.complete_run(run.id, str(result_event.get("result") or ""))
