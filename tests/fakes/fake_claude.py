"""A stand-in for the `claude` CLI, for launcher tests.

It checks that the launcher passed the lockdown flags, reads the MCP config,
emits a stream-json init event, runs a scripted list of tool calls against
the MCP server, and emits a result event. Behaviour is controlled by env vars:

  CLAUDE_FAKE_TOOLS     JSON list of tool names to report in init (default: the 4 gateway tools)
  CLAUDE_FAKE_SCRIPT    JSON list of {"tool": ..., "args": {...}} to call
  CLAUDE_FAKE_SLEEP     seconds to sleep before exiting (to test cancel/timeout)
  CLAUDE_FAKE_CRASH     if set, exit 1 before emitting anything
  CLAUDE_FAKE_LOG       file to append the argv and prompt to
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

REQUIRED = [
    ("--tools", ""),
    ("--permission-mode", "dontAsk"),
    ("--setting-sources", ""),
    ("--allowedTools", "mcp__agentguard__*"),
    ("--output-format", "stream-json"),
]


def emit(event: dict) -> None:
    sys.stdout.write(json.dumps(event) + "\n")
    sys.stdout.flush()


def flag_value(argv: list[str], flag: str) -> str | None:
    if flag in argv:
        i = argv.index(flag)
        return argv[i + 1] if i + 1 < len(argv) else None
    return None


async def main() -> int:
    argv = sys.argv[1:]
    prompt = sys.stdin.read()
    if os.environ.get("CLAUDE_FAKE_LOG"):
        with open(os.environ["CLAUDE_FAKE_LOG"], "a") as f:
            f.write(
                json.dumps(
                    {
                        "argv": argv,
                        "prompt": prompt,
                        "env_idle": os.environ.get("CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT"),
                        "env_keys": sorted(os.environ),
                    }
                )
                + "\n"
            )
    if os.environ.get("CLAUDE_FAKE_CRASH"):
        sys.stderr.write("fake claude: simulated crash\n")
        return 1
    for flag, value in REQUIRED:
        if flag_value(argv, flag) != value:
            sys.stderr.write(f"fake claude: missing lockdown flag {flag} {value!r}\n")
            return 3
    if "--strict-mcp-config" not in argv or "-p" not in argv:
        sys.stderr.write("fake claude: missing -p or --strict-mcp-config\n")
        return 3

    config = json.loads(Path(flag_value(argv, "--mcp-config") or "").read_text())
    server = config["mcpServers"]["agentguard"]
    default_tools = [
        f"mcp__agentguard__{t}" for t in ("block_ip", "get_ip_activity", "get_user_logins", "http_post")
    ]
    tools = json.loads(os.environ.get("CLAUDE_FAKE_TOOLS", json.dumps(default_tools)))
    emit(
        {
            "type": "system",
            "subtype": "init",
            "tools": tools,
            "mcp_servers": [{"name": "agentguard", "status": "connected"}],
            "model": flag_value(argv, "--model"),
            "claude_code_version": "fake",
            "permissionMode": flag_value(argv, "--permission-mode"),
            "session_id": "fake-session",
        }
    )
    script = json.loads(os.environ.get("CLAUDE_FAKE_SCRIPT", "[]"))
    outcomes = []
    if script:
        async with (
            httpx2.AsyncClient(headers=server["headers"], timeout=httpx2.Timeout(30, read=600)) as http,
            Client(streamable_http_client(server["url"], http_client=http)) as client,
        ):
            for step in script:
                emit(
                    {
                        "type": "assistant",
                        "message": {"content": [{"type": "text", "text": f"Calling {step['tool']}"}]},
                    }
                )
                res = await client.call_tool(step["tool"], step.get("args", {}), read_timeout_seconds=600)
                text = "".join(getattr(c, "text", "") for c in res.content)
                outcomes.append(f"{step['tool']}={'error' if res.is_error else 'ok'}")
                emit(
                    {"type": "user", "message": {"content": [{"type": "tool_result", "content": text[:200]}]}}
                )
    time.sleep(float(os.environ.get("CLAUDE_FAKE_SLEEP", "0")))
    summary = "Fake summary citing EVT-0004 and EVT-0022. Outcomes: " + ", ".join(outcomes)
    emit({"type": "assistant", "message": {"content": [{"type": "text", "text": summary}]}})
    emit(
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "result": summary,
            "num_turns": len(script) + 1,
            "duration_ms": 10,
            "total_cost_usd": 0.0,
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
