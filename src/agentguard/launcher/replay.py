"""Replay agent: sends a fixed script of tool calls through the real MCP gateway.

It is an ordinary MCP client holding only a run token, so replayed proposals
take exactly the same path (and get exactly the same checks) as a live model's.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from agentguard.events import Recorder
from agentguard.scenarios import ReplayScript


@dataclass
class StepOutcome:
    tool: str
    is_error: bool
    text: str


@dataclass
class ReplayResult:
    outcomes: list[StepOutcome] = field(default_factory=list)
    summary: str = ""


def _outcome_line(o: StepOutcome) -> str:
    text = o.text
    if not o.is_error:
        return f"- {o.tool}: executed"
    if "declined" in text:
        return f"- {o.tool}: declined by a human, not executed"
    if "expired" in text:
        return f"- {o.tool}: approval expired, not executed"
    if "blocked" in text:
        return f"- {o.tool}: blocked by policy, not executed"
    return f"- {o.tool}: not executed"


async def run_replay(
    *,
    mcp_url: str,
    token: str,
    run_id: str,
    script: ReplayScript,
    recorder: Recorder,
    is_active: Callable[[], bool],
    call_timeout: float = 900.0,
) -> ReplayResult:
    result = ReplayResult()
    headers = {"Authorization": f"Bearer {token}"}
    timeout = httpx2.Timeout(30.0, read=call_timeout)
    async with (
        httpx2.AsyncClient(headers=headers, timeout=timeout) as http,
        Client(streamable_http_client(mcp_url, http_client=http)) as client,
    ):
        for step in script.steps:
            if not is_active():
                break
            if step.say:
                recorder.emit(run_id, "agent.message", {"text": step.say, "replay": True})
            res = await client.call_tool(step.tool, step.args, read_timeout_seconds=call_timeout)
            text = "".join(getattr(c, "text", "") for c in res.content)
            result.outcomes.append(StepOutcome(step.tool, bool(res.is_error), text))
    lines = [_outcome_line(o) for o in result.outcomes]
    result.summary = script.summary.strip() + "\n\nOutcome of each scripted action:\n" + "\n".join(lines)
    return result
