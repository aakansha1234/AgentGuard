"""Starts, tracks and stops agent runs (live Claude Code, replay scripts, external agents)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from agentguard.config import Settings
from agentguard.events import Recorder
from agentguard.gate import Gatekeeper
from agentguard.launcher.claude_code import _kill, run_claude_code
from agentguard.launcher.replay import run_replay
from agentguard.models import ACTIVE_RUN_STATES, Enforcement, RunMode
from agentguard.policy import PolicyProvider
from agentguard.scenarios import ScenarioCatalog
from agentguard.store import RunRecord
from agentguard.tools.base import ToolRegistry

log = logging.getLogger(__name__)


class RunManager:
    def __init__(
        self,
        *,
        settings: Settings,
        gate: Gatekeeper,
        recorder: Recorder,
        registry: ToolRegistry,
        policies: PolicyProvider,
        scenarios: ScenarioCatalog,
    ) -> None:
        self.settings = settings
        self.gate = gate
        self.recorder = recorder
        self.registry = registry
        self.policies = policies
        self.scenarios = scenarios
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._procs: dict[str, asyncio.subprocess.Process] = {}
        gate.on_run_stopped = self._on_stopped

    def _is_active(self, run_id: str) -> bool:
        run = self.gate.store.get_run(run_id)
        return run is not None and run.state in ACTIVE_RUN_STATES

    def _on_stopped(self, run_id: str, state: str) -> None:
        proc = self._procs.get(run_id)
        if proc is not None:
            _kill(proc)

    def create(
        self,
        *,
        owner: str,
        task: str,
        mode: RunMode,
        dataset_id: str,
        subject: str,
        enforcement: Enforcement,
        scenario: str | None,
        tools: list[str] | None = None,
    ) -> tuple[RunRecord, str]:
        if mode == RunMode.REPLAY:
            if scenario is None:
                raise ValueError("replay runs need a scenario")
            self.scenarios.script(self.scenarios.get(scenario).replay)  # validate early
        if mode == RunMode.LIVE and not self.settings.claude_available():
            raise ValueError(f"Claude Code CLI not found ({self.settings.claude_bin!r})")
        if tools is None and scenario is not None:
            tools = self.scenarios.get(scenario).tools
        run, token = self.gate.create_run(
            owner=owner,
            task=task,
            mode=mode,
            dataset_id=dataset_id,
            subject=subject,
            enforcement=enforcement,
            scenario=scenario,
            tools=tools,
        )
        if mode == RunMode.REPLAY:
            self._spawn(run.id, self._replay(run, token))
        elif mode == RunMode.LIVE:
            self._spawn(run.id, self._live(run, token))
        return run, token

    def _spawn(self, run_id: str, coro: Any) -> None:
        task = asyncio.get_running_loop().create_task(coro, name=f"run-{run_id}")
        self._tasks[run_id] = task

        def _done(t: asyncio.Task[None]) -> None:
            self._tasks.pop(run_id, None)
            self._procs.pop(run_id, None)
            if not t.cancelled() and t.exception() is not None:
                log.error("run %s crashed", run_id, exc_info=t.exception())
                self.gate.fail_run(run_id, f"internal error: {t.exception()}")

        task.add_done_callback(_done)

    async def _replay(self, run: RunRecord, token: str) -> None:
        scenario = self.scenarios.get(run.scenario or "")
        script = self.scenarios.script(scenario.replay)
        self.gate.start_run(run.id, agent={"kind": "replay", "script": script.id, "note": script.note})
        try:
            result = await run_replay(
                mcp_url=self.settings.mcp_url,
                token=token,
                run_id=run.id,
                script=script,
                recorder=self.recorder,
                is_active=lambda: self._is_active(run.id),
            )
        except Exception as exc:
            if self._is_active(run.id):
                self.gate.fail_run(run.id, f"replay client error: {exc}")
            return
        self.gate.complete_run(run.id, result.summary)

    async def _live(self, run: RunRecord, token: str) -> None:
        limit = float(self.policies.current().doc.limits.max_run_seconds) + 15.0
        await run_claude_code(
            settings=self.settings,
            registry=self.registry,
            recorder=self.recorder,
            gate=self.gate,
            run=run,
            token=token,
            register_process=lambda p: self._procs.__setitem__(run.id, p),
            time_limit=limit,
        )

    def cancel(self, run_id: str, actor: str) -> bool:
        stopped = self.gate.cancel_run(run_id, actor)
        proc = self._procs.get(run_id)
        if proc is not None:
            _kill(proc)
        return stopped

    async def shutdown(self) -> None:
        for proc in list(self._procs.values()):
            _kill(proc)
        for task in list(self._tasks.values()):
            task.cancel()
        for task in list(self._tasks.values()):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
