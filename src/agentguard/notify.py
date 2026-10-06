"""Alerts when a human is needed: a webhook message per approval request or halted run.

Set AGENTGUARD_NOTIFY_WEBHOOK to a Slack incoming-webhook URL (or anything that
accepts the same JSON). AGENTGUARD_NOTIFY_FORMAT=json sends the raw event
instead. Every attempt is recorded in the run's audit log as notify.sent or
notify.failed; the webhook URL itself (a secret) never is.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import Any

import httpx2

from agentguard.events import EventBus, Recorder
from agentguard.store import EventRecord

log = logging.getLogger(__name__)

NOTIFY_TYPES = ("approval.requested", "run.halted")
FORMATS = ("slack", "json")


def _args(args: Any) -> str:
    text = ", ".join(f"{k}={v!r}" for k, v in args.items()) if isinstance(args, dict) else repr(args)
    return text if len(text) <= 300 else text[:297] + "..."


def message(event: EventRecord, dashboard_url: str) -> str:
    p = event.payload
    link = f"{dashboard_url}/#run={event.run_id}"
    if event.type == "approval.requested":
        rules = ", ".join(p.get("rule_ids") or []) or "policy"
        return (
            f":warning: AgentGuard needs a decision: {p.get('tool')}({_args(p.get('args'))})\n"
            f"Why: {rules}. {p.get('explanation') or ''}\n"
            f"Expires {p.get('expires_at')}. Nothing happens unless someone approves.\n"
            f"Review: {link}"
        )
    reason = p.get("reason", "halted")
    return f":octagonal_sign: AgentGuard stopped run {event.run_id}: {reason}\nDetails: {link}"


class Notifier:
    def __init__(
        self,
        *,
        url: str,
        fmt: str,
        dashboard_url: str,
        bus: EventBus | None,
        recorder: Recorder | None,
        http: httpx2.AsyncClient | None = None,
    ) -> None:
        if fmt not in FORMATS:
            raise ValueError(f"AGENTGUARD_NOTIFY_FORMAT must be one of {', '.join(FORMATS)}")
        self._url = url
        self._fmt = fmt
        self._dashboard = dashboard_url.rstrip("/")
        self._bus = bus
        self._recorder = recorder
        self._http = http or httpx2.AsyncClient(timeout=10)
        self._task: asyncio.Task[None] | None = None

    def body(self, event: EventRecord) -> dict[str, Any]:
        if self._fmt == "json":
            return {
                "type": event.type,
                "run_id": event.run_id,
                "action_id": event.action_id,
                "ts": event.ts,
                "payload": event.payload,
                "dashboard": f"{self._dashboard}/#run={event.run_id}",
            }
        return {"text": message(event, self._dashboard)}

    async def send(self, event: EventRecord) -> bool:
        body = json.dumps(self.body(event), default=str)
        error = ""
        for attempt in range(3):
            try:
                headers = {"Content-Type": "application/json"}
                r = await self._http.post(self._url, content=body, headers=headers)
                if r.status_code < 300:
                    self._record(event, "notify.sent", {"event": event.type})
                    return True
                error = f"HTTP {r.status_code}"
            except httpx2.HTTPError as exc:
                error = type(exc).__name__
            await asyncio.sleep(0.5 * (attempt + 1))
        log.warning("notification for %s failed: %s", event.type, error)
        self._record(event, "notify.failed", {"event": event.type, "error": error})
        return False

    def _record(self, event: EventRecord, type_: str, payload: dict[str, Any]) -> None:
        if self._recorder is not None:
            self._recorder.emit(event.run_id, type_, payload, event.action_id)

    async def _loop(self) -> None:
        assert self._bus is not None, "start() needs an event bus"
        queue = self._bus.subscribe()
        try:
            while True:
                event = await queue.get()
                if event.type in NOTIFY_TYPES:
                    await self.send(event)
        finally:
            self._bus.unsubscribe(queue)

    def start(self) -> None:
        self._task = asyncio.get_running_loop().create_task(self._loop(), name="agentguard-notifier")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        await self._http.aclose()
