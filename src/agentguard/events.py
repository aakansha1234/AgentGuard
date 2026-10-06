"""Audit events: persisted first, then broadcast to live subscribers."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any

from agentguard.store import EventRecord, Store

ALL_RUNS = "*"


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[EventRecord]]] = defaultdict(set)

    def subscribe(self, run_id: str = ALL_RUNS) -> asyncio.Queue[EventRecord]:
        queue: asyncio.Queue[EventRecord] = asyncio.Queue(maxsize=10_000)
        self._subscribers[run_id].add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[EventRecord], run_id: str = ALL_RUNS) -> None:
        self._subscribers[run_id].discard(queue)

    def publish(self, event: EventRecord) -> None:
        for key in (event.run_id, ALL_RUNS):
            for queue in list(self._subscribers.get(key, ())):
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    # A stuck subscriber must not block the gate; it can resume from the DB.
                    self._subscribers[key].discard(queue)


class Recorder:
    """The only way events are written: store, then publish."""

    def __init__(self, store: Store, bus: EventBus) -> None:
        self.store = store
        self.bus = bus

    def emit(
        self, run_id: str, type_: str, payload: dict[str, Any] | None = None, action_id: str | None = None
    ) -> EventRecord:
        event = self.store.append_event(run_id, type_, payload or {}, action_id)
        self.bus.publish(event)
        return event
