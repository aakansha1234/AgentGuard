"""Fixture datasets of login events.

Every string field in an event is untrusted: it came from log sources an
attacker can influence (user agents, free-text messages).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class LoginEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    ts: datetime
    user: str
    src_ip: str
    outcome: Literal["failure", "success"]
    method: str
    user_agent: str
    message: str

    def to_json(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class DatasetFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    description: str
    untrusted_test_data: bool
    events: list[LoginEvent]


@dataclass(frozen=True)
class Dataset:
    id: str
    title: str
    description: str
    events: tuple[LoginEvent, ...]

    @property
    def event_ids(self) -> frozenset[str]:
        return frozenset(e.id for e in self.events)

    @property
    def users(self) -> frozenset[str]:
        return frozenset(e.user for e in self.events)


class DatasetStore:
    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._cache: dict[str, Dataset] = {}

    def ids(self) -> list[str]:
        return sorted(p.stem for p in self._dir.glob("*.json"))

    def get(self, dataset_id: str) -> Dataset:
        if dataset_id not in self._cache:
            if dataset_id not in self.ids():
                raise KeyError(f"unknown dataset: {dataset_id}")
            raw = json.loads((self._dir / f"{dataset_id}.json").read_text())
            parsed = DatasetFile.model_validate(raw)
            if parsed.id != dataset_id:
                raise ValueError(f"dataset file {dataset_id}.json declares id {parsed.id}")
            events = tuple(sorted(parsed.events, key=lambda e: (e.ts, e.id)))
            self._cache[dataset_id] = Dataset(parsed.id, parsed.title, parsed.description, events)
        return self._cache[dataset_id]
