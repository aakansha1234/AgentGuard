"""Demo scenarios and replay scripts (fixtures/scenarios.yaml, fixtures/replay/*.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Scenario(_Strict):
    id: str
    title: str
    description: str
    dataset: str
    subject: str
    replay: str
    task: str
    # Which agent mode shows this scenario best. Scenarios about a mistake or a
    # successful trick default to replay: a live model usually doesn't make it.
    recommended_mode: Literal["live", "replay"] = "replay"
    # The tools the agent gets for this scenario. None: every tool AgentGuard offers.
    tools: list[str] | None = None


class ReplayStep(_Strict):
    say: str | None = None
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class ReplayScript(_Strict):
    id: str
    note: str | None = None
    steps: list[ReplayStep]
    summary: str


class ScenarioCatalog:
    def __init__(self, fixtures_dir: Path) -> None:
        raw = yaml.safe_load((fixtures_dir / "scenarios.yaml").read_text())
        self.scenarios = {s["id"]: Scenario.model_validate(s) for s in raw["scenarios"]}
        self._replay_dir = fixtures_dir / "replay"

    def get(self, scenario_id: str) -> Scenario:
        return self.scenarios[scenario_id]

    def list(self) -> list[Scenario]:
        return list(self.scenarios.values())

    def script(self, replay_id: str) -> ReplayScript:
        if replay_id not in {p.stem for p in self._replay_dir.glob("*.yaml")}:
            raise KeyError(replay_id)
        return ReplayScript.model_validate(
            yaml.safe_load((self._replay_dir / f"{replay_id}.yaml").read_text())
        )
