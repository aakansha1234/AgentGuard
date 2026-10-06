from __future__ import annotations

import os
import socket
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentguard.config import PROJECT_ROOT
from agentguard.events import EventBus, Recorder
from agentguard.gate import Gatekeeper
from agentguard.models import Enforcement, RunMode
from agentguard.policy import Policy, PolicyProvider
from agentguard.reviewers.base import Reviewer
from agentguard.store import RunRecord, Store
from agentguard.tools import DatasetStore, soc_registry

# Tests never load the developer's .env (it may hold real API keys).
os.environ["AGENTGUARD_DOTENV"] = ""

POLICY_PATH = PROJECT_ROOT / "policies" / "default.yaml"
DATASETS = PROJECT_ROOT / "fixtures" / "datasets"


class FakeClock:
    def __init__(self) -> None:
        self.t = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += timedelta(seconds=seconds)


class GateEnv:
    def __init__(
        self, tmp_path: Path, reviewer: Reviewer | None = None, policy_text: str | None = None
    ) -> None:
        self.clock = FakeClock()
        self.registry = soc_registry()
        self.policy_path = tmp_path / "policy.yaml"
        self.policy_path.write_text(policy_text or POLICY_PATH.read_text())
        self.policies = PolicyProvider(self.policy_path, self.registry)
        self.store = Store(tmp_path / "test.db", clock=self.clock)
        self.bus = EventBus()
        self.recorder = Recorder(self.store, self.bus)
        self.datasets = DatasetStore(DATASETS)
        self.gate = Gatekeeper(
            store=self.store,
            recorder=self.recorder,
            registry=self.registry,
            policies=self.policies,
            datasets=self.datasets,
            reviewer=reviewer,
            clock=self.clock,
            approval_poll_seconds=0.02,
        )

    def run(
        self,
        *,
        dataset: str = "baseline",
        subject: str = "alice",
        enforcement: Enforcement = Enforcement.ENFORCE,
        task: str = "Investigate Alice's failed logins.",
        start: bool = True,
        mode: RunMode = RunMode.REPLAY,
    ) -> RunRecord:
        run, _token = self.gate.create_run(
            owner="tester",
            task=task,
            mode=mode,
            dataset_id=dataset,
            subject=subject,
            enforcement=enforcement,
        )
        if start:
            self.gate.start_run(run.id)
        fresh = self.store.get_run(run.id)
        assert fresh is not None
        return fresh

    def set_policy(self, mutate: str, replacement: str) -> Policy:
        text = self.policy_path.read_text()
        assert mutate in text, mutate
        self.policy_path.write_text(text.replace(mutate, replacement))
        return self.policies.reload()

    def event_types(self, run_id: str) -> list[str]:
        return [e.type for e in self.store.events_after(run_id)]


@pytest.fixture
def env(tmp_path: Path) -> Iterator[GateEnv]:
    e = GateEnv(tmp_path)
    yield e
    e.store.close()


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Fail loudly if anything opens an outbound connection; record attempts."""
    attempts: list[object] = []

    def refuse(self: socket.socket, address: object) -> None:
        attempts.append(address)
        raise AssertionError(f"unexpected network connection to {address!r}")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    return attempts
