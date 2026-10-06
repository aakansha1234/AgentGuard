"""Wires the components together."""

from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass

from agentguard.config import Settings
from agentguard.events import EventBus, Recorder
from agentguard.gate import Gatekeeper
from agentguard.launcher.runner import RunManager
from agentguard.policy import PolicyProvider
from agentguard.reviewers.base import Reviewer
from agentguard.scenarios import ScenarioCatalog
from agentguard.store import Clock, Store, utcnow
from agentguard.tools import DatasetStore, ToolRegistry, soc_registry
from agentguard.tools.upstream import UpstreamPool, load_upstream_tools


@dataclass
class Services:
    settings: Settings
    store: Store
    bus: EventBus
    recorder: Recorder
    registry: ToolRegistry
    policies: PolicyProvider
    datasets: DatasetStore
    scenarios: ScenarioCatalog
    gate: Gatekeeper
    runs: RunManager
    reviewer: Reviewer | None
    upstreams: UpstreamPool | None = None

    @property
    def reviewer_name(self) -> str | None:
        return None if self.reviewer is None else self.reviewer.name


REVIEWER_MODES = ("jev", "clef", "human")


class ReviewerConfigError(RuntimeError):
    """The chosen reviewer mode can't run. Never fall back to another mode."""


def _require_env(mode: str, *names: str) -> None:
    missing = [n for n in names if not os.environ.get(n, "").strip()]
    if missing:
        raise ReviewerConfigError(
            f"AGENTGUARD_REVIEWER={mode} needs {', '.join(missing)} (set it in the environment or .env)"
        )


def make_reviewer(settings: Settings) -> Reviewer | None:
    """Build the reviewer for AGENTGUARD_REVIEWER. `human` means no model: reviewed actions wait for you."""
    mode = settings.reviewer
    if not mode:
        raise ReviewerConfigError(
            f"AGENTGUARD_REVIEWER is not set; choose one of: {', '.join(REVIEWER_MODES)} (in env or .env)"
        )
    if mode == "jev":
        _require_env(mode, "TYPESAFE_API_KEY")
        if importlib.util.find_spec("typesafe_sdk") is None:
            raise ReviewerConfigError("AGENTGUARD_REVIEWER=jev needs typesafe-sdk: run `uv sync --extra jev`")
        from agentguard.reviewers.jev import JevReviewer

        return JevReviewer()
    if mode == "clef":
        _require_env(mode, "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN")
        from agentguard.reviewers.clef import ClefReviewer

        return ClefReviewer()
    if mode == "human":
        return None
    raise ReviewerConfigError(
        f"unknown AGENTGUARD_REVIEWER={mode!r}; choose one of: {', '.join(REVIEWER_MODES)}"
    )


def build_registry(settings: Settings) -> tuple[ToolRegistry, UpstreamPool | None]:
    """Built-in tools plus the tools of every configured upstream MCP server."""
    pool, upstream_specs = load_upstream_tools(settings.upstreams_path)
    demo = soc_registry().all() if settings.demo_tools else []
    return ToolRegistry([*demo, *upstream_specs]), pool


def build_services(
    settings: Settings,
    *,
    reviewer: Reviewer | None = None,
    clock: Clock = utcnow,
    approval_poll_seconds: float = 10.0,
) -> Services:
    settings.ensure_operator_token()
    store = Store(settings.db_path, clock=clock)
    bus = EventBus()
    recorder = Recorder(store, bus)
    reviewer = reviewer if reviewer is not None else make_reviewer(settings)
    registry, upstreams = build_registry(settings)
    policies = PolicyProvider(settings.policy_path, registry)
    datasets = DatasetStore(settings.fixtures_dir / "datasets")
    scenarios = ScenarioCatalog(settings.fixtures_dir)
    gate = Gatekeeper(
        store=store,
        recorder=recorder,
        registry=registry,
        policies=policies,
        datasets=datasets,
        reviewer=reviewer,
        clock=clock,
        approval_poll_seconds=approval_poll_seconds,
    )
    runs = RunManager(
        settings=settings,
        gate=gate,
        recorder=recorder,
        registry=registry,
        policies=policies,
        scenarios=scenarios,
    )
    return Services(
        settings,
        store,
        bus,
        recorder,
        registry,
        policies,
        datasets,
        scenarios,
        gate,
        runs,
        reviewer,
        upstreams,
    )
