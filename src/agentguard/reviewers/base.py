"""Reviewer interface.

A reviewer looks at a proposed action that the deterministic policy already
allowed and may escalate it to human approval. It can never relax a denial or
skip an approval: the gate only calls it when the policy's answer is `allow`.

Reviewers see trusted inputs only (the task, the proposed call, tool labels,
the run's history of tool names and outcomes, and IP addresses parsed out of
the evidence), never raw tool output, because raw logs can carry text written
to steer a model.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ReviewInput:
    task: str
    subject: str
    tool: str
    tool_description: str
    labels: list[str]
    args: dict[str, Any]
    session_labels: list[str]
    prior_actions: list[str] = field(default_factory=list)
    # IP addresses that appeared in evidence earlier in the run. Parsed and
    # canonicalized by the gate, so they cannot carry injected instructions.
    evidence_ips: list[str] = field(default_factory=list)

    def to_state(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReviewResult:
    escalate: bool
    scores: dict[str, float]
    reason: str
    reviewer: str
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Reviewer(Protocol):
    name: str

    async def review(self, inp: ReviewInput, threshold: float) -> ReviewResult: ...


class StaticReviewer:
    """Deterministic reviewer for tests and demos: escalates tools listed in `escalate_tools`."""

    def __init__(
        self, escalate_tools: set[str] | None = None, fail: bool = False, delay: float = 0.0
    ) -> None:
        self.name = "static"
        self.escalate_tools = escalate_tools or set()
        self.fail = fail
        self.delay = delay
        self.calls: list[ReviewInput] = []

    async def review(self, inp: ReviewInput, threshold: float) -> ReviewResult:
        import asyncio

        self.calls.append(inp)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise RuntimeError("reviewer backend unavailable")
        score = 0.95 if inp.tool in self.escalate_tools else 0.05
        return ReviewResult(
            escalate=score >= threshold,
            scores={"out_of_scope": score},
            reason="tool flagged by static reviewer" if score >= threshold else "no concerns",
            reviewer=self.name,
        )
