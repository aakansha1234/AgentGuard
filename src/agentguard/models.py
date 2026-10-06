"""Shared enums and value types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ActionState(StrEnum):
    PROPOSED = "proposed"
    DENIED = "denied"
    PENDING_APPROVAL = "pending_approval"
    ALLOWED = "allowed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    INVALIDATED = "invalidated"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


# An action in one of these states can never run.
TERMINAL_NOT_EXECUTED = frozenset(
    {
        ActionState.DENIED,
        ActionState.REJECTED,
        ActionState.EXPIRED,
        ActionState.CANCELLED,
        ActionState.INVALIDATED,
    }
)


class RunState(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    HALTED = "halted"


ACTIVE_RUN_STATES = frozenset({RunState.CREATED, RunState.RUNNING})


class RunMode(StrEnum):
    LIVE = "live"  # Claude Code launched by AgentGuard
    REPLAY = "replay"  # scripted proposals sent through the same gateway
    EXTERNAL = "external"  # any MCP client the operator connects with a run token


class Enforcement(StrEnum):
    ENFORCE = "enforce"
    SHADOW = "shadow"  # record what would have been blocked, block nothing


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    effect: Effect
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "effect": self.effect.value, "description": self.description}


@dataclass
class Decision:
    """Outcome of evaluating one proposed action."""

    effect: Effect
    source: str  # "builtin", "policy" or "reviewer"
    decisive: list[RuleHit]
    matched: list[RuleHit] = field(default_factory=list)
    policy_version: str = ""
    halt: bool = False
    counts_as_strike: bool = False
    review: dict[str, Any] | None = None

    @property
    def rule_ids(self) -> list[str]:
        return [h.rule_id for h in self.decisive]

    @property
    def explanation(self) -> str:
        return " ".join(h.description for h in self.decisive)

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect.value,
            "source": self.source,
            "rule_ids": self.rule_ids,
            "explanation": self.explanation,
            "decisive": [h.to_dict() for h in self.decisive],
            "matched": [h.to_dict() for h in self.matched],
            "policy_version": self.policy_version,
            "halt": self.halt,
            "review": self.review,
        }
