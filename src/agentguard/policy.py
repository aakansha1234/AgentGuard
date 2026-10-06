"""Policy schema, loader and deterministic evaluator.

Semantics:
- A rule applies when its `match` selects the tool (by name or label, any-of)
  and every condition in `when` holds.
- Any applicable deny rule wins. Otherwise any applicable require_approval
  rule wins. Otherwise an applicable allow rule permits. Otherwise the call is
  denied by default.
- A condition that cannot be evaluated (missing value, wrong type) raises
  PolicyEvaluationError; the gate turns that into a denial (fail closed).
"""

from __future__ import annotations

import ipaddress
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from agentguard.canonical import canonical_json, sha256_hex
from agentguard.models import Decision, Effect, RuleHit
from agentguard.tools.base import ToolRegistry

PATH_ROOTS = frozenset({"args", "facts", "run", "session", "tool"})

Op = Literal[
    "eq",
    "ne",
    "in",
    "not_in",
    "in_cidr",
    "not_in_cidr",
    "lt",
    "lte",
    "gt",
    "gte",
    "contains",
    "not_contains",
    "host_in",
    "host_not_in",
    "mentioned_in",
    "not_mentioned_in",
    "exists",
]
_NUMERIC_OPS = {"lt", "lte", "gt", "gte"}
_CIDR_OPS = {"in_cidr", "not_in_cidr"}
UPSTREAM_SEPARATOR = "__"
# Labels policies may use even when no current tool carries them (upstream tools get
# these from their MCP annotations; see tools/upstream.py).
STANDARD_LABELS = frozenset({"read_only", "reads_private", "ingests_untrusted", "side_effect", "egress"})
_LIST_OPS = {"in", "not_in", "in_cidr", "not_in_cidr", "host_in", "host_not_in"}


class PolicyError(Exception):
    """The policy file is invalid."""


class PolicyEvaluationError(Exception):
    def __init__(self, rule_id: str, message: str) -> None:
        super().__init__(f"{rule_id}: {message}")
        self.rule_id = rule_id


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


def _check_path(path: str) -> str:
    parts = path.split(".")
    if parts[0] not in PATH_ROOTS or len(parts) < 2 or any(not p for p in parts):
        raise ValueError(f"invalid path {path!r}; must start with one of {sorted(PATH_ROOTS)}")
    return path


class Condition(_Strict):
    path: str
    op: Op
    value: Any = None
    ref: str | None = None
    list_name: str | None = Field(default=None, alias="list")

    @model_validator(mode="after")
    def _shape(self) -> Condition:
        _check_path(self.path)
        if self.ref is not None:
            _check_path(self.ref)
        sources = sum(x is not None for x in (self.value, self.ref, self.list_name))
        if self.op == "exists":
            if not isinstance(self.value, bool) or self.ref or self.list_name:
                raise ValueError("'exists' takes value: true or false")
            return self
        if sources != 1:
            raise ValueError("a condition needs exactly one of value, ref or list")
        if self.op in _NUMERIC_OPS and self.value is not None and not isinstance(self.value, int | float):
            raise ValueError(f"{self.op} needs a numeric value")
        if self.op in _LIST_OPS and self.value is not None and not isinstance(self.value, list):
            raise ValueError(f"{self.op} needs a list value")
        if self.op in _CIDR_OPS and isinstance(self.value, list):
            for cidr in self.value:
                ipaddress.ip_network(cidr, strict=False)
        return self


class Match(_Strict):
    tools: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _nonempty(self) -> Match:
        if not self.tools and not self.labels:
            raise ValueError("match needs tools or labels")
        return self

    def selects(self, tool_name: str, tool_labels: frozenset[str]) -> bool:
        return tool_name in self.tools or bool(tool_labels.intersection(self.labels))


class Rule(_Strict):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
    description: str = Field(min_length=1, max_length=300)
    effect: Effect
    match: Match
    when: list[Condition] = Field(default_factory=list)
    halt: bool = False

    @model_validator(mode="after")
    def _halt_only_on_deny(self) -> Rule:
        if self.halt and self.effect != Effect.DENY:
            raise ValueError("halt is only valid on deny rules")
        return self


class Limits(_Strict):
    max_tool_calls: int = Field(ge=1, le=1000)
    max_run_seconds: int = Field(ge=10, le=86400)
    max_policy_denials: int = Field(ge=1, le=100)


class ReviewerPolicy(_Strict):
    """Optional model-based reviewer. It can only escalate allow -> require_approval."""

    enabled: bool = False
    review_labels: list[str] = Field(default_factory=list)
    fail_closed_labels: list[str] = Field(default_factory=list)
    escalate_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    timeout_seconds: float = Field(default=3.0, gt=0, le=30)


class PolicyDoc(_Strict):
    schema_version: Literal[1]
    name: str
    description: str = ""
    default_effect: Literal["deny"] = "deny"
    approval_ttl_seconds: int = Field(ge=10, le=3600)
    on_human_deny: Literal["continue", "halt"] = "continue"
    limits: Limits
    lists: dict[str, list[str]] = Field(default_factory=dict)
    reviewer: ReviewerPolicy = Field(default_factory=ReviewerPolicy)
    rules: list[Rule]


@dataclass(frozen=True)
class EvalContext:
    tool: str
    labels: frozenset[str]
    args: dict[str, Any]
    facts: dict[str, Any]
    run: dict[str, Any]
    session: dict[str, Any]

    def as_tree(self) -> dict[str, Any]:
        return {
            "tool": {"name": self.tool, "labels": sorted(self.labels)},
            "args": self.args,
            "facts": self.facts,
            "run": self.run,
            "session": self.session,
        }


_MISSING = object()


def _resolve(tree: dict[str, Any], path: str) -> Any:
    node: Any = tree
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _ip(value: Any, rule_id: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        ip = ipaddress.ip_address(value.strip() if isinstance(value, str) else value)
    except (ValueError, TypeError) as exc:
        raise PolicyEvaluationError(rule_id, f"not an IP address: {value!r}") from exc
    # ::ffff:10.0.0.1 is 10.0.0.1: fold it so it can't slip past IPv4 CIDR rules. Built-in
    # tools canonicalize IPs already; upstream tools pass their arguments through as given.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _mentioned(token: str, text: str) -> bool:
    """True if `token` appears in `text` as a whole token (10.0.0.1 is not in 10.0.0.15)."""
    pattern = r"(?<![0-9A-Za-z.:_-])" + re.escape(token) + r"(?![0-9A-Za-z:_-]|\.[0-9A-Za-z])"
    return re.search(pattern, text) is not None


def _host_matches(host: str, domains: list[Any]) -> bool:
    host = host.lower().rstrip(".")
    for d in domains:
        d = str(d).lower().rstrip(".")
        if host == d or host.endswith("." + d):
            return True
    return False


class Policy:
    def __init__(
        self, doc: PolicyDoc, source_text: str, inactive_rules: frozenset[str] = frozenset()
    ) -> None:
        self.doc = doc
        self.source_text = source_text
        # Rules that only name tools of upstream servers that aren't connected.
        self.inactive_rules = inactive_rules
        self.version = "p-" + sha256_hex(canonical_json(doc.model_dump(mode="json", by_alias=True)))[:12]

    @classmethod
    def parse(cls, text: str, registry: ToolRegistry) -> Policy:
        try:
            raw = yaml.safe_load(text)
            doc = PolicyDoc.model_validate(raw)
        except (yaml.YAMLError, ValidationError) as exc:
            raise PolicyError(str(exc)) from exc
        cls._cross_check(doc, registry)
        known = set(registry.names())
        inactive = frozenset(
            r.id for r in doc.rules if r.match.tools and not r.match.labels and not known & set(r.match.tools)
        )
        return cls(doc, text, inactive)

    @classmethod
    def load(cls, path: Path, registry: ToolRegistry) -> Policy:
        return cls.parse(path.read_text(), registry)

    @staticmethod
    def _cross_check(doc: PolicyDoc, registry: ToolRegistry) -> None:
        ids = [r.id for r in doc.rules]
        if len(ids) != len(set(ids)):
            raise PolicyError("rule ids must be unique")
        known_tools = set(registry.names())
        known_labels = registry.labels() | STANDARD_LABELS
        sources = registry.sources()
        for rule in doc.rules:
            # A rule for an upstream server that isn't connected stays inactive, so one
            # policy can cover optional integrations. A typo in a connected server's
            # tool name, or in a built-in tool's name, is still an error.
            unknown = {
                t
                for t in set(rule.match.tools) - known_tools
                if UPSTREAM_SEPARATOR not in t or t.split(UPSTREAM_SEPARATOR, 1)[0] in sources
            }
            if unknown:
                raise PolicyError(f"rule {rule.id} names unknown tools {sorted(unknown)}")
            unknown_labels = set(rule.match.labels) - known_labels
            if unknown_labels:
                raise PolicyError(f"rule {rule.id} names unknown labels {sorted(unknown_labels)}")
            for cond in rule.when:
                if cond.list_name is not None:
                    if cond.list_name not in doc.lists:
                        raise PolicyError(f"rule {rule.id} references unknown list {cond.list_name!r}")
                    if cond.op in _CIDR_OPS:
                        for cidr in doc.lists[cond.list_name]:
                            try:
                                ipaddress.ip_network(cidr, strict=False)
                            except ValueError as exc:
                                raise PolicyError(f"list {cond.list_name!r}: bad CIDR {cidr!r}") from exc

    # -- evaluation -------------------------------------------------------

    def _operand(self, cond: Condition, tree: dict[str, Any], rule_id: str) -> Any:
        if cond.ref is not None:
            value = _resolve(tree, cond.ref)
            if value is _MISSING:
                raise PolicyEvaluationError(rule_id, f"missing value for {cond.ref}")
            return value
        if cond.list_name is not None:
            return self.doc.lists[cond.list_name]
        return cond.value

    def _holds(self, cond: Condition, tree: dict[str, Any], rule_id: str) -> bool:
        left = _resolve(tree, cond.path)
        if cond.op == "exists":
            return (left is not _MISSING and left is not None) == cond.value
        if left is _MISSING:
            raise PolicyEvaluationError(rule_id, f"missing value for {cond.path}")
        right = self._operand(cond, tree, rule_id)
        op = cond.op
        try:
            if op == "eq":
                return left == right
            if op == "ne":
                return left != right
            if op in ("in", "not_in"):
                found = left in list(right)
                return found if op == "in" else not found
            if op in _CIDR_OPS:
                ip = _ip(left, rule_id)
                inside = any(ip in ipaddress.ip_network(str(c), strict=False) for c in right)
                return inside if op == "in_cidr" else not inside
            if op in _NUMERIC_OPS:
                if isinstance(left, bool) or not isinstance(left, int | float):
                    raise PolicyEvaluationError(rule_id, f"{cond.path} is not a number")
                return {
                    "lt": left < right,
                    "lte": left <= right,
                    "gt": left > right,
                    "gte": left >= right,
                }[op]
            if op in ("contains", "not_contains"):
                if not isinstance(left, list | set | frozenset | tuple):
                    raise PolicyEvaluationError(rule_id, f"{cond.path} is not a list")
                found = right in left
                return found if op == "contains" else not found
            if op in ("mentioned_in", "not_mentioned_in"):
                if not isinstance(left, str) or not isinstance(right, str):
                    raise PolicyEvaluationError(rule_id, f"{cond.path} and its text must be strings")
                found = _mentioned(left, right)
                return found if op == "mentioned_in" else not found
            if op in ("host_in", "host_not_in"):
                if not isinstance(left, str):
                    raise PolicyEvaluationError(rule_id, f"{cond.path} is not a host name")
                found = _host_matches(left, list(right))
                return found if op == "host_in" else not found
        except TypeError as exc:
            raise PolicyEvaluationError(rule_id, f"cannot compare {cond.path}: {exc}") from exc
        raise PolicyEvaluationError(rule_id, f"unsupported op {op}")

    def evaluate(self, ctx: EvalContext) -> Decision:
        tree = ctx.as_tree()
        matched: list[Rule] = []
        for rule in self.doc.rules:
            if not rule.match.selects(ctx.tool, ctx.labels):
                continue
            if all(self._holds(c, tree, rule.id) for c in rule.when):
                matched.append(rule)

        hits = [RuleHit(r.id, r.effect, r.description) for r in matched]
        for effect in (Effect.DENY, Effect.REQUIRE_APPROVAL, Effect.ALLOW):
            decisive = [r for r in matched if r.effect == effect]
            if decisive:
                return Decision(
                    effect=effect,
                    source="policy",
                    decisive=[RuleHit(r.id, r.effect, r.description) for r in decisive],
                    matched=hits,
                    policy_version=self.version,
                    halt=any(r.halt for r in decisive),
                    counts_as_strike=effect == Effect.DENY,
                )
        return Decision(
            effect=Effect.DENY,
            source="policy",
            decisive=[RuleHit("default-deny", Effect.DENY, "No policy rule permits this action.")],
            matched=hits,
            policy_version=self.version,
            counts_as_strike=True,
        )

    def summary(self) -> dict[str, Any]:
        d = self.doc
        return {
            "version": self.version,
            "name": d.name,
            "description": d.description,
            "default_effect": d.default_effect,
            "approval_ttl_seconds": d.approval_ttl_seconds,
            "on_human_deny": d.on_human_deny,
            "limits": d.limits.model_dump(),
            "lists": d.lists,
            "reviewer": d.reviewer.model_dump(),
            "rules": [
                {**r.model_dump(mode="json", by_alias=True), "inactive": r.id in self.inactive_rules}
                for r in d.rules
            ],
            "source": self.source_text,
        }


class PolicyProvider:
    """Holds the effective policy. Reloading swaps it atomically."""

    def __init__(self, path: Path, registry: ToolRegistry) -> None:
        self._path = path
        self._registry = registry
        self._lock = threading.Lock()
        self._policy = Policy.load(path, registry)

    def current(self) -> Policy:
        with self._lock:
            return self._policy

    def reload(self) -> Policy:
        policy = Policy.load(self._path, self._registry)
        with self._lock:
            self._policy = policy
        return policy

    def replace(self, policy: Policy) -> None:
        with self._lock:
            self._policy = policy
