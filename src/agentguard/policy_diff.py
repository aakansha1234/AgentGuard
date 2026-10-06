"""`agentguard policy-diff`: what an edited policy would have decided differently.

Every action records what the policy saw when it decided (tool, labels,
arguments, facts, run, session). This replays those recorded decisions against
another policy file, so a rule change can be checked against real traffic
before it's turned on. Only the policy is compared: reviewer escalations and
human decisions are not replayed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentguard.policy import EvalContext, Policy, PolicyEvaluationError
from agentguard.store import ActionRecord, Store


@dataclass(frozen=True)
class Change:
    action_id: str
    run_id: str
    created_at: str
    tool: str
    args: dict[str, Any]
    before: str
    before_rules: list[str]
    after: str
    after_rules: list[str]


@dataclass(frozen=True)
class DiffReport:
    compared: int
    skipped: int
    changes: list[Change]


def _evaluate(policy: Policy, ctx: dict[str, Any]) -> tuple[str, list[str]]:
    try:
        decision = policy.evaluate(
            EvalContext(
                tool=ctx["tool"]["name"],
                labels=frozenset(ctx["tool"]["labels"]),
                args=ctx["args"],
                facts=ctx["facts"],
                run=ctx["run"],
                session=ctx["session"],
            )
        )
    except PolicyEvaluationError as exc:
        return "deny", [f"builtin:policy-error ({exc})"]
    return str(decision.effect), decision.rule_ids


def diff(store: Store, policy: Policy, limit: int = 1000) -> DiffReport:
    actions: list[ActionRecord] = store.recent_actions(limit)
    changes: list[Change] = []
    compared = skipped = 0
    for action in actions:
        ctx = action.eval_context
        if ctx is None:  # builtin decisions (invalid args, limits) and actions from before recording
            skipped += 1
            continue
        compared += 1
        after, after_rules = _evaluate(policy, ctx)
        before = str(ctx["policy_effect"])
        if after != before:
            changes.append(
                Change(
                    action_id=action.id,
                    run_id=action.run_id,
                    created_at=action.created_at,
                    tool=action.tool,
                    args=ctx["args"],
                    before=before,
                    before_rules=list(ctx["policy_rules"]),
                    after=after,
                    after_rules=after_rules,
                )
            )
    return DiffReport(compared, skipped, changes)


def print_report(report: DiffReport, policy_version: str) -> None:
    print(
        f"Replayed {report.compared} recorded decisions against {policy_version} "
        f"({report.skipped} skipped: built-in checks or no record)."
    )
    if not report.changes:
        print("No decision would change.")
        return
    print(f"{len(report.changes)} would change:\n")
    for c in report.changes:
        args = ", ".join(f"{k}={v!r}" for k, v in c.args.items())
        if len(args) > 80:
            args = args[:77] + "..."
        print(f"  {c.created_at[:19]}  {c.action_id}  {c.tool}({args})")
        print(f"      {c.before:17} {', '.join(c.before_rules) or 'default deny'}")
        print(f"   -> {c.after:17} {', '.join(c.after_rules) or 'default deny'}")
