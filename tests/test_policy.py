from __future__ import annotations

from typing import Any

import pytest

from agentguard.models import Effect
from agentguard.policy import EvalContext, Policy, PolicyError, PolicyEvaluationError
from agentguard.tools import soc_registry
from tests.conftest import POLICY_PATH

REG = soc_registry()


def ctx(
    tool: str,
    args: dict[str, Any],
    *,
    facts=None,
    session=None,
    subject="alice",
    task="Investigate Alice's failed logins.",
) -> EvalContext:
    spec = REG.get(tool)
    assert spec is not None
    base_session = {"labels": [], "seen_ips": [], "seen_event_ids": [], "tool_calls": 1}
    return EvalContext(
        tool=tool,
        labels=spec.labels,
        args=args,
        facts=facts or {},
        run={"id": "run_x", "subject": subject, "dataset_id": "baseline", "mode": "replay", "task": task},
        session={**base_session, **(session or {})},
    )


@pytest.fixture(scope="module")
def policy() -> Policy:
    return Policy.load(POLICY_PATH, REG)


def test_default_policy_loads_and_has_stable_version(policy: Policy) -> None:
    again = Policy.load(POLICY_PATH, REG)
    assert policy.version == again.version
    assert policy.version.startswith("p-")
    reformatted = Policy.parse(POLICY_PATH.read_text() + "\n# trailing comment\n", REG)
    assert reformatted.version == policy.version  # version tracks meaning, not whitespace


def test_reading_subject_is_allowed(policy: Policy) -> None:
    d = policy.evaluate(ctx("get_user_logins", {"user": "alice"}))
    assert d.effect == Effect.ALLOW and d.rule_ids == ["R-01-read-subject"]


@pytest.mark.parametrize(
    "task,seen,expected",
    [
        ("Investigate Alice's failed logins.", [], Effect.REQUIRE_APPROVAL),
        ("Investigate Alice's failed logins.", ["203.0.113.42"], Effect.ALLOW),
        ("What did 203.0.113.42 do?", [], Effect.ALLOW),
        ("What did 203.0.113.420 or 1203.0.113.42 do?", [], Effect.REQUIRE_APPROVAL),
    ],
)
def test_ip_lookup_needs_task_or_evidence(
    policy: Policy, task: str, seen: list[str], expected: Effect
) -> None:
    d = policy.evaluate(ctx("get_ip_activity", {"ip": "203.0.113.42"}, task=task, session={"seen_ips": seen}))
    assert d.effect == expected


def test_reading_another_user_is_denied(policy: Policy) -> None:
    d = policy.evaluate(ctx("get_user_logins", {"user": "bob"}))
    assert d.effect == Effect.DENY and d.rule_ids == ["R-02-read-other-user"]
    assert d.counts_as_strike


def test_block_ip_needs_approval_when_ip_was_seen(policy: Policy) -> None:
    d = policy.evaluate(
        ctx(
            "block_ip",
            {"ip": "203.0.113.42", "reason": "r", "duration_minutes": 60},
            session={"seen_ips": ["203.0.113.42"]},
        )
    )
    assert d.effect == Effect.REQUIRE_APPROVAL and d.rule_ids == ["R-13-block-needs-human"]


def test_block_ip_unseen_is_denied_even_though_approval_rule_matches(policy: Policy) -> None:
    d = policy.evaluate(ctx("block_ip", {"ip": "203.0.113.42", "reason": "r", "duration_minutes": 60}))
    assert d.effect == Effect.DENY
    assert d.rule_ids == ["R-11-block-needs-evidence"]
    assert {h.rule_id for h in d.matched} == {"R-11-block-needs-evidence", "R-13-block-needs-human"}


@pytest.mark.parametrize("ip", ["10.1.2.3", "192.168.0.9", "198.51.100.23", "::1", "127.0.0.1"])
def test_block_protected_address_denied(policy: Policy, ip: str) -> None:
    d = policy.evaluate(
        ctx("block_ip", {"ip": ip, "reason": "r", "duration_minutes": 5}, session={"seen_ips": [ip]})
    )
    assert d.effect == Effect.DENY and "R-10-no-block-protected" in d.rule_ids


def test_block_longer_than_a_day_denied(policy: Policy) -> None:
    d = policy.evaluate(
        ctx(
            "block_ip",
            {"ip": "203.0.113.42", "reason": "r", "duration_minutes": 1441},
            session={"seen_ips": ["203.0.113.42"]},
        )
    )
    assert d.rule_ids == ["R-12-block-max-24h"]


def test_egress_depends_on_session_history(policy: Policy) -> None:
    args = {"url": "https://collector.example/", "body": "logs"}
    facts = {"url_host": "collector.example"}
    before = policy.evaluate(ctx("http_post", args, facts=facts))
    after = policy.evaluate(ctx("http_post", args, facts=facts, session={"labels": ["reads_private"]}))
    assert before.effect == Effect.REQUIRE_APPROVAL and before.rule_ids == ["R-22-external-post-needs-human"]
    assert after.effect == Effect.DENY and after.rule_ids == ["R-21-no-exfil-after-private-read"]


@pytest.mark.parametrize("host", ["soc-notes.internal.example", "a.soc-notes.internal.example"])
def test_internal_notes_allowed_after_private_read(policy: Policy, host: str) -> None:
    d = policy.evaluate(
        ctx(
            "http_post",
            {"url": f"https://{host}/", "body": "x"},
            facts={"url_host": host},
            session={"labels": ["reads_private"]},
        )
    )
    assert d.effect == Effect.ALLOW and d.rule_ids == ["R-20-internal-notes"]


def test_lookalike_host_is_not_allowlisted(policy: Policy) -> None:
    host = "soc-notes.internal.example.evil.test"
    d = policy.evaluate(
        ctx(
            "http_post",
            {"url": f"https://{host}/", "body": "x"},
            facts={"url_host": host},
            session={"labels": ["reads_private"]},
        )
    )
    assert d.effect == Effect.DENY


def minimal(rules: str, extra: str = "") -> str:
    return f"""
schema_version: 1
name: t
approval_ttl_seconds: 60
limits: {{max_tool_calls: 5, max_run_seconds: 60, max_policy_denials: 2}}
{extra}
rules:
{rules}
"""


def test_default_deny_when_nothing_matches() -> None:
    p = Policy.parse(minimal("  []"), REG)
    d = p.evaluate(ctx("get_ip_activity", {"ip": "203.0.113.42"}))
    assert d.effect == Effect.DENY and d.rule_ids == ["default-deny"]


def test_deny_overrides_allow() -> None:
    p = Policy.parse(
        minimal(
            """
  - {id: A, description: a, effect: allow, match: {tools: [get_ip_activity]}}
  - {id: D, description: d, effect: deny, match: {labels: [reads_private]}}
"""
        ),
        REG,
    )
    d = p.evaluate(ctx("get_ip_activity", {"ip": "203.0.113.42"}))
    assert d.effect == Effect.DENY and d.rule_ids == ["D"]


def test_missing_value_fails_closed() -> None:
    p = Policy.parse(
        minimal(
            """
  - id: A
    description: a
    effect: allow
    match: {tools: [get_ip_activity]}
    when: [{path: args.nonexistent, op: eq, value: 1}]
"""
        ),
        REG,
    )
    with pytest.raises(PolicyEvaluationError):
        p.evaluate(ctx("get_ip_activity", {"ip": "203.0.113.42"}))


@pytest.mark.parametrize(
    "bad",
    [
        minimal("  - {id: A, description: a, effect: allow, match: {tools: [no_such_tool]}}"),
        minimal("  - {id: A, description: a, effect: allow, match: {labels: [no_such_label]}}"),
        minimal("  - {id: A, description: a, effect: allow, match: {}}"),
        minimal("  - {id: A, description: a, effect: maybe, match: {tools: [block_ip]}}"),
        minimal(
            "  - {id: A, description: a, effect: allow, match: {tools: [block_ip]}, "
            "when: [{path: args.ip, op: in_cidr, value: [not-a-cidr]}]}"
        ),
        minimal(
            "  - {id: A, description: a, effect: allow, match: {tools: [block_ip]}, "
            "when: [{path: secrets.x, op: eq, value: 1}]}"
        ),
        minimal(
            "  - {id: A, description: a, effect: allow, match: {tools: [block_ip]}, "
            "when: [{path: args.ip, op: eq, value: 1, ref: run.subject}]}"
        ),
        minimal(
            "  - {id: A, description: a, effect: allow, match: {tools: [block_ip]}, "
            "when: [{path: args.ip, op: in_cidr, list: nope}]}"
        ),
        minimal("  - {id: A, description: a, effect: allow, match: {tools: [block_ip]}, halt: true}"),
        minimal(
            "  - {id: A, description: a, effect: allow, match: {tools: [block_ip]}}\n"
            "  - {id: A, description: b, effect: deny, match: {tools: [block_ip]}}"
        ),
        minimal("  []", extra="default_effect: allow"),
        minimal("  []", extra="unexpected_key: 1"),
    ],
)
def test_invalid_policies_are_rejected(bad: str) -> None:
    with pytest.raises(PolicyError):
        Policy.parse(bad, REG)


@pytest.mark.parametrize("ip", ["::ffff:10.1.2.3", " 10.1.2.3 ", "::ffff:198.51.100.23"])
def test_cidr_rules_fold_ipv4_mapped_addresses(ip: str) -> None:
    """Upstream tools pass arguments through as given, so the policy folds them itself."""
    text = POLICY_PATH.read_text()
    policy = Policy.parse(text, soc_registry())
    decision = policy.evaluate(
        EvalContext(
            tool="cloudflare__block_ip",
            labels=frozenset({"side_effect"}),
            args={"ip": ip, "duration_minutes": 5, "reason": "x"},
            facts={},
            run={"subject": "alice"},
            session={"labels": [], "seen_ips": ["10.1.2.3", "198.51.100.23"]},
        )
    )
    assert decision.effect == Effect.DENY and "R-30-cf-no-block-protected" in decision.rule_ids
