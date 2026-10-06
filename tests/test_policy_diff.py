"""`agentguard policy-diff`: replaying recorded decisions against an edited policy."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from agentguard.cli import main
from agentguard.policy import Policy
from agentguard.policy_diff import diff
from tests.conftest import POLICY_PATH
from tests.liveserver import LiveServer


@pytest.fixture
def srv(tmp_path: Path) -> Iterator[LiveServer]:
    with LiveServer(tmp_path) as s:
        yield s


async def record_some_traffic(srv: LiveServer) -> str:
    created = srv.create_run(subject="alice", tools=["get_user_logins", "get_ip_activity", "http_post"])
    async with srv.mcp(created["token"]) as client:
        await client.call_tool("get_user_logins", {"user": "alice"})  # allow R-01
        await client.call_tool("get_user_logins", {"user": "bob"})  # deny R-02
        await client.call_tool("get_ip_activity", {"ip": "203.0.113.42"})  # allow R-03
        await client.call_tool("get_user_logins", {"user": "alice", "limit": "lots"})  # invalid: builtin
    return created["run"]["id"]


async def test_unchanged_policy_changes_nothing_and_edits_show_up(srv: LiveServer, tmp_path: Path) -> None:
    await record_some_traffic(srv)
    actions = [a for r in srv.services.store.list_runs() for a in srv.services.store.list_actions(r.id)]
    assert sum(a.eval_context is not None for a in actions) == 3, "builtin rejections aren't policy decisions"

    same = diff(srv.services.store, srv.services.policies.current())
    assert (same.compared, same.skipped, same.changes) == (3, 1, [])

    # Edit: IP lookups now need a human.
    rule = "  - id: R-03-ip-activity\n    description: Looking up activity from a source IP in this run's"
    edited = POLICY_PATH.read_text().replace(
        rule + " dataset is allowed.\n    effect: allow",
        rule + " dataset needs a human for now.\n    effect: require_approval",
    )
    assert edited != POLICY_PATH.read_text()
    report = diff(srv.services.store, Policy.parse(edited, srv.services.registry))
    [change] = report.changes
    assert change.tool == "get_ip_activity" and change.args["ip"] == "203.0.113.42"
    assert (change.before, change.after) == ("allow", "require_approval")
    assert change.before_rules == ["R-03-ip-activity"]


async def test_cli(
    srv: LiveServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    await record_some_traffic(srv)
    srv.services.store.close()  # the CLI opens the database itself
    monkeypatch.setenv("AGENTGUARD_DOTENV", "")
    monkeypatch.setenv("AGENTGUARD_DATA_DIR", str(srv.settings.data_dir))
    monkeypatch.setenv("AGENTGUARD_REVIEWER", "human")
    strict = tmp_path / "strict.yaml"
    strict.write_text(POLICY_PATH.read_text().replace("effect: allow", "effect: deny"))
    assert main(["policy-diff", str(strict)]) == 0
    out = capsys.readouterr().out
    assert "Replayed 3 recorded decisions" in out and "2 would change" in out
    assert "allow             R-01-read-subject" in out
