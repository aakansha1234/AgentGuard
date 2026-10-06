"""Proxying an upstream MCP server: discovery, labels, credentials, policy, execution."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp import types as mcp_types

from agentguard.config import Settings
from agentguard.policy import Policy, PolicyError
from agentguard.tools import ToolArgsError, ToolRegistry, soc_registry
from agentguard.tools.upstream import (
    UpstreamError,
    UpstreamPool,
    build_specs,
    discover,
    labels_from_annotations,
    load_upstream_tools,
    load_upstreams,
)
from tests.conftest import POLICY_PATH
from tests.liveserver import LiveServer

NOTES_SERVER = Path(__file__).parent / "fakes" / "notes_server.py"

NOTES_RULES = """
  - id: U-01-read-notes
    description: Reading notes is fine.
    effect: allow
    match: { tools: [notes__read_notes, notes__whoami] }

  - id: U-02-add-note-needs-human
    description: Adding a note changes state.
    effect: require_approval
    match: { tools: [notes__add_note] }

  - id: U-03-try-fail
    description: Allowed so the test can see upstream errors.
    effect: allow
    match: { tools: [notes__fail] }
"""


def upstreams_file(tmp_path: Path, extra: str = "") -> Path:
    path = tmp_path / "upstreams.yaml"
    path.write_text(
        "servers:\n"
        "  notes:\n"
        f"    command: {json.dumps(sys.executable)}\n"
        f"    args: [{json.dumps(str(NOTES_SERVER))}]\n"
        "    env: {NOTES_TOKEN: '${TEST_NOTES_TOKEN}'}\n" + extra
    )
    return path


# --- config and discovery --------------------------------------------------------------------


def test_secrets_are_expanded_and_a_missing_one_is_an_error(tmp_path: Path) -> None:
    path = upstreams_file(tmp_path)
    [notes] = load_upstreams(path, {"TEST_NOTES_TOKEN": "s3cret", "PATH": "/usr/bin", "OTHER_SECRET": "x"})
    assert notes.env["NOTES_TOKEN"] == "s3cret"
    assert "OTHER_SECRET" not in notes.env, "stdio servers get only what the file lists (plus PATH/HOME/...)"
    with pytest.raises(UpstreamError, match="TEST_NOTES_TOKEN"):
        load_upstreams(path, {"PATH": "/usr/bin"})


@pytest.mark.parametrize(
    "server",
    [
        "    command: x\n    url: https://example.com/mcp\n",  # both transports
        "    args: [a]\n",  # neither
        "    url: https://example.com/mcp\n    env: {A: b}\n",  # env on an HTTP server
    ],
)
def test_bad_server_config_is_rejected(tmp_path: Path, server: str) -> None:
    path = tmp_path / "upstreams.yaml"
    path.write_text("servers:\n  s:\n" + server)
    with pytest.raises(UpstreamError):
        load_upstreams(path, {})


def test_labels_from_annotations_default_to_the_cautious_reading() -> None:
    ann = mcp_types.ToolAnnotations
    assert labels_from_annotations(None) == {"side_effect", "egress"}
    assert labels_from_annotations(ann(read_only_hint=True)) == {"read_only", "ingests_untrusted"}
    assert labels_from_annotations(ann(read_only_hint=True, open_world_hint=False)) == {"read_only"}
    assert labels_from_annotations(ann(read_only_hint=False, open_world_hint=False)) == {"side_effect"}


def test_discovery_builds_strict_namespaced_tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_NOTES_TOKEN", "s3cret")
    pool, specs = load_upstream_tools(upstreams_file(tmp_path))
    assert pool is not None
    by_name = {s.name: s for s in specs}
    assert set(by_name) == {"notes__read_notes", "notes__add_note", "notes__whoami", "notes__fail"}
    add = by_name["notes__add_note"]
    assert add.source == "notes" and add.labels == {"side_effect"}
    assert by_name["notes__fail"].labels == {"side_effect", "egress"}
    assert add.canonicalize({"text": "hi"}) == {"text": "hi"}
    with pytest.raises(ToolArgsError, match="text"):
        add.canonicalize({"priority": 2})
    with pytest.raises(ToolArgsError, match="cc"):
        add.canonicalize({"text": "hi", "cc": "attacker@example.com"})


def test_tool_allowlist_and_label_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_NOTES_TOKEN", "s3cret")
    extra = "    tools:\n      read_notes: {}\n      add_note: {labels: [side_effect, egress]}\n"
    _, specs = load_upstream_tools(upstreams_file(tmp_path, extra))
    assert {s.name: s.labels for s in specs} == {
        "notes__read_notes": {"read_only"},
        "notes__add_note": {"side_effect", "egress"},
    }
    bad = "    tools:\n      no_such_tool: {}\n"
    with pytest.raises(UpstreamError, match="no_such_tool"):
        load_upstream_tools(upstreams_file(tmp_path, bad))


def test_pool_refuses_to_open_if_tools_changed_since_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_NOTES_TOKEN", "s3cret")
    upstreams = load_upstreams(upstreams_file(tmp_path))
    discovered = discover(upstreams)
    tampered = {
        "notes": [
            t.model_copy(update={"input_schema": {"type": "object", "properties": {"x": {"type": "string"}}}})
            if t.name == "add_note"
            else t
            for t in discovered["notes"]
        ]
    }
    pool = UpstreamPool(upstreams, tampered)

    async def open_pool() -> None:
        await pool.open()

    with pytest.raises(UpstreamError, match="changed tools"):
        asyncio.run(open_pool())
    assert build_specs(upstreams, discovered, pool)


# --- policy -----------------------------------------------------------------------------------


def test_rules_for_unconfigured_upstreams_are_inactive_but_typos_are_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ghost = POLICY_PATH.read_text() + (
        "\n  - id: G-01\n    description: For a server that isn't connected.\n"
        "    effect: allow\n    match: { tools: [ghost__anything] }\n"
    )
    Policy.parse(ghost, soc_registry())  # no ghost server: inactive, accepted

    monkeypatch.setenv("TEST_NOTES_TOKEN", "s3cret")
    _, specs = load_upstream_tools(upstreams_file(tmp_path))
    registry = ToolRegistry([*soc_registry().all(), *specs])
    typo = POLICY_PATH.read_text() + (
        "\n  - id: T-01\n    description: Typo in a connected server's tool.\n"
        "    effect: allow\n    match: { tools: [notes__raed_notes] }\n"
    )
    with pytest.raises(PolicyError, match="notes__raed_notes"):
        Policy.parse(typo, registry)
    with pytest.raises(PolicyError, match="get_user_loginz"):
        Policy.parse(
            POLICY_PATH.read_text().replace("tools: [get_user_logins] }", "tools: [get_user_loginz] }", 1),
            soc_registry(),
        )


# --- end to end through the gateway ----------------------------------------------------------


@pytest.fixture
def srv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[LiveServer]:
    monkeypatch.setenv("TEST_NOTES_TOKEN", "s3cret-notes-token")
    monkeypatch.setenv("PARENT_SECRET", "AgentGuard's own secret")
    path = upstreams_file(tmp_path)

    def configure(s: Settings) -> None:
        s.upstreams_path = path
        s.policy_path.write_text(s.policy_path.read_text() + NOTES_RULES)

    with LiveServer(tmp_path, configure=configure) as s:
        yield s


def approve(srv: LiveServer, pending: dict[str, Any]) -> None:
    with srv.api() as c:
        r = c.post(
            f"/api/approvals/{pending['id']}/resolve",
            json={"decision": "approve", "args_hash": pending["args_hash"]},
        )
    assert r.status_code == 200, r.text


def text_of(result: Any) -> str:
    return "\n".join(c.text for c in result.content if hasattr(c, "text"))


async def test_proxied_calls_are_checked_then_forwarded(srv: LiveServer) -> None:
    created = srv.create_run(tools=["notes__read_notes", "notes__whoami", "notes__add_note", "notes__fail"])
    run_id = created["run"]["id"]
    async with srv.mcp(created["token"]) as client:
        listed = {t.name for t in (await client.list_tools()).tools}
        assert listed == {"notes__read_notes", "notes__whoami", "notes__add_note", "notes__fail"}

        who = await client.call_tool("notes__whoami", {})
        assert not who.is_error
        assert "token=set len=18" in text_of(who), "the upstream got its credential"
        assert "leaked_parent=False" in text_of(who), "and nothing else from AgentGuard's environment"

        add = asyncio.create_task(
            client.call_tool("notes__add_note", {"text": "contain host-7", "priority": 2})
        )
        pending = await asyncio.to_thread(srv.wait_action, run_id, "pending_approval")
        assert pending["tool"] == "notes__add_note"
        assert srv.services.store.executions(tool="notes__add_note") == []
        approve(srv, pending)
        assert "saved note 1" in text_of(await add)

        notes = await client.call_tool("notes__read_notes", {})
        assert "[p2] contain host-7" in text_of(notes)

        # No annotations: labelled egress + side_effect, so with no model reviewer a human decides.
        fail = asyncio.create_task(client.call_tool("notes__fail", {}))
        approve(srv, await asyncio.to_thread(srv.wait_action, run_id, "pending_approval"))
        failed = await fail
        assert failed.is_error and "Error executing tool fail" in text_of(failed)

        extra = await client.call_tool("notes__add_note", {"text": "x", "bcc": "attacker@example.com"})
        assert extra.is_error and "Invalid arguments" in text_of(extra)

    actions = {a.tool + ":" + a.state for a in srv.services.store.list_actions(run_id)}
    assert "notes__fail:failed" in actions and "notes__add_note:succeeded" in actions
    assert len(srv.services.store.executions(tool="notes__add_note")) == 1


async def test_run_allowlist_hides_and_refuses_other_tools(srv: LiveServer) -> None:
    created = srv.create_run(tools=["notes__read_notes"])
    async with srv.mcp(created["token"]) as client:
        assert [t.name for t in (await client.list_tools()).tools] == ["notes__read_notes"]
        refused = await client.call_tool("notes__whoami", {})
        assert refused.is_error and "not one of this run's tools" in text_of(refused)
    [action] = srv.services.store.list_actions(created["run"]["id"])
    assert action.decision is not None and action.decision["rule_ids"] == ["builtin:tool-not-in-run"]


def test_unknown_tools_in_a_run_request_are_rejected(srv: LiveServer) -> None:
    with srv.api() as c:
        r = c.post("/api/runs", json={"task": "t", "mode": "external", "tools": ["notes__nope"]})
    assert r.status_code == 409 and "notes__nope" in r.text


def test_scenario_runs_get_only_the_scenario_tools(srv: LiveServer) -> None:
    created = srv.create_run(mode="external", scenario="normal")
    assert created["run"]["tools"] == ["block_ip", "get_ip_activity", "get_user_logins", "http_post"]
