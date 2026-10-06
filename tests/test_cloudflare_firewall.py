"""Cloudflare firewall integration: the MCP server's logic, and the whole path through AgentGuard."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2
import pytest

from agentguard.config import Settings
from agentguard.integrations.cloudflare_firewall import Firewall, FirewallError, parse_note
from tests.fakes.fake_cloudflare import FakeCloudflare
from tests.liveserver import LiveServer

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


def firewall(fake: FakeCloudflare, token: str | None = None) -> Firewall:
    http = httpx2.AsyncClient(transport=fake.transport(), base_url="https://api.cloudflare.com")
    return Firewall(fake.account, token or fake.token, http=http)


async def test_block_records_expiry_and_extends_instead_of_duplicating() -> None:
    fake = FakeCloudflare()
    fw = firewall(fake)
    first = await fw.block("203.0.113.42", 60, "brute force, EVT-0007", now=NOW)
    assert first["status"] == "blocked" and first["expires_at"] == "2026-10-06T13:00:00Z"
    [rule] = fake.rules.values()
    assert rule["configuration"] == {"target": "ip", "value": "203.0.113.42"}
    assert parse_note(rule["notes"]) == (NOW + timedelta(minutes=60), "brute force, EVT-0007")

    again = await fw.block("::ffff:203.0.113.42", 120, "still attacking", now=NOW)
    assert again["status"] == "extended" and again["rule_id"] == first["rule_id"]
    assert len(fake.rules) == 1

    v6 = await fw.block("2001:db8::7", 5, "ipv6 attacker", now=NOW)
    assert fake.rules[v6["rule_id"]]["configuration"]["target"] == "ip6"


async def test_people_made_rules_are_never_touched() -> None:
    fake = FakeCloudflare()
    human = fake.add_human_rule("203.0.113.42")
    fw = firewall(fake)
    assert await fw.list() == []
    result = await fw.unblock("203.0.113.42")
    assert result["status"] == "not blocked" and human in fake.rules
    await fw.block("203.0.113.42", 1, "test", now=NOW - timedelta(hours=1))
    assert await fw.sweep(now=NOW) == ["203.0.113.42"]
    assert list(fake.rules) == [human]


async def test_sweep_removes_only_expired_blocks() -> None:
    fake = FakeCloudflare()
    fw = firewall(fake)
    await fw.block("203.0.113.1", 10, "old", now=NOW - timedelta(minutes=30))
    await fw.block("203.0.113.2", 60, "current", now=NOW)
    assert await fw.sweep(now=NOW) == ["203.0.113.1"]
    assert [b["ip"] for b in await fw.list()] == ["203.0.113.2"]


@pytest.mark.parametrize(
    ("ip", "minutes"),
    [("127.0.0.1", 5), ("0.0.0.0", 5), ("203.0.113.9", 0), ("203.0.113.9", 1441)],  # noqa: S104
)
async def test_refuses_nonsense(ip: str, minutes: int) -> None:
    fake = FakeCloudflare()
    with pytest.raises(FirewallError):
        await firewall(fake).block(ip, minutes, "x", now=NOW)
    assert fake.rules == {}


async def test_api_errors_are_reported() -> None:
    with pytest.raises(FirewallError, match="Authentication error"):
        await firewall(FakeCloudflare(), token="wrong").list()


# --- through AgentGuard ---------------------------------------------------------------------


@pytest.fixture
def cloudflare_srv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[LiveServer, FakeCloudflare]]:
    fake = FakeCloudflare(account="acct-test", token="fw-token")
    with fake.serve() as api:
        monkeypatch.setenv("TEST_CF_ACCOUNT", fake.account)
        monkeypatch.setenv("TEST_CF_FIREWALL_TOKEN", fake.token)
        upstreams = tmp_path / "upstreams.yaml"
        upstreams.write_text(
            "servers:\n"
            "  cloudflare:\n"
            f"    command: {json.dumps(sys.executable)}\n"
            "    args: [-m, agentguard.integrations.cloudflare_firewall]\n"
            "    env:\n"
            "      CLOUDFLARE_ACCOUNT_ID: ${TEST_CF_ACCOUNT}\n"
            "      CLOUDFLARE_API_TOKEN: ${TEST_CF_FIREWALL_TOKEN}\n"
            f"      CLOUDFLARE_API_BASE: {api.base}\n"
            "    tools:\n"
            "      block_ip: {labels: [side_effect]}\n"
            "      unblock_ip: {labels: [side_effect]}\n"
            "      list_blocks: {labels: [read_only]}\n"
        )

        def configure(s: Settings) -> None:
            s.upstreams_path = upstreams

        with LiveServer(tmp_path, configure=configure) as srv:
            yield srv, fake


def text_of(result: Any) -> str:
    return "\n".join(c.text for c in result.content if hasattr(c, "text"))


async def test_real_firewall_path_checks_then_blocks(
    cloudflare_srv: tuple[LiveServer, FakeCloudflare],
) -> None:
    srv, fake = cloudflare_srv
    policy = srv.services.policies.current()
    assert not policy.inactive_rules & {"R-30-cf-no-block-protected", "R-32-cf-block-needs-human"}
    created = srv.create_run(
        subject="alice", tools=["get_user_logins", "cloudflare__block_ip", "cloudflare__list_blocks"]
    )
    run_id = created["run"]["id"]
    async with srv.mcp(created["token"]) as client:
        await client.call_tool("get_user_logins", {"user": "alice"})  # evidence: 203.0.113.42

        protected = await client.call_tool(
            "cloudflare__block_ip", {"ip": "10.20.30.40", "duration_minutes": 60, "reason": "test"}
        )
        assert protected.is_error and "R-30-cf-no-block-protected" in text_of(protected)
        unseen = await client.call_tool(
            "cloudflare__block_ip", {"ip": "198.51.100.200", "duration_minutes": 60, "reason": "test"}
        )
        assert unseen.is_error and "R-31-cf-block-needs-evidence" in text_of(unseen)
        too_long = await client.call_tool(
            "cloudflare__block_ip", {"ip": "203.0.113.42", "duration_minutes": 10080, "reason": "a week"}
        )
        assert too_long.is_error and "Invalid arguments" in text_of(too_long)
        assert fake.rules == {}, "nothing reached Cloudflare"

        block = asyncio.create_task(
            client.call_tool(
                "cloudflare__block_ip",
                {"ip": "203.0.113.42", "duration_minutes": 60, "reason": "brute force on alice, EVT-0007"},
            )
        )
        pending = await asyncio.to_thread(srv.wait_action, run_id, "pending_approval")
        assert pending["decision"]["rule_ids"] == ["R-32-cf-block-needs-human"]
        assert fake.rules == {}, "still nothing at Cloudflare while waiting for a human"
        with srv.api() as c:
            r = c.post(
                f"/api/approvals/{pending['id']}/resolve",
                json={"decision": "approve", "args_hash": pending["args_hash"]},
            )
            assert r.status_code == 200, r.text
        done = await block
        assert not done.is_error and '"status": "blocked"' in text_of(done)
        [rule] = fake.rules.values()
        assert rule["configuration"]["value"] == "203.0.113.42" and rule["notes"].startswith(
            "agentguard | expires"
        )

        listed = await client.call_tool("cloudflare__list_blocks", {})
        assert "203.0.113.42" in text_of(listed)
