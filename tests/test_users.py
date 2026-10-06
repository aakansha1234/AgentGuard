"""Users, roles and single sign-on."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from agentguard.auth import Principal, trusted_proxy
from agentguard.cli import main
from agentguard.config import Settings
from tests.liveserver import LiveServer

BLOCK = {"ip": "203.0.113.42", "reason": "EVT-0004..EVT-0022", "duration_minutes": 60}


def add_user(srv: LiveServer, name: str, role: str, email: str | None = None) -> str:
    from agentguard.auth import USER_TOKEN_PREFIX, hash_user_token

    token = f"{USER_TOKEN_PREFIX}{name}-test-token"
    srv.services.store.add_user(name=name, role=role, email=email, token_hash=hash_user_token(token))
    return token


def client(srv: LiveServer, token: str | None = None, **headers: str) -> httpx.Client:
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=srv.url, headers=headers, timeout=30)


@pytest.fixture
def srv(tmp_path: Path) -> Iterator[LiveServer]:
    with LiveServer(tmp_path) as s:
        yield s


def test_roles_include_the_ones_below() -> None:
    admin, approver, viewer = (Principal("x", r, "user-token") for r in ("admin", "approver", "viewer"))
    assert admin.can("approver") and admin.can("viewer")
    assert approver.can("viewer") and not approver.can("admin")
    assert not viewer.can("approver")


def test_viewer_can_look_but_not_act(srv: LiveServer) -> None:
    token = add_user(srv, "vera", "viewer")
    with client(srv, token) as c:
        me = c.get("/api/config").json()["user"]
        assert me == {"name": "vera", "role": "viewer", "via": "user-token"}
        assert c.get("/api/runs").status_code == 200
        r = c.post("/api/runs", json={"task": "t", "mode": "external"})
        assert r.status_code == 403 and "admin" in r.json()["detail"]
        assert (
            c.post(
                "/api/approvals/act_x/resolve", json={"decision": "approve", "args_hash": "x" * 20}
            ).status_code
            == 403
        )


async def test_approver_decides_and_is_named_in_the_record(srv: LiveServer) -> None:
    approver = add_user(srv, "ana", "approver")
    with client(srv, approver) as c:
        assert c.post("/api/runs", json={"task": "t", "mode": "external"}).status_code == 403
    created = srv.create_run(subject="alice")  # the operator token is the bootstrap admin
    run_id = created["run"]["id"]
    async with srv.mcp(created["token"]) as mcp:
        await mcp.call_tool("get_user_logins", {"user": "alice"})
        call = asyncio.create_task(mcp.call_tool("block_ip", BLOCK))
        pending = await asyncio.to_thread(srv.wait_action, run_id, "pending_approval")
        with client(srv, approver) as c:
            r = c.post(
                f"/api/approvals/{pending['id']}/resolve",
                json={"decision": "deny", "args_hash": pending["args_hash"]},
            )
            assert r.status_code == 200, r.text
        await call
    action = srv.services.store.get_action(pending["id"])
    assert action is not None and action.approver == "ana" and action.state == "rejected"


def test_bad_tokens_and_run_tokens_are_refused(srv: LiveServer) -> None:
    run_token = srv.create_run()["token"]
    for token in ("agu_not-a-user", run_token, "random"):
        with client(srv, token) as c:
            assert c.get("/api/runs").status_code == 401
    with client(srv) as c:
        assert c.get("/api/runs").status_code == 401
        assert c.get("/api/session").json() == {"user": None, "message": ""}


# --- single sign-on ------------------------------------------------------------------------


def test_trusted_proxy_rules() -> None:
    assert not trusted_proxy("127.0.0.1", []) and not trusted_proxy("::1", [])
    assert not trusted_proxy("::ffff:127.0.0.1", [])
    assert trusted_proxy("10.1.2.3", [])
    assert trusted_proxy("10.1.2.3", ["10.0.0.0/8"]) and not trusted_proxy("192.0.2.1", ["10.0.0.0/8"])
    assert trusted_proxy("127.0.0.1", ["127.0.0.1/32"]), "explicitly trusted local proxy"
    assert not trusted_proxy(None, []) and not trusted_proxy("not-an-ip", [])


def sso_srv(tmp_path: Path, trusted: list[str]) -> LiveServer:
    def configure(s: Settings) -> None:
        s.auth_header = "X-ExeDev-Email"
        s.trusted_proxies = trusted

    return LiveServer(tmp_path, configure=configure)


def test_sso_header_from_a_local_process_is_ignored(tmp_path: Path) -> None:
    with sso_srv(tmp_path, trusted=[]) as srv:  # default: loopback is never a proxy
        add_user(srv, "sam", "admin", email="sam@example.com")
        with client(srv, **{"X-ExeDev-Email": "sam@example.com"}) as c:
            assert c.get("/api/runs").status_code == 401


def test_sso_header_from_the_proxy_signs_in_listed_users(tmp_path: Path) -> None:
    with sso_srv(tmp_path, trusted=["127.0.0.1/32"]) as srv:  # the test client plays the proxy
        add_user(srv, "sam", "approver", email="Sam@Example.com")
        with client(srv, **{"X-ExeDev-Email": "sam@example.com"}) as c:
            assert c.get("/api/session").json()["user"] == {"name": "sam", "role": "approver", "via": "sso"}
            assert c.get("/api/runs").status_code == 200
            assert c.post("/api/runs", json={"task": "t", "mode": "external"}).status_code == 403
        with client(srv, **{"X-ExeDev-Email": "mallory@example.com"}) as c:
            r = c.get("/api/runs")
            assert r.status_code == 403 and "not an AgentGuard user" in r.json()["detail"]
            assert "not an AgentGuard user" in c.get("/api/session").json()["message"]


# --- CLI --------------------------------------------------------------------------------------


def test_user_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AGENTGUARD_DOTENV", "")
    monkeypatch.setenv("AGENTGUARD_DATA_DIR", str(tmp_path / "data"))
    assert main(["user", "add", "ana", "--role", "approver"]) == 0
    out = capsys.readouterr().out
    assert re.search(r"Token \(shown once.*\): agu_\S{20,}", out)
    assert main(["user", "add", "sam", "--role", "admin", "--email", "sam@example.com", "--no-token"]) == 0
    assert main(["user", "add", "ana", "--role", "viewer"]) == 1, "duplicate name"
    assert main(["user", "add", "bad", "--role", "root"]) == 2
    assert main(["user", "add", "x", "--role", "viewer", "--no-token"]) == 2, "no way to sign in"
    capsys.readouterr()
    assert main(["user", "list"]) == 0
    listing = capsys.readouterr().out
    assert "ana" in listing and "approver" in listing and "sam@example.com" in listing
    assert main(["user", "remove", "ana"]) == 0
    assert main(["user", "remove", "ana"]) == 1
