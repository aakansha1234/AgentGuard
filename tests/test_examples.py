"""The API examples, driven by scripted model APIs against a real AgentGuard.

The SDKs and MCP client are real; only the model is scripted. That proves the
wiring: the model is offered exactly the run's tools, every call goes through
AgentGuard (allowed or denied by policy), and results reach the model.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from tests.fakes.fake_model_apis import FakeModelApis
from tests.liveserver import LiveServer

pytest.importorskip("anthropic")
pytest.importorskip("openai")

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
TOOLS = ["get_ip_activity", "get_user_logins"]  # sorted


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, EXAMPLES / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def srv(tmp_path: Path) -> Iterator[LiveServer]:
    with LiveServer(tmp_path) as s:
        yield s


@pytest.fixture
def apis() -> Iterator[FakeModelApis]:
    with FakeModelApis() as a:
        yield a


def check_agentguard_decided(srv: LiveServer, run_id: str) -> None:
    actions = srv.services.store.list_actions(run_id)
    decided = {(a.tool, (a.args or {}).get("user"), a.state) for a in actions}
    assert decided == {("get_user_logins", "alice", "succeeded"), ("get_user_logins", "bob", "denied")}


async def test_claude_example_goes_through_agentguard(srv: LiveServer, apis: FakeModelApis) -> None:
    import anthropic

    example = load("claude_api_agent")
    created = srv.create_run(subject="alice", tools=TOOLS)
    client = anthropic.AsyncAnthropic(base_url=apis.base, api_key="test-key", max_retries=0)
    summary = await example.run_with_mcp_client(
        "Investigate alice.", srv.settings.mcp_url, created["token"], client
    )

    first = apis.anthropic_requests[0]
    assert first["model"] == "claude-opus-5-5"
    assert sorted(t["name"] for t in first["tools"]) == TOOLS, "only the run's tools"
    assert first["fallbacks"] == "default" and first["output_config"] == {"effort": "high"}
    assert "server-side-fallback-2026-07-01" in apis.anthropic_headers[0]["anthropic-beta"]
    check_agentguard_decided(srv, created["run"]["id"])
    assert "EVT-0004" in summary, "the allowed result reached the model"
    assert "R-02-read-other-user" in summary, "and so did the denial"


async def test_claude_connector_request_shape(apis: FakeModelApis) -> None:
    import anthropic

    example = load("claude_api_agent")
    client = anthropic.AsyncAnthropic(base_url=apis.base, api_key="test-key", max_retries=0)
    await example.run_with_connector("t", "https://guard.example.test/mcp", "agr_secret", client)
    body = apis.anthropic_requests[0]
    assert body["mcp_servers"] == [
        {
            "type": "url",
            "url": "https://guard.example.test/mcp",
            "name": "agentguard",
            "authorization_token": "agr_secret",
        }
    ]
    assert body["tools"] == [{"type": "mcp_toolset", "mcp_server_name": "agentguard"}]
    assert "mcp-client-2025-11-20" in apis.anthropic_headers[0]["anthropic-beta"]


async def test_openai_example_goes_through_agentguard(srv: LiveServer, apis: FakeModelApis) -> None:
    import openai

    example = load("openai_api_agent")
    created = srv.create_run(subject="alice", tools=TOOLS)
    client = openai.AsyncOpenAI(base_url=f"{apis.base}/v1", api_key="test-key", max_retries=0)
    summary = await example.run_with_mcp_client(
        "Investigate alice.", srv.settings.mcp_url, created["token"], client
    )

    first = apis.openai_requests[0]
    assert sorted(t["name"] for t in first["tools"]) == TOOLS
    assert all(t["type"] == "function" for t in first["tools"])
    assert apis.openai_requests[1]["previous_response_id"] == "resp_1"
    check_agentguard_decided(srv, created["run"]["id"])
    assert "EVT-0004" in summary and "R-02-read-other-user" in summary


async def test_openai_remote_mcp_request_shape(apis: FakeModelApis) -> None:
    import openai

    example = load("openai_api_agent")
    client = openai.AsyncOpenAI(base_url=f"{apis.base}/v1", api_key="test-key", max_retries=0)
    await example.run_with_remote_mcp("t", "https://guard.example.test/mcp", "agr_secret", client)
    [tool] = apis.openai_requests[0]["tools"]
    assert tool == {
        "type": "mcp",
        "server_label": "agentguard",
        "server_url": "https://guard.example.test/mcp",
        "authorization": "agr_secret",
        "require_approval": "never",
    }
