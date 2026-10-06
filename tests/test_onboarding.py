"""`agentguard init` and the demo-tools switch."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentguard.cli import main
from agentguard.config import Settings
from agentguard.models import Effect
from agentguard.policy import EvalContext, Policy
from agentguard.services import build_registry
from tests.test_upstream import upstreams_file


def test_init_writes_a_cautious_policy_that_loads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("TEST_NOTES_TOKEN", "s3cret")
    monkeypatch.setenv("AGENTGUARD_DOTENV", "")
    upstreams = upstreams_file(tmp_path)
    out = tmp_path / "policy.yaml"
    assert main(["init", "--upstreams", str(upstreams), "--output", str(out)]) == 0
    assert "notes__add_note" in capsys.readouterr().out

    settings = Settings()
    settings.upstreams_path = upstreams
    settings.demo_tools = False
    registry, _ = build_registry(settings)
    assert set(registry.names()) == {"notes__read_notes", "notes__whoami", "notes__add_note", "notes__fail"}
    policy = Policy.load(out, registry)

    def effect(tool: str) -> Effect:
        spec = registry.get(tool)
        assert spec is not None
        ctx = EvalContext(tool=tool, labels=spec.labels, args={}, facts={}, run={}, session={"labels": []})
        return policy.evaluate(ctx).effect

    assert effect("notes__read_notes") == Effect.ALLOW
    assert effect("notes__add_note") == Effect.REQUIRE_APPROVAL
    assert effect("notes__fail") == Effect.REQUIRE_APPROVAL, "no annotations: treated as outbound"
    assert policy.doc.default_effect == "deny"

    assert main(["init", "--upstreams", str(upstreams), "--output", str(out)]) == 1, "won't overwrite"
    assert "--force" in capsys.readouterr().err


def test_init_needs_an_upstreams_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AGENTGUARD_DOTENV", "")
    monkeypatch.delenv("AGENTGUARD_UPSTREAMS", raising=False)
    assert main(["init"]) == 2
    assert "AGENTGUARD_UPSTREAMS" in capsys.readouterr().err


def test_demo_tools_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTGUARD_DEMO_TOOLS", "off")
    assert Settings.from_env().demo_tools is False
    monkeypatch.setenv("AGENTGUARD_DEMO_TOOLS", "maybe")
    with pytest.raises(ValueError, match="on or off"):
        Settings.from_env()
