"""Settings helpers: .env loading and reviewer selection."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentguard.cli import main as cli_main
from agentguard.config import Settings, load_dotenv
from agentguard.services import ReviewerConfigError, make_reviewer


def test_load_dotenv_parses_and_never_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("AG_T_A", "AG_T_B", "AG_T_C", "AG_T_D", "AG_T_E", "AG_T_KEEP", "AG_T_EMPTY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AG_T_KEEP", "from-shell")
    env = tmp_path / ".env"
    env.write_text(
        "# comment\n"
        "\n"
        "AG_T_A=plain\n"
        "export AG_T_B='single quoted # not a comment'\n"
        'AG_T_C="double quoted"\n'
        "AG_T_D=value # trailing comment\n"
        "AG_T_KEEP=from-file\n"
        "AG_T_EMPTY=\n"
        "not a variable line\n"
        "1BAD=x\n"
        "AG_T_E=a=b=c\n"
    )
    loaded = load_dotenv(env)
    import os

    assert os.environ["AG_T_A"] == "plain"
    assert os.environ["AG_T_B"] == "single quoted # not a comment"
    assert os.environ["AG_T_C"] == "double quoted"
    assert os.environ["AG_T_D"] == "value"
    assert os.environ["AG_T_E"] == "a=b=c"
    assert os.environ["AG_T_KEEP"] == "from-shell", "existing variables win"
    assert "AG_T_KEEP" not in loaded and "1BAD" not in loaded
    assert load_dotenv(tmp_path / "missing") == []


CREDS = ("TYPESAFE_API_KEY", "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN")


@pytest.fixture
def no_creds(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in CREDS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_each_mode_builds_its_reviewer(no_creds: pytest.MonkeyPatch) -> None:
    s = Settings()
    for name in CREDS:
        no_creds.setenv(name, "test-value-not-real")
    s.reviewer = "jev"
    assert (r := make_reviewer(s)) is not None and r.name == "jev"
    s.reviewer = "clef"
    assert (r := make_reviewer(s)) is not None and r.name == "clef"
    s.reviewer = "human"
    assert make_reviewer(s) is None


@pytest.mark.parametrize(
    ("mode", "present", "missing"),
    [
        ("jev", ["CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN"], "TYPESAFE_API_KEY"),
        ("clef", ["TYPESAFE_API_KEY", "CLOUDFLARE_ACCOUNT_ID"], "CLOUDFLARE_API_TOKEN"),
    ],
)
def test_model_mode_without_its_key_errors_instead_of_falling_back(
    no_creds: pytest.MonkeyPatch, mode: str, present: list[str], missing: str
) -> None:
    for name in present:  # the other mode's keys must not rescue this one
        no_creds.setenv(name, "test-value-not-real")
    s = Settings()
    s.reviewer = mode
    with pytest.raises(ReviewerConfigError, match=missing):
        make_reviewer(s)


def test_mode_has_no_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTGUARD_REVIEWER", raising=False)
    s = Settings.from_env()
    assert s.reviewer == ""
    with pytest.raises(ReviewerConfigError, match="AGENTGUARD_REVIEWER is not set"):
        make_reviewer(s)


@pytest.mark.parametrize("mode", ["auto", "none", "clef-flash"])
def test_unknown_modes_are_rejected(mode: str) -> None:
    s = Settings()
    s.reviewer = mode
    with pytest.raises(ReviewerConfigError, match="jev, clef, human"):
        make_reviewer(s)


def test_mode_from_env_is_normalised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTGUARD_REVIEWER", " Clef ")
    assert Settings.from_env().reviewer == "clef"


def test_serve_refuses_to_start_without_the_key(
    no_creds: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    no_creds.setenv("AGENTGUARD_REVIEWER", "clef")
    no_creds.setenv("AGENTGUARD_DATA_DIR", str(tmp_path))
    no_creds.setenv("AGENTGUARD_DOTENV", "")
    assert cli_main(["serve", "--port", "1"]) == 2
    assert "CLOUDFLARE_ACCOUNT_ID" in capsys.readouterr().err
