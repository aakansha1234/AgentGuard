"""Backups and audit export."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from agentguard.cli import main
from tests.liveserver import LiveServer


@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    with LiveServer(tmp_path) as srv:
        srv.create_run(task="first")
        srv.create_run(task="second")
    monkeypatch.setenv("AGENTGUARD_DOTENV", "")
    monkeypatch.setenv("AGENTGUARD_DATA_DIR", str(srv.settings.data_dir))
    return srv.settings.data_dir


def test_backup_is_a_working_private_copy(data_dir: Path, tmp_path: Path) -> None:
    dest = tmp_path / "copy.sqlite"
    assert main(["backup", "--output", str(dest)]) == 0
    assert oct(dest.stat().st_mode & 0o777) == "0o600"
    conn = sqlite3.connect(dest)
    assert conn.execute("SELECT count(*) FROM runs").fetchone()[0] == 2
    conn.close()


def test_export_audit_writes_json_lines_incrementally(
    data_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "audit.jsonl"
    assert main(["export-audit", "--output", str(out)]) == 0
    events = [json.loads(line) for line in out.read_text().splitlines()]
    assert [e["type"] for e in events] == ["run.created", "run.created"]
    assert {"seq", "ts", "run_id", "type", "payload"} <= set(events[0])
    last = events[-1]["seq"]
    assert f"--after {last}" in capsys.readouterr().err

    assert main(["export-audit", "--output", str(out), "--after", str(last), "--append"]) == 0
    assert len(out.read_text().splitlines()) == 2, "nothing new"
