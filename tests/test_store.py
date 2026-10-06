from __future__ import annotations

import sqlite3
import threading
from importlib import resources
from pathlib import Path

import pytest

from agentguard.store import Store


def make_run(store: Store, run_id: str = "run_1") -> None:
    store.create_run(
        run_id=run_id,
        owner="o",
        task="t",
        mode="replay",
        scenario=None,
        dataset_id="baseline",
        subject="alice",
        enforcement="enforce",
        policy_version="p-1",
        state="running",
        token_hash=f"h-{run_id}",
        session={},
        tools=["get_user_logins"],
    )


def test_events_are_append_only(tmp_path: Path) -> None:
    store = Store(tmp_path / "db.sqlite")
    make_run(store)
    e = store.append_event("run_1", "x", {"a": 1})
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._conn.execute("UPDATE events SET type = 'y' WHERE seq = ?", (e.seq,))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._conn.execute("DELETE FROM events")


def test_event_sequences_are_monotonic_per_run_and_global(tmp_path: Path) -> None:
    store = Store(tmp_path / "db.sqlite")
    make_run(store, "run_a")
    make_run(store, "run_b")
    seqs = [store.append_event(r, "x", {}) for r in ["run_a", "run_b", "run_a", "run_a"]]
    assert [e.seq for e in seqs] == sorted(e.seq for e in seqs)
    assert [e.run_seq for e in store.events_after("run_a")] == [1, 2, 3]
    assert [e.run_seq for e in store.events_after("run_a", after_seq=seqs[0].seq)] == [2, 3]


def test_conditional_transition_has_exactly_one_winner_across_threads(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite"
    store = Store(path)
    make_run(store)
    store.insert_action(
        action_id="act_1", run_id="run_1", tool="block_ip", raw_args={}, state="pending_approval"
    )
    store.close()

    winners: list[bool] = []
    barrier = threading.Barrier(8)

    def contender() -> None:
        s = Store(path)  # separate connection per thread, like separate workers
        barrier.wait()
        winners.append(s.transition_action("act_1", ["pending_approval"], "approved", approver="x"))
        s.close()

    threads = [threading.Thread(target=contender) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert winners.count(True) == 1


def test_execution_ledger_rejects_second_execution(tmp_path: Path) -> None:
    store = Store(tmp_path / "db.sqlite")
    make_run(store)
    store.insert_action(action_id="act_1", run_id="run_1", tool="block_ip", raw_args={}, state="executing")
    store.record_execution(action_id="act_1", run_id="run_1", tool="block_ip", args={"ip": "1.2.3.4"})
    with pytest.raises(sqlite3.IntegrityError):
        store.record_execution(action_id="act_1", run_id="run_1", tool="block_ip", args={"ip": "1.2.3.4"})
    assert len(store.executions("run_1")) == 1


def test_update_rejects_unknown_columns(tmp_path: Path) -> None:
    store = Store(tmp_path / "db.sqlite")
    make_run(store)
    with pytest.raises(ValueError):
        store.update_run("run_1", token_hash="stolen")
    with pytest.raises(ValueError):
        store.update_run("run_1", **{"state = 'x' --": 1})


def test_migrations_are_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite"
    Store(path).close()
    store = Store(path)
    migrations = [f for f in resources.files("agentguard.migrations").iterdir() if f.name.endswith(".sql")]
    assert store._conn.execute("PRAGMA user_version").fetchone()[0] == len(migrations)


def test_v1_database_upgrades_and_old_runs_keep_builtin_tools(tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "db.sqlite"
    v1 = (resources.files("agentguard.migrations") / "001_init.sql").read_text()
    conn = sqlite3.connect(path)
    conn.executescript(f"BEGIN;\n{v1}\nPRAGMA user_version = 1;\nCOMMIT;")
    conn.execute(
        """INSERT INTO runs (id, created_at, updated_at, owner, task, mode, dataset_id, subject,
           enforcement, policy_version, state, token_hash, session)
           VALUES ('run_old', 't', 't', 'o', 't', 'replay', 'baseline', 'alice', 'enforce', 'p-1',
                   'completed', 'h', '{}')"""
    )
    conn.commit()
    conn.close()
    store = Store(path)
    old = store.get_run("run_old")
    assert old is not None and old.tools is None
    make_run(store, "run_new")
    new = store.get_run("run_new")
    assert new is not None and new.tools == ["get_user_logins"]
