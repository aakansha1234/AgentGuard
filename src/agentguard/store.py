"""SQLite persistence: runs, actions, the execution ledger and the append-only event log.

All state changes that matter for safety are conditional UPDATEs
(`... WHERE id = ? AND state IN (...)`), so two concurrent callers can never
both win the same transition.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

Clock = Callable[[], datetime]


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="milliseconds")


def parse_iso(text: str) -> datetime:
    return datetime.fromisoformat(text)


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _load(text: str | None) -> Any:
    return None if text is None else json.loads(text)


@dataclass
class RunRecord:
    id: str
    created_at: str
    updated_at: str
    started_at: str | None
    ended_at: str | None
    owner: str
    task: str
    mode: str
    scenario: str | None
    dataset_id: str
    subject: str
    enforcement: str
    policy_version: str
    state: str
    state_reason: str | None
    token_hash: str
    session: dict[str, Any]
    agent: dict[str, Any]
    summary: str | None
    summary_check: dict[str, Any] | None
    tools: list[str] | None = None  # the run's tool allowlist; None on pre-allowlist runs

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> RunRecord:
        d = dict(row)
        d["session"] = _load(d["session"])
        d["agent"] = _load(d["agent"])
        d["summary_check"] = _load(d["summary_check"])
        d["tools"] = _load(d.get("tools"))
        return cls(**d)

    def public(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        d.pop("token_hash")
        return d


@dataclass
class UserRecord:
    name: str
    email: str | None
    role: str
    token_hash: str | None
    created_at: str
    disabled: bool

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> UserRecord:
        d = dict(row)
        d["disabled"] = bool(d["disabled"])
        return cls(**d)


@dataclass
class ActionRecord:
    id: str
    run_id: str
    seq: int
    created_at: str
    updated_at: str
    tool: str
    raw_args: Any
    args: dict[str, Any] | None
    args_hash: str | None
    facts: dict[str, Any] | None
    state: str
    decision: dict[str, Any] | None
    policy_version: str | None
    enforced: bool
    shadow_effect: str | None
    approval_expires_at: str | None
    approval_resolved_at: str | None
    approver: str | None
    approval_note: str | None
    exec_started_at: str | None
    exec_finished_at: str | None
    result: Any
    error: str | None
    eval_context: dict[str, Any] | None = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> ActionRecord:
        d = dict(row)
        for key in ("raw_args", "args", "facts", "decision", "result", "eval_context"):
            d[key] = _load(d[key])
        d["enforced"] = bool(d["enforced"])
        return cls(**d)

    def public(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class EventRecord:
    seq: int
    run_id: str
    run_seq: int
    ts: str
    type: str
    action_id: str | None
    payload: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> EventRecord:
        d = dict(row)
        d["payload"] = _load(d["payload"])
        return cls(**d)

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


_RUN_UPDATABLE = frozenset(
    {"started_at", "ended_at", "state", "state_reason", "session", "agent", "summary", "summary_check"}
)
_ACTION_UPDATABLE = frozenset(
    {
        "args",
        "args_hash",
        "facts",
        "decision",
        "policy_version",
        "enforced",
        "shadow_effect",
        "approval_expires_at",
        "approval_resolved_at",
        "approver",
        "approval_note",
        "exec_started_at",
        "exec_finished_at",
        "result",
        "error",
        "eval_context",
    }
)
_JSON_COLUMNS = frozenset(
    {"session", "agent", "summary_check", "raw_args", "args", "facts", "decision", "result", "eval_context"}
)


def _encode(column: str, value: Any) -> Any:
    if column in _JSON_COLUMNS and value is not None:
        return _dump(value)
    if isinstance(value, bool):
        return int(value)
    return value


class Store:
    def __init__(self, path: Path | str, clock: Clock = utcnow) -> None:
        self.clock = clock
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def backup(self, dest: Path) -> None:
        """A consistent copy of the database, safe while the server is running."""
        target = sqlite3.connect(dest)
        try:
            with self._lock:
                self._conn.backup(target)
        finally:
            target.close()

    def now(self) -> str:
        return iso(self.clock())

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._conn.in_transaction:
                yield self._conn  # nested: join the outer transaction
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def _migrate(self) -> None:
        with self._lock:
            current = self._conn.execute("PRAGMA user_version").fetchone()[0]
            files = sorted(
                (f for f in resources.files("agentguard.migrations").iterdir() if f.name.endswith(".sql")),
                key=lambda f: f.name,
            )
            for f in files:
                number = int(f.name.split("_", 1)[0])
                if number <= current:
                    continue
                self._conn.executescript(f"BEGIN;\n{f.read_text()}\nPRAGMA user_version = {number};\nCOMMIT;")

    def _one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchone()

    def _all(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    # -- users ------------------------------------------------------------

    def add_user(self, *, name: str, role: str, email: str | None, token_hash: str | None) -> UserRecord:
        with self.tx() as c:
            c.execute(
                "INSERT INTO users (name, email, role, token_hash, created_at) VALUES (?,?,?,?,?)",
                (name, email, role, token_hash, self.now()),
            )
        user = self.get_user(name)
        assert user is not None
        return user

    def get_user(self, name: str) -> UserRecord | None:
        row = self._one("SELECT * FROM users WHERE name = ?", (name,))
        return UserRecord.from_row(row) if row else None

    def user_by_token_hash(self, token_hash: str) -> UserRecord | None:
        row = self._one("SELECT * FROM users WHERE token_hash = ? AND disabled = 0", (token_hash,))
        return UserRecord.from_row(row) if row else None

    def user_by_email(self, email: str) -> UserRecord | None:
        row = self._one("SELECT * FROM users WHERE lower(email) = lower(?) AND disabled = 0", (email,))
        return UserRecord.from_row(row) if row else None

    def list_users(self) -> list[UserRecord]:
        return [UserRecord.from_row(r) for r in self._all("SELECT * FROM users ORDER BY name")]

    def remove_user(self, name: str) -> bool:
        with self.tx() as c:
            return c.execute("DELETE FROM users WHERE name = ?", (name,)).rowcount == 1

    # -- runs -------------------------------------------------------------

    def create_run(
        self,
        *,
        run_id: str,
        owner: str,
        task: str,
        mode: str,
        scenario: str | None,
        dataset_id: str,
        subject: str,
        enforcement: str,
        policy_version: str,
        state: str,
        token_hash: str,
        session: dict[str, Any],
        tools: list[str],
        agent: dict[str, Any] | None = None,
    ) -> RunRecord:
        now = self.now()
        with self.tx() as c:
            c.execute(
                """INSERT INTO runs (id, created_at, updated_at, owner, task, mode, scenario, dataset_id,
                   subject, enforcement, policy_version, state, token_hash, session, agent, tools)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    run_id,
                    now,
                    now,
                    owner,
                    task,
                    mode,
                    scenario,
                    dataset_id,
                    subject,
                    enforcement,
                    policy_version,
                    state,
                    token_hash,
                    _dump(session),
                    _dump(agent or {}),
                    _dump(tools),
                ),
            )
        run = self.get_run(run_id)
        assert run is not None
        return run

    def get_run(self, run_id: str) -> RunRecord | None:
        row = self._one("SELECT * FROM runs WHERE id = ?", (run_id,))
        return RunRecord.from_row(row) if row else None

    def get_run_by_token_hash(self, token_hash: str) -> RunRecord | None:
        row = self._one("SELECT * FROM runs WHERE token_hash = ?", (token_hash,))
        return RunRecord.from_row(row) if row else None

    def list_runs(self, limit: int = 50) -> list[RunRecord]:
        rows = self._all("SELECT * FROM runs ORDER BY created_at DESC, id DESC LIMIT ?", (limit,))
        return [RunRecord.from_row(r) for r in rows]

    def runs_in_states(self, states: Iterable[str]) -> list[RunRecord]:
        states = list(states)
        marks = ",".join("?" * len(states))
        rows = self._all(f"SELECT * FROM runs WHERE state IN ({marks})", states)  # noqa: S608
        return [RunRecord.from_row(r) for r in rows]

    def update_run(self, run_id: str, **fields: Any) -> None:
        bad = set(fields) - _RUN_UPDATABLE
        if bad:
            raise ValueError(f"cannot update run columns {sorted(bad)}")
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self.tx() as c:
            c.execute(
                f"UPDATE runs SET {cols}, updated_at = ? WHERE id = ?",  # noqa: S608
                [*(_encode(k, v) for k, v in fields.items()), self.now(), run_id],
            )

    def transition_run(self, run_id: str, from_states: Iterable[str], to_state: str, **fields: Any) -> bool:
        """Conditionally move a run to a new state. Returns False if it was not in from_states."""
        fields = {"state": to_state, **fields}
        bad = set(fields) - _RUN_UPDATABLE
        if bad:
            raise ValueError(f"cannot update run columns {sorted(bad)}")
        from_states = list(from_states)
        cols = ", ".join(f"{k} = ?" for k in fields)
        marks = ",".join("?" * len(from_states))
        with self.tx() as c:
            cur = c.execute(
                f"UPDATE runs SET {cols}, updated_at = ? WHERE id = ? AND state IN ({marks})",  # noqa: S608
                [*(_encode(k, v) for k, v in fields.items()), self.now(), run_id, *from_states],
            )
            return cur.rowcount == 1

    # -- actions ----------------------------------------------------------

    def insert_action(
        self, *, action_id: str, run_id: str, tool: str, raw_args: Any, state: str
    ) -> ActionRecord:
        now = self.now()
        with self.tx() as c:
            seq = c.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM actions WHERE run_id = ?", (run_id,)
            ).fetchone()[0]
            c.execute(
                """INSERT INTO actions (id, run_id, seq, created_at, updated_at, tool, raw_args, state)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (action_id, run_id, seq, now, now, tool, _dump(raw_args), state),
            )
        action = self.get_action(action_id)
        assert action is not None
        return action

    def get_action(self, action_id: str) -> ActionRecord | None:
        row = self._one("SELECT * FROM actions WHERE id = ?", (action_id,))
        return ActionRecord.from_row(row) if row else None

    def list_actions(self, run_id: str) -> list[ActionRecord]:
        rows = self._all("SELECT * FROM actions WHERE run_id = ? ORDER BY seq", (run_id,))
        return [ActionRecord.from_row(r) for r in rows]

    def recent_actions(self, limit: int = 1000) -> list[ActionRecord]:
        rows = self._all("SELECT * FROM actions ORDER BY created_at DESC, id DESC LIMIT ?", (limit,))
        return [ActionRecord.from_row(r) for r in rows]

    def actions_in_states(self, states: Iterable[str], run_id: str | None = None) -> list[ActionRecord]:
        states = list(states)
        marks = ",".join("?" * len(states))
        sql = f"SELECT * FROM actions WHERE state IN ({marks})"  # noqa: S608
        params: list[Any] = states
        if run_id is not None:
            sql += " AND run_id = ?"
            params = [*states, run_id]
        return [ActionRecord.from_row(r) for r in self._all(sql + " ORDER BY created_at", params)]

    def count_actions(self, run_id: str) -> int:
        row = self._one("SELECT COUNT(*) FROM actions WHERE run_id = ?", (run_id,))
        return int(row[0]) if row else 0

    def update_action(self, action_id: str, **fields: Any) -> None:
        bad = set(fields) - _ACTION_UPDATABLE
        if bad:
            raise ValueError(f"cannot update action columns {sorted(bad)}")
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self.tx() as c:
            c.execute(
                f"UPDATE actions SET {cols}, updated_at = ? WHERE id = ?",  # noqa: S608
                [*(_encode(k, v) for k, v in fields.items()), self.now(), action_id],
            )

    def transition_action(
        self,
        action_id: str,
        from_states: Iterable[str],
        to_state: str,
        *,
        where: dict[str, Any] | None = None,
        **fields: Any,
    ) -> bool:
        """Atomically move an action between states.

        `where` adds equality guards, e.g. {"args_hash": h, "policy_version": v}.
        Returns True only for the single caller whose UPDATE matched.
        """
        bad = set(fields) - _ACTION_UPDATABLE
        if bad:
            raise ValueError(f"cannot update action columns {sorted(bad)}")
        guards = where or {}
        if set(guards) - {"args_hash", "policy_version", "run_id"}:
            raise ValueError("unsupported guard column")
        from_states = list(from_states)
        sets = ", ".join(["state = ?", *(f"{k} = ?" for k in fields), "updated_at = ?"])
        marks = ",".join("?" * len(from_states))
        guard_sql = "".join(f" AND {k} = ?" for k in guards)
        with self.tx() as c:
            cur = c.execute(
                f"UPDATE actions SET {sets} WHERE id = ? AND state IN ({marks}){guard_sql}",  # noqa: S608
                [
                    to_state,
                    *(_encode(k, v) for k, v in fields.items()),
                    self.now(),
                    action_id,
                    *from_states,
                    *guards.values(),
                ],
            )
            return cur.rowcount == 1

    # -- execution ledger -------------------------------------------------

    def record_execution(self, *, action_id: str, run_id: str, tool: str, args: dict[str, Any]) -> None:
        """Insert into the ledger. Raises sqlite3.IntegrityError if this action already executed."""
        with self.tx() as c:
            c.execute(
                "INSERT INTO executions (action_id, run_id, tool, args, created_at) VALUES (?,?,?,?,?)",
                (action_id, run_id, tool, _dump(args), self.now()),
            )

    def executions(self, run_id: str | None = None, tool: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM executions WHERE 1=1"
        params: list[Any] = []
        if run_id is not None:
            sql += " AND run_id = ?"
            params.append(run_id)
        if tool is not None:
            sql += " AND tool = ?"
            params.append(tool)
        rows = self._all(sql + " ORDER BY created_at", params)
        return [{**dict(r), "args": _load(r["args"])} for r in rows]

    # -- events -----------------------------------------------------------

    def append_event(
        self, run_id: str, type_: str, payload: dict[str, Any], action_id: str | None = None
    ) -> EventRecord:
        with self.tx() as c:
            run_seq = c.execute(
                "SELECT COALESCE(MAX(run_seq), 0) + 1 FROM events WHERE run_id = ?", (run_id,)
            ).fetchone()[0]
            cur = c.execute(
                "INSERT INTO events (run_id, run_seq, ts, type, action_id, payload) VALUES (?,?,?,?,?,?)",
                (run_id, run_seq, self.now(), type_, action_id, _dump(payload)),
            )
            seq = cur.lastrowid
            row = c.execute("SELECT * FROM events WHERE seq = ?", (seq,)).fetchone()
        return EventRecord.from_row(row)

    def all_events_after(self, after_seq: int = 0, limit: int = 5000) -> list[EventRecord]:
        """Every run's events in order, for export."""
        rows = self._all("SELECT * FROM events WHERE seq > ? ORDER BY seq LIMIT ?", (after_seq, limit))
        return [EventRecord.from_row(r) for r in rows]

    def events_after(self, run_id: str, after_seq: int = 0, limit: int = 5000) -> list[EventRecord]:
        rows = self._all(
            "SELECT * FROM events WHERE run_id = ? AND seq > ? ORDER BY seq LIMIT ?",
            (run_id, after_seq, limit),
        )
        return [EventRecord.from_row(r) for r in rows]
