-- AgentGuard schema v1

CREATE TABLE runs (
    id                TEXT PRIMARY KEY,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    started_at        TEXT,
    ended_at          TEXT,
    owner             TEXT NOT NULL,
    task              TEXT NOT NULL,
    mode              TEXT NOT NULL,
    scenario          TEXT,
    dataset_id        TEXT NOT NULL,
    subject           TEXT NOT NULL,
    enforcement       TEXT NOT NULL,
    policy_version    TEXT NOT NULL,
    state             TEXT NOT NULL,
    state_reason      TEXT,
    token_hash        TEXT NOT NULL UNIQUE,
    session           TEXT NOT NULL,            -- JSON: labels, seen_ips, counters
    agent             TEXT NOT NULL DEFAULT '{}', -- JSON: agent kind, model, tool list
    summary           TEXT,
    summary_check     TEXT                      -- JSON: cited evidence validation
);

CREATE TABLE actions (
    id                    TEXT PRIMARY KEY,
    run_id                TEXT NOT NULL REFERENCES runs(id),
    seq                   INTEGER NOT NULL,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    tool                  TEXT NOT NULL,
    raw_args              TEXT NOT NULL,        -- JSON as proposed (redacted, size-capped)
    args                  TEXT,                 -- canonical JSON; NULL when invalid
    args_hash             TEXT,
    facts                 TEXT,
    state                 TEXT NOT NULL,
    decision              TEXT,                 -- JSON Decision
    policy_version        TEXT,
    enforced              INTEGER NOT NULL DEFAULT 1,
    shadow_effect         TEXT,
    approval_expires_at   TEXT,
    approval_resolved_at  TEXT,
    approver              TEXT,
    approval_note         TEXT,
    exec_started_at       TEXT,
    exec_finished_at      TEXT,
    result                TEXT,                 -- JSON, redacted
    error                 TEXT,
    UNIQUE (run_id, seq)
);
CREATE INDEX actions_run ON actions(run_id);
CREATE INDEX actions_state ON actions(state);

-- Ledger of tool executions. The primary key on action_id is the
-- idempotency key: one proposal can execute at most once.
CREATE TABLE executions (
    action_id   TEXT PRIMARY KEY REFERENCES actions(id),
    run_id      TEXT NOT NULL REFERENCES runs(id),
    tool        TEXT NOT NULL,
    args        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     TEXT NOT NULL REFERENCES runs(id),
    run_seq    INTEGER NOT NULL,
    ts         TEXT NOT NULL,
    type       TEXT NOT NULL,
    action_id  TEXT,
    payload    TEXT NOT NULL,
    UNIQUE (run_id, run_seq)
);
CREATE INDEX events_run ON events(run_id, seq);

CREATE TRIGGER events_append_only_update BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER events_append_only_delete BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER executions_append_only_update BEFORE UPDATE ON executions
BEGIN
    SELECT RAISE(ABORT, 'executions are append-only');
END;

CREATE TRIGGER executions_append_only_delete BEFORE DELETE ON executions
BEGIN
    SELECT RAISE(ABORT, 'executions are append-only');
END;
