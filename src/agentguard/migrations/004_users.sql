-- People who can use the dashboard and API. The operator token stays as a
-- bootstrap admin; everyone else is listed here.
CREATE TABLE users (
    name        TEXT PRIMARY KEY,
    email       TEXT UNIQUE,                 -- sign-in through a trusted proxy header (SSO)
    role        TEXT NOT NULL CHECK (role IN ('admin', 'approver', 'viewer')),
    token_hash  TEXT UNIQUE,                 -- personal token, stored hashed
    created_at  TEXT NOT NULL,
    disabled    INTEGER NOT NULL DEFAULT 0
);
